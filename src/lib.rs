use anyhow::{anyhow, bail, Context};
use hex::ToHex;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use pki::TrustStore;
use types::collateral::SgxCollateral;
use types::qe_identity::{EnclaveType, QeTcbStatus};
use types::quote::SgxQuote;
use types::report::SgxReportBody;
use types::tcb_info::TcbInfo;
use types::{INTEL_QE_VENDOR_ID, INTEL_ROOT_CA};
use uuid::Uuid;
use zerocopy::AsBytes;

mod pki;
mod utils;

pub mod types;

/// Verify a remote attestation from a given collateral and quote, returning
/// the verified sgx report body (containing MRENCLAVE and report data bytes).
pub fn verify_remote_attestation(
    collateral: SgxCollateral,
    quote: SgxQuote,
) -> anyhow::Result<SgxReportBody> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    let tcb_info = verify_integrity(&collateral, &quote)?;

    // 2. Verify the Quoting Enclave source and all signatures in the quote.
    verify_quote_source(&collateral, &quote)?;
    verify_quote_signatures(&quote)?;

    // 3. Verify the status of the Intel® SGX TCB described in the chain.
    verify_tcb_status(&tcb_info)?;

    // 4. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    verify_enclave_measurements()?;

    Ok(quote.quote_body.report_body)
}

/// Verify the integrity of the certificate chain
fn verify_integrity(collateral: &SgxCollateral, quote: &SgxQuote) -> anyhow::Result<TcbInfo> {
    // TODO(oz): validate expirations

    let root_ca = collateral
        .tcb_info_issuer_chain
        .last()
        .context("Tcb issuer chain is empty")?;

    // Verify the root certificate is self issued
    if root_ca.tbs_certificate.issuer != root_ca.tbs_certificate.subject {
        bail!("Root cert authority is not self signed");
    }

    // Verify that the Trusted Root intel key has signed the certificate
    INTEL_ROOT_CA
        .verify(root_ca)
        .map_err(|e| anyhow!("failed to verify root ca certificate: {e}"))?;

    // Now that we have verified the root ca, we can build the initial trust store.
    let mut trust_store = TrustStore::new(vec![root_ca.clone()])?;

    // Verify that the CRL is signed by Intel and add it to the store
    trust_store
        .push_unverified_crl(collateral.root_ca_crl.clone())
        .context("failed to verify root ca crl")?;

    // Verify the pck crl chain and add it to the store
    let pck_issuer = trust_store
        .verify_chain_leaf(&collateral.pck_crl_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    // Verify the pck crl and add it to the store
    pck_issuer
        .pk
        .verify(&collateral.pck_crl)
        .map_err(|e| anyhow!("failed to verify pck crl: {e}"))?;
    trust_store.push_trusted_crl(collateral.pck_crl.clone());

    // Verify the tcb info issuer chain
    let tcb_issuer = trust_store
        .verify_chain_leaf(&collateral.tcb_info_issuer_chain)
        .context("failed to verify tcb issuer chain")?;

    // TODO: validate signature algorithm oids (ec-with-sha256, prime256v1)

    // get the tcb signer public key
    let tcb_signer = tcb_issuer
        .cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing tcb signer public key")?;
    let tcb_signer = p256::ecdsa::VerifyingKey::from_sec1_bytes(tcb_signer)
        .context("invalid tcb signer public key")?;

    // Verify the tcb info, and get the real struct
    let tcb_info = collateral
        .tcb_info
        .as_tcb_info_and_verify(tcb_signer)
        .context("failed to verify tcb info signature")?;

    // Verify the quote's pck signing certificate chain
    let _pck_signer = trust_store
        .verify_chain_leaf(&quote.support.pck_cert_chain)
        .context("failed to verify quote support pck signing certificate chain")?;

    // Verify the quote identity issuer chain
    let _qe_id_issuer = trust_store
        .verify_chain_leaf(&collateral.qe_identity_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    Ok(tcb_info)
}

/// Verify the quote enclave source
fn verify_quote_source(collateral: &SgxCollateral, quote: &SgxQuote) -> anyhow::Result<()> {
    // verify the qe vendor is intel
    Uuid::from_slice(&quote.quote_body.qe_vendor_id)
        .ok()
        .filter(|uuid| uuid == &INTEL_QE_VENDOR_ID)
        .with_context(|| {
            format!(
                "QE Vendor ID: {} not Intel",
                quote.quote_body.qe_vendor_id.encode_hex::<String>()
            )
        })?;

    let qe_identity = collateral
        .qe_identity
        .verify_as_enclave_identity(
            &VerifyingKey::from_sec1_bytes(
                collateral.qe_identity_issuer_chain[0]
                    .tbs_certificate
                    .subject_public_key_info
                    .subject_public_key
                    .as_bytes()
                    .unwrap(),
            )
            .context("failed to parse qe identity issuer pk")?,
        )
        .context("failed to verify enclave identity")?;

    // Compare mrsigner values
    if qe_identity.mrsigner != quote.support.qe_report_body.mrsigner {
        bail!(
            "invalid qe mrsigner, expected {} but got {}",
            hex::encode(qe_identity.mrsigner),
            hex::encode(quote.support.qe_report_body.mrsigner)
        )
    }

    // Compare isvprodid values
    let report_isvprodid = quote.support.qe_report_body.isvprodid.get();
    let col_isvprodid = qe_identity.isvprodid;
    if report_isvprodid != col_isvprodid {
        bail!("invalid qe isvprodid, expected {report_isvprodid} but got {col_isvprodid}")
    }

    // Compare attributes from QE identity and masked attributes from quote’s QE report
    let qe_report_attributes = quote.support.qe_report_body.sgx_attributes;

    let calculated_mask = qe_identity
        .attributes_mask
        .iter()
        .zip(qe_report_attributes.iter())
        .map(|(a, b)| *a & *b);

    if calculated_mask
        .zip(qe_identity.attributes)
        .any(|(masked_attr, identity_attr)| masked_attr != identity_attr)
    {
        bail!("qe attributes mismatch")
    }

    if qe_identity.id != EnclaveType::Qe {
        bail!(
            "Invalid enclave identity for quoting enclave : {:?}",
            qe_identity.id
        );
    }

    // Later, we will also lookup the tcb status in the TcbInfo but if
    // the Enclave Identity tcb status isn't up to date, we can fail right
    // away
    let report_isvsvn = quote.support.qe_report_body.isvsvn.get();
    let tcb_status = qe_identity.tcb_status(report_isvsvn);
    if tcb_status != &QeTcbStatus::UpToDate {
        bail!("Enclave version tcb not up to date (was {:?})", tcb_status);
    }

    Ok(())
}

fn verify_quote_signatures(quote: &SgxQuote) -> anyhow::Result<()> {
    let pck_pk_bytes = quote.support.pck_cert_chain[0]
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing pck pk")?;
    let pck_pkey = VerifyingKey::from_sec1_bytes(pck_pk_bytes)
        .map_err(|e| anyhow!("failed to parse pck key: {e}"))?;

    pck_pkey
        .verify(
            quote.support.qe_report_body.as_bytes(),
            &quote.support.qe_report_signature,
        )
        .map_err(|e| anyhow!("failed to verify qe report signature: {e}"))?;

    quote.support.verify_qe_report()?;

    // TODO(oz): fix this, getting an error from verifying key parsing
    let attest_key = quote.support.attest_pub_key;
    let attest_key = VerifyingKey::from_sec1_bytes(&attest_key)
        .map_err(|e| anyhow!("failed to parse attest key: {e}"))?;

    let data = quote.quote_body.as_bytes();
    let sig = quote.support.isv_signature;
    attest_key
        .verify(data, &sig)
        .context("failed to verify quote signature")?;

    Ok(())
}

/// Ensure the latest tcb info is not revoked, and is either up to date or only needs a
/// configuration change.
fn verify_tcb_status(_tcb_info: &TcbInfo) -> anyhow::Result<()> {
    // TODO:
    //   - sort tcb info by pcesvn/compsvn
    //   - ensure status of the latest is either:
    //      - TcbStatus::UpToDate
    //      - TcbStatus::ConfigurationNeeded

    todo!()
}

fn verify_enclave_measurements(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::{SgxCollateral, SgxQuote};

    fn test_data() -> (SgxCollateral, SgxQuote<'static>) {
        let json = include_str!("../data/full_collateral.json");
        let collateral: SgxCollateral = serde_json::from_str(json).unwrap();

        let der = include_bytes!("../data/quote.bin");
        let quote = SgxQuote::read(&mut der.as_slice()).unwrap();

        (collateral, quote)
    }

    #[test]
    fn e2e_verify_remote_attestation() {
        let (collateral, quote) = test_data();
        super::verify_remote_attestation(collateral, quote)
            .expect("should have remote attested real good");
    }

    #[test]
    fn verify_integrity() {
        let (collateral, quote) = test_data();
        super::verify_integrity(&collateral, &quote)
            .expect("certificate chain integrity should succeed");
    }

    #[test]
    fn verify_quote_source() {
        let (collateral, quote) = test_data();
        super::verify_quote_source(&collateral, &quote).expect("quote source to be valid");
    }

    #[test]
    fn verify_quote_signatures() {
        let (_, quote) = test_data();
        super::verify_quote_signatures(&quote).expect("tcb status to be valid");
    }

    #[test]
    fn verify_tcb_status() {
        let (collateral, quote) = test_data();
        let tcb_info = super::verify_integrity(&collateral, &quote).unwrap();
        super::verify_tcb_status(&tcb_info).expect("tcb status to be valid");
    }

    #[test]
    fn verify_enclave_measurements() {
        let (_, _) = test_data();
        super::verify_enclave_measurements().expect("enclave measurements to be correct");
    }
}
