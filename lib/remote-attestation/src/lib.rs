use std::time::SystemTime;

use anyhow::{anyhow, bail, Context};
use hex::ToHex;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use pki::TrustStore;
use types::collateral::SgxCollateral;
use types::qe_identity::{EnclaveType, QeTcbStatus};
use types::quote::SgxQuote;
use types::report::{MREnclave, SgxReportBody};
use types::tcb_info::TcbInfo;
use types::{INTEL_QE_VENDOR_ID, INTEL_ROOT_CA};
use utils::Expireable;
use uuid::Uuid;
use zerocopy::AsBytes;

use crate::types::sgx_x509::SgxPckExtension;
use crate::types::tcb_info::{TcbLevel, TcbStatus};
use crate::types::TcbStanding;

mod pki;
mod utils;

pub mod types;

/// Verify a remote attestation from a given collateral and quote, returning
/// the verified sgx report body (containing MRENCLAVE and report data bytes).
///
/// # Security considerations
///
/// Consumers of this api *MUST* use a secure channel to aquire current_time.
/// Specifically, on fortanix targets, [`SystemTime::now`](https://edp.fortanix.com/docs/api/std/time/struct.SystemTime.html#underlying-system-calls) is insecure.
pub fn verify_remote_attestation(
    current_time: SystemTime,
    collateral: SgxCollateral,
    quote: SgxQuote,
    expected_mrenclave: &MREnclave,
) -> anyhow::Result<(TcbStanding, SgxReportBody)> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    let tcb_info = verify_integrity(current_time, &collateral, &quote)?;

    // 2. Verify the Quoting Enclave source and all signatures in the quote.
    verify_quote(&collateral, &quote)?;

    // 3. Verify the status of the Intel® SGX TCB described in the chain.
    let tcb_standing = verify_tcb_status(&tcb_info, &quote.support.pck_extension)?;

    // 4. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    if expected_mrenclave != &quote.quote_body.report_body.mrenclave {
        bail!(
            "invalid MRENCLAVE, expected {}, but got {}",
            hex::encode(expected_mrenclave),
            hex::encode(quote.quote_body.report_body.mrenclave)
        );
    }

    Ok((tcb_standing, quote.quote_body.report_body))
}

/// Verify the integrity of the certificate chain
fn verify_integrity(
    current_time: SystemTime,
    collateral: &SgxCollateral,
    quote: &SgxQuote,
) -> anyhow::Result<TcbInfo> {
    if !collateral.tcb_info_issuer_chain.valid_at(current_time) {
        bail!("Expired tcb info issuer chain")
    }
    if !collateral.pck_crl_issuer_chain.valid_at(current_time) {
        bail!("Expired pck crl issuer chain")
    }
    if !quote.support.pck_cert_chain.valid_at(current_time) {
        bail!("Expired quote support pck chain")
    }

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
    let mut trust_store = TrustStore::new(current_time, vec![root_ca.clone()])?;

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
    if !collateral.pck_crl.valid_at(current_time) {
        bail!("Expired or future PCK CRL")
    }
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

fn verify_quote(collateral: &SgxCollateral, quote: &SgxQuote) -> anyhow::Result<()> {
    verify_quote_source(collateral, quote)?;
    verify_quote_signatures(quote)?;
    Ok(())
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
                    .context("missing subject public key")?,
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

    let mut key = [0u8; 65];
    key[0] = 4;
    key[1..].copy_from_slice(&quote.support.attest_pub_key);
    let attest_key = VerifyingKey::from_sec1_bytes(&key)
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
fn verify_tcb_status(
    tcb_info: &TcbInfo,
    pck_extension: &SgxPckExtension,
) -> anyhow::Result<TcbStanding> {
    /// Returns true if all the pck components are >= all the tcb level components AND
    /// the pck pcesvn is >= tcb pcesvn
    fn in_tcb_level(level: &TcbLevel, pck_extension: &SgxPckExtension) -> bool {
        const SVN_LENGTH: usize = 16;
        let pck_components: &[u8; SVN_LENGTH] = &pck_extension.tcb.compsvn;

        pck_components
            .iter()
            .zip(level.tcb.components())
            .all(|(&p, l)| p >= l)
            && pck_extension.tcb.pcesvn >= level.tcb.pcesvn()
    }

    // make sure the tcb_info matches the enclave's model/PCE version
    if pck_extension.fmspc != tcb_info.fmspc {
        return Err(anyhow!(format!(
            "tcb fmspc mismatch (pck extension fmspc was {:?}, tcb_info fmspc was {:?})",
            &pck_extension.fmspc, &tcb_info.fmspc
        )));
    }
    if pck_extension.pceid != tcb_info.pce_id {
        return Err(anyhow!(format!(
            "tcb pceid mismatch (pck extension pceid was {:?}, tcb_info pceid was {:?})",
            &pck_extension.pceid, &tcb_info.pce_id
        )));
    }

    // TODO: Sort tcb levels by pcesvn and compsvn(s)
    //let mut tcb_levels = tcb_info.tcb_levels.clone();
    //tcb_levels.sort_by(|a, b| a.tcb.pcesvn().cmp(&b.tcb.pcesvn()));

    let first_matching_level = tcb_info
        .tcb_levels
        .iter()
        .find(|level| in_tcb_level(level, pck_extension))
        .context("Unsupported TCB in pck extension")?;

    // Find the tcb status corresponding to our enclave in the tcb info
    // the consumer of dcap needs to decide which statuses are acceptable (either by
    // returning this up, or configuring acceptable statuses)
    match first_matching_level.tcb_status {
        TcbStatus::UpToDate => Ok(TcbStanding::UpToDate),
        TcbStatus::SWHardeningNeeded => Ok(TcbStanding::SWHardeningNeeded {
            advisory_ids: first_matching_level.advisory_ids.clone(),
        }),
        // TODO: we allow `ConfigurationAndSWHardeningNeeded` temporarily until we do the TCB
        // recovery
        TcbStatus::ConfigurationAndSWHardeningNeeded => Ok(TcbStanding::SWHardeningNeeded {
            advisory_ids: vec![],
        }),
        _ => bail!("invalid tcb status: {:?}", first_matching_level.tcb_status),
    }
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

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
        let expected_mrenclave = quote.quote_body.report_body.mrenclave;

        // Warning: SystemTime::now() is an insecure api on fortanix targets
        super::verify_remote_attestation(SystemTime::now(), collateral, quote, &expected_mrenclave)
            .expect("should have remote attested real good");
    }

    #[test]
    fn verify_integrity() {
        let (collateral, quote) = test_data();
        // Warning: SystemTime::now() is an insecure api on fortanix targets
        super::verify_integrity(SystemTime::now(), &collateral, &quote)
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

        // Warning: Systemtime::now()is an insecure api on fortanix targets
        let tcb_info = super::verify_integrity(SystemTime::now(), &collateral, &quote).unwrap();
        super::verify_tcb_status(&tcb_info, &quote.support.pck_extension)
            .expect("tcb status to be valid");
    }
}
