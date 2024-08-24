use anyhow::{anyhow, bail, Context};
use pki::TrustStore;
use types::collateral::SgxCollateral;
use types::quote::SgxQuote;
use types::tcb_info::TcbInfo;
use types::INTEL_ROOT_CA;

mod pki;
mod utils;

pub mod types;

/// Verify a remote attestation from a given collateral and quote.
pub fn verify_remote_attestation(collateral: SgxCollateral, quote: SgxQuote) -> anyhow::Result<()> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked by the parent entity.
    let (tcb_info,) = verify_integrity(&collateral, &quote)?;

    // 2. Verify the Quoting Enclave is from a suitable source and is up to date.
    verify_quote()?;

    // 3. Verify the status of the Intel® SGX TCB described in the chain.
    verify_tcb_status(&tcb_info)?;

    // 4. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    verify_enclave_measurements()?;

    Ok(())
}

fn verify_integrity(collateral: &SgxCollateral, quote: &SgxQuote) -> anyhow::Result<(TcbInfo,)> {
    let root_ca = collateral
        .tcb_info_issuer_chain
        .last()
        .context("Tcb issuer chain is empty")?;

    // We need to verify the root certificate is self issued
    if root_ca.tbs_certificate.issuer != root_ca.tbs_certificate.subject {
        bail!("Root cert authority is not self signed");
    }

    // We need to verify that the Trusted Root intel key has signed the certificate
    INTEL_ROOT_CA
        .verify(root_ca)
        .map_err(|e| anyhow!("failed to verify root ca certificate: {e}"))?;

    // Now that we have verified the root ca, we can build the initial trust store.
    let mut trust_store = TrustStore::new(vec![root_ca.clone()])?;

    // Verify that the CRL is signed by Intel and add it to the store
    trust_store
        .push_unverified_crl(collateral.root_ca_crl.clone())
        .context("failed to verify root ca crl")?;

    // verify the pck crl chain and add it to the store
    let pck_issuer = trust_store
        .verify_chain_leaf(&collateral.pck_crl_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    // verify the pck crl and add it to the store
    pck_issuer
        .pk
        .verify(&collateral.pck_crl)
        .map_err(|e| anyhow!("failed to verify pck crl: {e}"))?;
    trust_store.push_trusted_crl(collateral.pck_crl.clone());

    // verify the tcb info issuer chain
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

    // verify the tcb info, and get the real struct
    let tcb_info = collateral
        .tcb_info
        .as_tcb_info_and_verify(tcb_signer)
        .context("failed to verify tcb info signature")?;

    // verify the quote's support pck signing certificate chain
    trust_store
        .verify_chain_leaf(&quote.support.pck_cert_chain)
        .context("failed to verify quote support pck signing certificate chain")?;

    // verify the quote identity issuer chain
    let _qe_id_issuer = trust_store
        .verify_chain_leaf(&collateral.qe_identity_issuer_chain)
        .context("failed to verify pck crl issuer certificate chain")?;

    Ok((tcb_info,))
}

fn verify_quote(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

/// Ensure the latest tcb info is not revoked, and is either up to date or only needs a
/// configuration change.
fn verify_tcb_status(_tcb_info: &TcbInfo) -> anyhow::Result<()> {
    // TODO:
    //   - sort tcb info by pcesvn/compsvn
    //   - ensure status of the latest is either:
    //      - TcbStatus::UpToDate
    //      - TcbStatus::ConfigurationNeeded

    Ok(())
}

fn verify_enclave_measurements(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verify_integrity_success() {
        let json = include_str!("../data/full_collaterall.json");
        let collateral: SgxCollateral = serde_json::from_str(json).unwrap();

        let der = include_bytes!("../data/our_evidence.bin").to_vec();
        let mut slice = der.as_slice();
        let quote = SgxQuote::read(&mut slice).unwrap();

        verify_integrity(&collateral, &quote).unwrap();
    }
}
