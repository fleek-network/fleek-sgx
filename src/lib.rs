use std::ops::Deref;

use anyhow::{anyhow, bail, Context};
use types::{Quote, SgxCollateral, INTEL_ROOT_CA};
use x509_cert::certificate::CertificateInner;
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;

pub mod types;

pub fn verify_remote_attestation(collateral: SgxCollateral, quote: Quote) -> anyhow::Result<()> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate, and that no keys in the chain have been revoked.
    verify_integrity(collateral, quote)?;

    // 3. Verify the Quoting Enclave is from a suitable source and is up to date.
    verify_quote()?;

    // 4. Verify the status of the Intel® SGX TCB described in the chain.
    verify_tcb_status()?;

    // 5. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    verify_enclave_measurements()?;

    Ok(())
}

fn verify_integrity(collateral: SgxCollateral, _quote: Quote) -> anyhow::Result<()> {
    let tcb_issuer_chain =
        x509_cert::Certificate::load_pem_chain(collateral.tcb_info_issuer_chain.as_bytes())
            .context("invalid tcb issuer certificate chain")?;

    let tcb_leaf = tcb_issuer_chain
        .first()
        .context("issuer chain empty, missing tcb signer leaf")?;

    // TODO: validate algorithm identifier oids (ec-with-sha256, prime256v1)

    let tcb_signer = tcb_leaf
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("missing tcb signer public key")?;
    let tcb_signer = p256::ecdsa::VerifyingKey::from_sec1_bytes(tcb_signer)
        .context("invalid tcb signer public key")?;

    let tcb_info = collateral
        .tcb_info
        .as_tcb_info_and_verify(tcb_signer)
        .context("failed to verify tcb info signature")?;

    let pem = pem::parse(collateral.root_ca_crl.as_bytes()).context("invalid root ca crl pem")?;
    let root_ca_crl = x509_cert::crl::CertificateList::from_der(pem.contents())
        .context("invalid root ca crl der")?;

    let root_ca = tcb_issuer_chain
        .iter()
        .last()
        .context("Tcb issuer chain is empty")?;

    verify_root_ca(root_ca, &root_ca_crl)?;

    // Now that we verified signed the root certificate we and crl list we can trust them

    //     let mut trusted_crl = Crl::new();
    //     trusted_crl.push_from_der(&root_crl_der)?;
    //     trusted_crl.push_from_pem(collateral.pck_crl.as_bytes())?;

    //     let mut trusted_root_ca = List::<Certificate>::new();
    //     trusted_root_ca.push(root_ca.clone());

    //     let pck_issuer_crl_chain =
    //         Certificate::from_pem_multiple(collateral.pck_crl_issuer_chain.as_bytes())?;

    //     // todo maybe use this err_info to print better error here
    //     Certificate::verify(
    //         &pck_issuer_crl_chain,
    //         &trusted_root_ca,
    //         Some(&mut trusted_crl),
    //         None,
    //     )?;

    //     Certificate::verify(
    //         &tcb_issuer_chain,
    //         &trusted_root_ca,
    //         Some(&mut trusted_crl),
    //         None,
    //     )?;

    //     let pck_cert_chain =
    // Certificate::from_pem_multiple(collateral.pck_signing_chain.as_bytes())?;

    //     Certificate::verify(
    //         &pck_cert_chain,
    //         &trusted_root_ca,
    //         Some(&mut trusted_crl),
    //         None,
    //     )?;

    //     let qe_id_issuer_chain =
    //         Certificate::from_pem_multiple(collateral.qe_identity_issuer_chain.as_bytes())?;

    //     Certificate::verify(
    //         &qe_id_issuer_chain,
    //         &trusted_root_ca,
    //         Some(&mut trusted_crl),
    //         None,
    //     )?;

    Ok(())
}

fn verify_root_ca(root_ca: &CertificateInner, root_ca_crl: &CertificateList) -> anyhow::Result<()> {
    // We need to verify the root certificate is self issued
    if root_ca.tbs_certificate.issuer != root_ca.tbs_certificate.subject {
        bail!("Root cert authority is not self signed");
    }

    // We need to verify that the Trusted Root intel key has signed the certificate
    INTEL_ROOT_CA
        .deref()
        .verify(root_ca)
        .map_err(|e| anyhow!("failed to verify root ca certificate: {e}"))?;

    // Verify that the CRL is signed by Intel
    INTEL_ROOT_CA
        .verify(root_ca_crl)
        .map_err(|e| anyhow!("failed to verify root ca certificate revocation list: {e}"))?;

    // Now we can trust the root ca and the root crl
    Ok(())
}

fn verify_quote(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

fn verify_tcb_status(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

fn verify_enclave_measurements(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

#[cfg(test)]
#[test]
fn test_verify_integrity() {
    let json = include_str!("../data/full_collaterall.json");
    let collateral: SgxCollateral = serde_json::from_str(json).unwrap();

    verify_integrity(collateral, Quote {}).unwrap();
}
