pub mod test_tls;
pub mod types;

use anyhow::{bail, Context};
use mbedtls::alloc::List;
use mbedtls::x509::{Certificate, Crl};
use types::{get_intel_pub_key, Quote, SgxCollateral};
use x509_parser::prelude::{parse_x509_pem, CertificateRevocationList, FromDer};

pub fn verify_remote_attestation(quote: Quote, collateral: SgxCollateral) -> anyhow::Result<()> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate.
    // 2. Verify no keys in the chain have been revoked.s
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
        Certificate::from_pem_multiple(collateral.tcb_info_issuer_chain.as_bytes())?;

    let (_, root_crl_pem) = parse_x509_pem(collateral.root_ca_crl.as_bytes())?;
    let root_crl_der = root_crl_pem.contents;

    let root_ca = tcb_issuer_chain
        .iter()
        .last()
        .context("Tcb issuer chain is empty")?;

    verify_root_ca(root_ca, &root_crl_der)?;

    // Now that we verified signed the root certificate we and crl list we can trust them
    let mut trusted_crl = Crl::new();
    trusted_crl.push_from_der(&root_crl_der)?;
    trusted_crl.push_from_pem(collateral.pck_crl.as_bytes())?;

    let mut trusted_root_ca = List::<Certificate>::new();
    trusted_root_ca.push(root_ca.clone());

    let pck_issuer_crl_chain =
        Certificate::from_pem_multiple(collateral.pck_crl_issuer_chain.as_bytes())?;

    // todo maybe use this err_info to print better error here
    Certificate::verify(
        &pck_issuer_crl_chain,
        &trusted_root_ca,
        Some(&mut trusted_crl),
        None,
    )?;

    Certificate::verify(
        &tcb_issuer_chain,
        &trusted_root_ca,
        Some(&mut trusted_crl),
        None,
    )?;

    let pck_cert_chain = Certificate::from_pem_multiple(collateral.pck_signing_chain.as_bytes())?;

    Certificate::verify(
        &pck_cert_chain,
        &trusted_root_ca,
        Some(&mut trusted_crl),
        None,
    )?;

    let qe_id_issuer_chain =
        Certificate::from_pem_multiple(collateral.qe_identity_issuer_chain.as_bytes())?;

    Certificate::verify(
        &qe_id_issuer_chain,
        &trusted_root_ca,
        Some(&mut trusted_crl),
        None,
    )?;

    Ok(())
}

fn verify_root_ca(root_ca: &Certificate, root_crl_der: &[u8]) -> anyhow::Result<()> {
    // We need to verify the root certificate is self signed
    if root_ca.issuer()? != root_ca.subject()? {
        bail!("Root cert authority is not self signed");
    }

    // We need to verify that the Trusted Root intel key has signed the certificate
    let sig = root_ca.signature()?;

    let mut bytes = [0; 64];
    let hash_len = mbedtls::hash::Md::hash(root_ca.digest_type(), root_ca.as_der(), &mut bytes)?;
    let hash = &bytes[0..hash_len];

    let mut intel_pub_key = get_intel_pub_key();

    intel_pub_key.verify(root_ca.digest_type(), hash, &sig)?;

    // Verify that the CRL is signed by Intel
    let (_, root_crl) = CertificateRevocationList::from_der(root_crl_der)?;

    // todo: Should we check the signature/hashing algorithm or is it safe to assume SECP256R1 with
    // sha256?

    let crl_sig = root_crl.signature_value.as_ref();

    let mut bytes = [0; 64];
    let hash_len = mbedtls::hash::Md::hash(mbedtls::hash::Type::Sha256, root_crl_der, &mut bytes)?;
    let hash = &bytes[0..hash_len];

    intel_pub_key.verify(mbedtls::hash::Type::Sha256, hash, crl_sig)?;

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
