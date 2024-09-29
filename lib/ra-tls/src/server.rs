use std::sync::Arc;

use anyhow::{Context, Result};
use ra_verify::types::report::MREnclave;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use rustls::ServerConfig;

use crate::cert::{Certificate, PrivateKey};
use crate::verifier::RemoteAttestationVerifier;

pub fn build_config_mtls<F>(
    key: PrivateKey,
    cert: Certificate,
    // If `mr_enclave` is provided, the server will expect and verify the client cert,
    // which must also contains the quote and collateral.
    mr_enclave: MREnclave,
    get_collateral: F,
) -> Result<ServerConfig>
where
    F: Fn(Vec<u8>) -> std::io::Result<Vec<u8>> + Send + Sync + 'static,
{
    let private_key = PrivatePkcs1KeyDer::from(key);
    let private_key = PrivateKeyDer::from(private_key);
    let cert = CertificateDer::from(cert);

    ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()?
        .with_client_cert_verifier(Arc::new(RemoteAttestationVerifier::new(
            mr_enclave,
            get_collateral,
        )))
        .with_single_cert(vec![cert], private_key)
        .context("Failed to build server config")
}

pub fn build_config_tls(key: PrivateKey, cert: Certificate) -> Result<ServerConfig> {
    let private_key = PrivatePkcs1KeyDer::from(key);
    let private_key = PrivateKeyDer::from(private_key);
    let cert = CertificateDer::from(cert);

    ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(vec![cert], private_key)
        .context("Failed to build server config")
}
