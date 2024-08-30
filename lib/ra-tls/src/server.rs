use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;

use anyhow::{Context, Result};
use fleek_remote_attestation::types::report::MREnclave;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};

use crate::cert::{Certificate, PrivateKey};
use crate::verifier::RemoteAttestationVerifier;

#[allow(unused)]
pub fn handle_requests(
    mr_enclave: MREnclave,
    key: PrivateKey,
    cert: Certificate,
    port: u16,
) -> Result<()> {
    let private_key = PrivatePkcs1KeyDer::from(key);
    let private_key = PrivateKeyDer::from(private_key);
    let cert = CertificateDer::from(cert);

    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()?
            .with_client_cert_verifier(Arc::new(RemoteAttestationVerifier::new(mr_enclave)))
            .with_single_cert(vec![cert], private_key)
            .context("Failed to build server config")?;
    let config = Arc::new(config);

    let listener =
        TcpListener::bind(format!("0.0.0.0:{}", port)).context("Failed to bind to TCP port")?;

    while let Ok((mut stream, _)) = listener.accept() {
        let mut conn =
            rustls::ServerConnection::new(config.clone()).context("Failed to connect to client")?;
        let _res = conn.complete_io(&mut stream)?;
        conn.writer().write_all(b"Hello from the server")?;
        conn.complete_io(&mut stream)?;
        // TODO(matthias): respond to requests
        conn.send_close_notify();
        conn.complete_io(&mut stream)?;
    }
    Ok(())
}
