use std::net::{TcpListener, TcpStream};
use std::sync::Arc;

use anyhow::Context;
use ra_verify::types::report::MREnclave;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

use crate::cert::{Certificate, PrivateKey};
use crate::verifier::RemoteAttestationVerifier;

pub struct RaTlsListener {
    config: Arc<ServerConfig>,
    inner: TcpListener,
}

impl RaTlsListener {
    /// Bind a new ra-tls listener.
    /// Pass an expected MREnclave to use RA client authentication, or none
    /// for no client auth.
    pub fn bind(
        mr_enclave: Option<MREnclave>,
        key: PrivateKey,
        cert: Certificate,
        port: u16,
    ) -> anyhow::Result<Self> {
        let private_key = PrivatePkcs1KeyDer::from(key);
        let private_key = PrivateKeyDer::from(private_key);
        let cert = CertificateDer::from(cert);

        let config = if let Some(mr_enclave) = mr_enclave {
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_safe_default_protocol_versions()?
                .with_client_cert_verifier(Arc::new(RemoteAttestationVerifier::new(mr_enclave)))
                .with_single_cert(vec![cert], private_key)
                .context("Failed to build server config")?
        } else {
            rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
                .with_safe_default_protocol_versions()?
                .with_no_client_auth()
                .with_single_cert(vec![cert], private_key)
                .context("Failed to build server config")?
        };
        let config = Arc::new(config);

        let inner =
            TcpListener::bind(format!("0.0.0.0:{}", port)).context("Failed to bind to TCP port")?;

        Ok(Self { config, inner })
    }

    pub fn accept(&mut self) -> anyhow::Result<StreamOwned<ServerConnection, TcpStream>> {
        loop {
            let (stream, _) = self.inner.accept()?;
            let Ok(conn) = ServerConnection::new(self.config.clone()) else {
                continue;
            };
            let tls = StreamOwned::new(conn, stream);
            return Ok(tls);
        }
    }
}
