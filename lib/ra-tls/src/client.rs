use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Context, Result};
use ra_verify::types::report::MREnclave;
use rustls::pki_types::{CertificateDer, IpAddr, PrivateKeyDer, PrivatePkcs1KeyDer, ServerName};
use rustls::{ClientConnection, StreamOwned};

use crate::cert::{Certificate, PrivateKey};
use crate::verifier::RemoteAttestationVerifier;

pub fn connect_mtls<F>(
    mr_enclave: MREnclave,
    get_collateral: F,
    server_ip: String,
    server_port: u16,
    key: PrivateKey,
    cert: Certificate,
) -> Result<StreamOwned<ClientConnection, TcpStream>>
where
    F: Fn(Vec<u8>) -> std::io::Result<Vec<u8>> + Send + Sync + 'static,
{
    let private_key = PrivatePkcs1KeyDer::from(key);
    let private_key = PrivateKeyDer::from(private_key);
    let cert = CertificateDer::from(cert);
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RemoteAttestationVerifier::new(
                mr_enclave,
                get_collateral,
            )))
            .with_client_auth_cert(vec![cert], private_key)?;

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = ServerName::IpAddress(
        IpAddr::try_from(server_ip.as_ref()).context("Failed to parse IP address")?,
    );
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    let sock = TcpStream::connect(format!("{server_ip}:{server_port}"))?;
    let tls = StreamOwned::new(conn, sock);
    Ok(tls)
}

pub fn connect_tls<F>(
    mr_enclave: MREnclave,
    get_collateral: F,
    server_ip: String,
    server_port: u16,
) -> Result<StreamOwned<ClientConnection, TcpStream>>
where
    F: Fn(Vec<u8>) -> std::io::Result<Vec<u8>> + Send + Sync + 'static,
{
    let mut config =
        rustls::ClientConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(RemoteAttestationVerifier::new(
                mr_enclave,
                get_collateral,
            )))
            .with_no_client_auth();

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    let server_name = ServerName::IpAddress(
        IpAddr::try_from(server_ip.as_ref()).context("Failed to parse IP address")?,
    );
    let conn = ClientConnection::new(Arc::new(config), server_name)?;
    let sock = TcpStream::connect(format!("{server_ip}:{server_port}"))?;
    let tls = StreamOwned::new(conn, sock);
    Ok(tls)
}
