use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;

use anyhow::{Context, Result};
use ra_verify::types::report::MREnclave;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer};
use rustls::ServerConnection;

use crate::cert::{Certificate, PrivateKey};
use crate::codec::{Codec, FramedStream, Request, Response, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
use crate::verifier::RemoteAttestationVerifier;

pub fn handle_enclave_requests(
    mr_enclave: MREnclave,
    key: PrivateKey,
    cert: Certificate,
    port: u16,
    shared_priv_key: [u8; SECRET_KEY_SIZE],
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

    while let Ok((stream, _client_ip)) = listener.accept() {
        let conn = ServerConnection::new(config.clone()).context("Failed to connect to client")?;

        let mut tls = rustls::StreamOwned::new(conn, stream);
        let mut buf = [0; 5];
        tls.read_exact(&mut buf)?;

        let mut fstream = FramedStream::from(tls);

        let msg = fstream.recv()?;
        if let Codec::Request(Request::GetKey) = msg {
            fstream.send(Codec::Response(Response::SecretKey(shared_priv_key)))?;
        }

        fstream.close()?;
    }
    Ok(())
}

#[allow(unused)]
pub fn handle_client_requests(
    key: PrivateKey,
    cert: Certificate,
    port: u16,
    shared_pub_key: [u8; PUBLIC_KEY_SIZE],
) -> Result<()> {
    let private_key = PrivatePkcs1KeyDer::from(key);
    let private_key = PrivateKeyDer::from(private_key);
    let cert = CertificateDer::from(cert);

    let config =
        rustls::ServerConfig::builder_with_provider(Arc::new(rustls_rustcrypto::provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert], private_key)
            .context("Failed to build server config")?;
    let config = Arc::new(config);

    let listener =
        TcpListener::bind(format!("0.0.0.0:{}", port)).context("Failed to bind to TCP port")?;

    while let Ok((stream, _client_ip)) = listener.accept() {
        let conn = ServerConnection::new(config.clone()).context("Failed to connect to client")?;

        let mut tls = rustls::StreamOwned::new(conn, stream);
        let mut buf = [0; 5];
        tls.read_exact(&mut buf)?;

        let mut fstream = FramedStream::from(tls);

        let msg = fstream.recv()?;
        if let Codec::Request(Request::GetKey) = msg {
            fstream.send(Codec::Response(Response::PublicKey(shared_pub_key)))?;
        }

        fstream.close()?;
    }
    Ok(())
}
