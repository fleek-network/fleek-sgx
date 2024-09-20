use std::io::Read;
use std::net::TcpListener;
use std::sync::Arc;

use anyhow::Context;
use ra_tls::rustls::{ServerConfig, ServerConnection, StreamOwned};

use super::codec::{Codec, FramedStream, Request, Response, EXTENDED_KEY_SIZE};
use crate::error::EnclaveError;

pub fn start_mutual_tls_server(
    config: ServerConfig,
    port: u16,
    shared_priv_key: [u8; EXTENDED_KEY_SIZE],
) -> Result<(), EnclaveError> {
    let config = Arc::new(config);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .context("Failed to bind to TCP port")
        .map_err(|_| EnclaveError::TlsServerError)?;

    while let Ok((stream, _client_ip)) = listener.accept() {
        let Ok(conn) = ServerConnection::new(config.clone()) else {
            continue;
        };

        let mut tls = StreamOwned::new(conn, stream);
        let mut buf = [0; 5];
        if tls.read_exact(&mut buf).is_err() {
            continue;
        }

        let mut fstream = FramedStream::from(tls);
        let Ok(msg) = fstream.recv() else {
            continue;
        };

        if let Codec::Request(Request::GetKey) = msg {
            if fstream
                .send(Codec::Response(Response::SecretKey(shared_priv_key)))
                .is_err()
            {
                continue;
            }
        }

        if fstream.close().is_err() {
            continue;
        }
    }
    Ok(())
}

pub fn start_tls_server(
    config: ServerConfig,
    port: u16,

    shared_pub_key: [u8; EXTENDED_KEY_SIZE],
) -> Result<(), EnclaveError> {
    let config = Arc::new(config);
    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .context("Failed to bind to TCP port")
        .map_err(|_| EnclaveError::TlsServerError)?;
    while let Ok((stream, _client_ip)) = listener.accept() {
        let Ok(conn) = ServerConnection::new(config.clone()) else {
            continue;
        };
        let mut tls = StreamOwned::new(conn, stream);
        let mut buf = [0; 5];
        if tls.read_exact(&mut buf).is_err() {
            continue;
        }
        let mut fstream = FramedStream::from(tls);
        let Ok(msg) = fstream.recv() else {
            continue;
        };
        if let Codec::Request(Request::GetKey) = msg {
            if fstream
                .send(Codec::Response(Response::PublicKey(shared_pub_key)))
                .is_err()
            {
                continue;
            }
        }
        if fstream.close().is_err() {
            continue;
        }
    }
    Ok(())
}
