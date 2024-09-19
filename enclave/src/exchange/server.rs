use std::io::Read;

use ra_tls::cert::{Certificate, PrivateKey};
use ra_tls::server::RaTlsListener;
use ra_verify::types::report::MREnclave;

use super::codec::{Codec, FramedStream, Request, Response, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};

pub fn handle_enclave_requests(
    mr_enclave: MREnclave,
    key: PrivateKey,
    cert: Certificate,
    port: u16,
    shared_priv_key: [u8; SECRET_KEY_SIZE],
) -> anyhow::Result<()> {
    let mut listener = RaTlsListener::bind(Some(mr_enclave), key, cert, port)?;

    while let Ok(mut tls) = listener.accept() {
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

#[allow(unused)]
pub fn handle_client_requests(
    key: PrivateKey,
    cert: Certificate,
    port: u16,
    shared_pub_key: [u8; PUBLIC_KEY_SIZE],
) -> anyhow::Result<()> {
    let mut listener = ra_tls::server::RaTlsListener::bind(None, key, cert, port)?;
    while let Ok(mut tls) = listener.accept() {
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
