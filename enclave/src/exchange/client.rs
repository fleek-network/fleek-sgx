use std::io::Write;

use ra_verify::types::report::MREnclave;

use super::codec::{Codec, FramedStream, Request, Response};
use crate::error::EnclaveError;
use crate::req_res::get_collateral;
use crate::seal_key::SealKeyPair;

pub fn get_secret_key_from_peers(
    peers: Vec<String>,
    tls_private_key: &[u8],
    tls_cert: &[u8],
    our_mrenclave: MREnclave,
) -> Result<SealKeyPair, EnclaveError> {
    // The runner should shuffle these peers before passing to enclave
    for peer in peers {
        if let Ok(mut stream) = ra_tls::client::connect_mtls(
            our_mrenclave,
            |quote| get_collateral(&quote).map(|c| serde_json::to_vec(&c).unwrap()),
            peer,
            crate::config::MTLS_PORT,
            tls_private_key.to_vec(),
            tls_cert.to_vec(),
        ) {
            if stream.write_all("hello".as_bytes()).is_err() {
                continue;
            }
            if stream.conn.negotiated_cipher_suite().is_none() {
                continue;
            }

            let mut fstream = FramedStream::from(stream);
            if fstream.send(Codec::Request(Request::GetKey)).is_err() {
                continue;
            }

            if let Ok(Codec::Response(Response::SecretKey(data))) = fstream.recv() {
                if let Ok(secret_key) = SealKeyPair::from_private_bytes(data) {
                    return Ok(secret_key);
                }
            }
        }
    }

    Err(EnclaveError::FailedToFetchSharedKey)
}
