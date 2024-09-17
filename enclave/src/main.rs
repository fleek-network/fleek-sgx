use ra_tls::server::build_config;

use crate::error::EnclaveError;
use crate::exchange::Enclave;

mod blockstore;
mod connection;
mod error;
mod exchange;
mod req_res;
mod runtime;
mod seal_key;

pub(crate) mod config {
    pub const MAX_BLOCKSTORE_SIZE: usize = 16 << 20; // 16 MiB
    pub const MAX_INPUT_SIZE: usize = 8 << 20; // 8 MiB
    pub const MAX_OUTPUT_SIZE: usize = 16 << 20; // 16 MiB
    pub const MAX_CONCURRENT_WASM_THREADS: usize = 128;
    pub const TLS_KEY_SIZE: usize = 2048;
    pub const MTLS_PORT: u16 = 55855;
    pub const TLS_PORT: u16 = 55856;
}

fn main() -> Result<(), EnclaveError> {
    println!("enclave started");

    // Run initialization routine to get the sealing key, self report, and tls info
    let Enclave {
        shared_seal_key,
        report,
        tls_secret_key,
        tls_cert,
    } = exchange::init()?;

    // Start mutual TLS server for communication with the enclaves on the other nodes
    let our_mrenclave = report.mrenclave;
    let server_config = build_config(
        tls_secret_key.clone(),
        tls_cert.clone(),
        Some(our_mrenclave),
    )
    .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
    let shared_priv_key = shared_seal_key.secret.serialize();
    std::thread::spawn(move || {
        exchange::server::start_mutual_tls_server(server_config, config::MTLS_PORT, shared_priv_key)
    });

    // Start TLS server for client remote attetation
    let shared_pub_key = shared_seal_key.public;
    let server_config = build_config(tls_secret_key.clone(), tls_cert, None)
        .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
    std::thread::spawn(move || {
        exchange::server::start_tls_server(
            server_config,
            config::TLS_PORT,
            shared_pub_key.serialize_compressed(),
        )
    });

    // Start handshake server for incoming client wasm requests
    connection::start_handshake_server(shared_seal_key)
}
