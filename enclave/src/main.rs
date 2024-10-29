use ra_tls::server::{build_config_mtls, build_config_tls};

use crate::error::EnclaveError;
use crate::exchange::collateral_prov::EnclaveCollateralProvider;
use crate::exchange::Enclave;

mod blockstore;
mod connection;
mod error;
mod exchange;
mod req_res;
mod runtime;
mod seal_key;

pub(crate) mod config {
    /// Maximum size of blockstore content
    pub const MAX_BLOCKSTORE_SIZE: usize = 16 << 20; // 16 MiB
    /// Maxmimum fuel limit allowed to be set by the client
    pub const MAX_FUEL_LIMIT: u64 = 10 << 32; // 40 Billion
    /// Maximum size of input parameter
    pub const MAX_INPUT_SIZE: usize = 8 << 20; // 8 MiB
    /// Maximum size of wasm output
    pub const MAX_OUTPUT_SIZE: usize = 16 << 20; // 16 MiB
    /// Maximum number of concurrent wasm threads.
    /// Must not exceed threads reserved for enclave.
    pub const MAX_CONCURRENT_WASM_THREADS: usize = 128;
    /// TLS key size
    pub const TLS_KEY_SIZE: usize = 2048;
    /// MTLS port to listen on for incoming enclave requests
    pub const MTLS_PORT: u16 = 55855;
    /// TLS port to listen on for incoming public key requests
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
    let server_config = build_config_mtls(
        tls_secret_key.clone(),
        tls_cert.clone(),
        our_mrenclave,
        EnclaveCollateralProvider::default(),
    )
    .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
    let shared_priv_key = shared_seal_key.to_private_bytes();
    std::thread::spawn(move || {
        exchange::server::start_mtls_server(server_config, config::MTLS_PORT, shared_priv_key)
            .unwrap()
    });

    // Start TLS server for client remote attetation
    let shared_pub_key = shared_seal_key.to_public_bytes();
    let server_config = build_config_tls(tls_secret_key.clone(), tls_cert)
        .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
    std::thread::spawn(move || {
        exchange::server::start_tls_server(server_config, config::TLS_PORT, shared_pub_key).unwrap()
    });

    // Start handshake server for incoming client wasm requests
    connection::start_handshake_server(shared_seal_key)
}
