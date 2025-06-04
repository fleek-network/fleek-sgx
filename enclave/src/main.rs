use args::ARGS;
use ra_tls::server::{build_config_mtls, build_config_tls};

use crate::error::EnclaveError;
use crate::exchange::collateral_prov::EnclaveCollateralProvider;
use crate::exchange::Enclave;

mod args;
mod blockstore;
mod connection;
mod error;
mod exchange;
mod req_res;
mod runtime;
mod seal_key;

pub(crate) mod config {}

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
    println!(
        "Finished initialization for MRENCLAVE: {}",
        hex::encode(our_mrenclave)
    );

    let server_config = build_config_mtls(
        tls_secret_key.clone(),
        tls_cert.clone(),
        our_mrenclave,
        EnclaveCollateralProvider::default(),
    )
    .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
    let shared_priv_key = shared_seal_key.to_private_bytes();
    std::thread::spawn(move || {
        exchange::server::start_mtls_server(
            server_config,
            ARGS.tls_config.mtls_port,
            shared_priv_key,
        )
        .unwrap()
    });

    // Start TLS server for client remote attetation
    let shared_pub_key = shared_seal_key.to_public_bytes();
    let server_config = build_config_tls(tls_secret_key.clone(), tls_cert)
        .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
    std::thread::spawn(move || {
        exchange::server::start_tls_server(server_config, ARGS.tls_config.tls_port, shared_pub_key)
            .unwrap()
    });

    // Start handshake server for incoming client wasm requests
    connection::start_handshake_server(shared_seal_key)
}
