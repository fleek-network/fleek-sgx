use error::EnclaveError;
use ra_verify::types::collateral::SgxCollateral;
use serde::Deserialize;

mod attest;
mod blockstore;
mod enclave;
mod error;
mod http;
mod runtime;
mod seal_key;

pub(crate) mod config {
    pub const MAX_OUTPUT_SIZE: usize = 16 << 20; // 16 MiB
    pub const MAX_CONCURRENT_WASM_THREADS: usize = 256;
    pub const TLS_KEY_SIZE: usize = 2048;
    pub const TLS_PORT: u16 = 55855;
    pub const HTTP_PORT: u16 = 8011;
}

#[derive(Deserialize)]
struct ServiceRequest {
    /// Blake3 hash of the wasm module.
    hash: String,
    /// Optionally enable decrypting the wasm file
    #[serde(default)]
    decrypt: bool,
    /// Entrypoint function to call. Defaults to `main`.
    #[serde(default = "default_function_name")]
    function: String,
    /// Input data string.
    #[serde(default)]
    input: String,
}

fn default_function_name() -> String {
    "main".into()
}

fn main() -> Result<(), EnclaveError> {
    let mut enclave = enclave::Enclave::init()?;
    enclave.run()?;
    Ok(())
}
