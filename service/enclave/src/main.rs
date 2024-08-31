use error::EnclaveError;
use rouille::{Request, Response};
use serde::Deserialize;

mod attest;
mod blockstore;
mod enclave;
mod error;
mod runtime;

pub(crate) mod config {
    pub const MAX_OUTPUT_SIZE: usize = 16 << 20; // 16 MiB
    pub const TLS_KEY_SIZE: usize = 2048;
    pub const TLS_PORT: u16 = 55855;
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

pub fn start_http_thread(port: u16, report_data: [u8; 64]) {
    println!("Binding http attestation debug server to 0.0.0.0:{port}");

    let (quote, collateral) = crate::attest::generate_for_report_data(report_data)
        .expect("failed to generate http report data");

    println!(
        "got collat {}",
        serde_json::to_string_pretty(&collateral).unwrap()
    );

    std::thread::spawn(move || {
        rouille::start_server(("0.0.0.0", port), move |req: &Request| {
            println!("got req {req:?}");
            rouille::router!(req,
                (GET)(/quote) => {
                    Response::from_data("raw", quote.clone())
                },
                (GET)(/collateral) => {
                    Response::json(&collateral)
                },
                _ => {
                    Response::empty_404()
                }
            )
        });
    });
}

fn main() -> Result<(), EnclaveError> {
    let mut enclave = enclave::Enclave::init()?;
    enclave.run();
    Ok(())
}
