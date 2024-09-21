use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::bail;
use bytes::BufMut;
use error::EnclaveError;
use exchange::server::handle_enclave_requests;
use exchange::EnclaveState;
use ra_verify::types::collateral::SgxCollateral;
use seal_key::SealKeyPair;
use serde::{Deserialize, Serialize};

mod blockstore;
mod error;
mod exchange;
mod http;
mod req_res;
mod runtime;
mod seal_key;

pub(crate) mod config {
    pub const MAX_BLOCKSTORE_SIZE: usize = 16 << 20; // 16 MiB
    pub const MAX_INPUT_SIZE: usize = 8 << 20; // 8 MiB
    pub const MAX_OUTPUT_SIZE: usize = 16 << 20; // 16 MiB
    pub const MAX_CONCURRENT_WASM_THREADS: usize = 128;
    pub const TLS_KEY_SIZE: usize = 2048;
    pub const TLS_PORT: u16 = 55855;
    pub const HTTP_PORT: u16 = 8011;
}

#[derive(Serialize, Deserialize)]
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

#[derive(Serialize, Deserialize)]
struct ServiceResponseHeader {
    /// Content hash
    #[serde(with = "hex")]
    hash: [u8; 32],
    /// Content blake3 tree
    #[serde(with = "hex")]
    tree: Vec<u8>,
    /// Network shared key signature
    #[serde(with = "hex")]
    signature: [u8; 65],
}

/// Synchronous semaphore that doesn't consume any cpu time when waiting.
struct Semaphore {
    count: Mutex<usize>,
    cv: Condvar,
}

impl Semaphore {
    /// Create a new semaphore with a max resource count.
    fn new(max: usize) -> Self {
        Self {
            count: Mutex::new(max),
            cv: Condvar::new(),
        }
    }

    /// Aquire a single resource, returning a guard.
    fn aquire(self: Arc<Semaphore>) -> SemaphoreGuard {
        {
            let mut count = self.count.lock().expect("failed to aquire lock");
            count = self
                .cv
                .wait_while(count, |c| *c == 0)
                .expect("failed to wait for condvar");
            *count -= 1;
        }
        SemaphoreGuard(self)
    }
}

/// Guard holding a semaphore resource.
struct SemaphoreGuard(Arc<Semaphore>);

impl Drop for SemaphoreGuard {
    fn drop(&mut self) {
        *self.0.count.lock().expect("failed to aquire lock") += 1;
        self.0.cv.notify_one();
    }
}

/// Handle an incoming handshake client connection
fn handle_connection(
    shared_seal_key: Arc<SealKeyPair>,
    conn: &mut TcpStream,
) -> anyhow::Result<()> {
    println!("handling connection in enclave");
    // read length delimiter
    let mut buf = [0; 4];
    conn.read_exact(&mut buf)?;
    let len = u32::from_be_bytes(buf) as usize;

    if len >= config::MAX_INPUT_SIZE {
        bail!("input too large");
    }

    // read payload
    let mut payload = vec![0; len];
    conn.read_exact(&mut payload)?;

    // parse payload
    let ServiceRequest {
        hash,
        function,
        input,
        decrypt,
    } = serde_json::from_slice(&payload)?;

    // fetch content from blockstore
    let (hash, mut module) = blockstore::get_verified_content(&hash)?;

    // optionally decrypt the module
    if decrypt {
        module = ecies::decrypt(&shared_seal_key.secret.to_bytes(), &module)?;
    }

    // run wasm module
    let output =
        crate::runtime::execute_module(hash, module, &function, input, shared_seal_key.clone())?;

    // TODO: Response encodings
    //       - For http: send hash, proof, signature via headers, stream payload in response body.
    //         Should we also allow setting the content-type header from the wasm module?
    //         - X-FLEEK-SGX-OUTPUT-HASH: hex encoded
    //         - X-FLEEK-SGX-OUTPUT-TREE: base64
    //         - X-FLEEK-SGX-OUTPUT-SIGNATURE: base64
    //       - For all others: send hash, signature, then verified b3 stream of content

    // For now, send a json header before the output data, delimiting with a CRLF `\r\n`
    let mut header = serde_json::to_vec(&ServiceResponseHeader {
        hash: output.hash.into(),
        tree: output.tree.into_iter().flatten().collect(),
        signature: output.signature,
    })?;
    header.put_slice(b"\r\n");

    let len = (header.len() + output.payload.len()) as u32;
    conn.write_all(&len.to_be_bytes())?;
    conn.write_all(&header)?;
    conn.write_all(&output.payload)?;

    Ok(())
}

fn main() -> Result<(), EnclaveError> {
    println!("enclave started");

    // Perform key exchange initialization sequence
    let EnclaveState {
        shared_seal_key,
        report,
        tls_secret_key,
        tls_cert,
        quote,
        collateral,
    } = exchange::init()?;

    // Spawn thread to run key sharing server
    let our_mrenclave = report.mrenclave;
    let shared_priv_key = shared_seal_key.to_private_bytes();
    std::thread::spawn(move || {
        handle_enclave_requests(
            our_mrenclave,
            tls_secret_key.clone(),
            tls_cert,
            config::TLS_PORT,
            shared_priv_key,
        )
    });

    // Spawn thread to run debug http verification data server
    let shared_pub_key = shared_seal_key.to_public_bytes();
    std::thread::spawn(move || {
        crate::http::start_server(config::HTTP_PORT, quote, collateral, &shared_pub_key);
    });

    // bind to userspace address for incoming requests from handshake
    let listener = TcpListener::bind("requests.fleek.network")
        .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
    let semaphore = Arc::new(Semaphore::new(config::MAX_CONCURRENT_WASM_THREADS));

    // Spawn a worker thread to process new connections and spawn threads for them
    let (tx, rx) = std::sync::mpsc::sync_channel(2048);
    let shared_seal_key = shared_seal_key.clone();
    let semaphore = semaphore.clone();
    std::thread::spawn(move || {
        while let Ok(mut conn) = rx.recv() {
            let shared_seal_key = shared_seal_key.clone();
            let semaphore = semaphore.clone();

            // Wait for limit on max concurrency
            let guard = semaphore.aquire();

            // Spawn a new thread to handle the connection
            std::thread::spawn(move || {
                // handle connection
                if let Err(e) = handle_connection(shared_seal_key, &mut conn) {
                    let error = format!("Error: {e}");
                    eprintln!("{error}");
                    let _ = conn.write_all(&(error.len() as u32).to_be_bytes());
                    let _ = conn.write_all(error.as_bytes());
                }
                drop(guard)
            });
        }
    });

    // Handle incoming handshake connections on the main thread,
    // and send them to the worker thread.
    loop {
        let (conn, _) = listener
            .accept()
            .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
        tx.send(conn)
            .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
    }
}
