use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::bail;
use bytes::BufMut;
use serde::{Deserialize, Serialize};

use crate::error::EnclaveError;
use crate::seal_key::SealKeyPair;
use crate::{blockstore, config};

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

pub fn start_handshake_server(shared_seal_key: Arc<SealKeyPair>) -> Result<(), EnclaveError> {
    // bind to userspace address for incoming requests from handshake
    let listener = TcpListener::bind("requests.fleek.network")
        .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
    let semaphore = Arc::new(Semaphore::new(config::MAX_CONCURRENT_WASM_THREADS));

    // Setup a worker thread to spawn connection threads
    let (tx, rx) = std::sync::mpsc::sync_channel::<TcpStream>(2048);
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

    // Handle incoming handshake connections on the main thread
    loop {
        let (conn, _) = listener
            .accept()
            .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
        tx.send(conn)
            .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
    }
}

/// Handle an incoming handshake client connection
pub fn handle_connection(
    shared_seal_key: Arc<SealKeyPair>,
    conn: &mut (impl Read + Write),
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
    let mut module = blockstore::get_verified_content(&hash)?;

    // optionally decrypt the module
    if decrypt {
        module = ecies::decrypt(&shared_seal_key.secret.serialize(), &module)?;
    }

    // run wasm module
    let output = crate::runtime::execute_module(module, &function, input, &shared_seal_key.secret)?;

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