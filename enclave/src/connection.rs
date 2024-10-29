use std::borrow::Cow;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};

use anyhow::bail;
use bytes::BufMut;
use libsecp256k1::Signature;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::config::MAX_FUEL_LIMIT;
use crate::error::EnclaveError;
use crate::seal_key::SealKeyPair;
use crate::{blockstore, config};

/// Client request to the service
#[derive(Serialize, Deserialize)]
struct ServiceRequest<'a> {
    /// Blake3 hash of the wasm module.
    hash: Cow<'a, str>,

    /// Optionally enable decrypting the wasm file
    #[serde(default)]
    decrypt: bool,

    /// Fuel limit to set. Defaults to the maximum instruction count.
    /// Node can implement a check against the client balance to be
    /// able to pay for the computation or not.
    #[serde(
        default = "ServiceRequest::max_fuel_limit",
        deserialize_with = "de_fuel"
    )]
    fuel: u64,

    /// Entrypoint function to call. Defaults to `main` if not set.
    #[serde(default = "ServiceRequest::default_function_name")]
    function: Cow<'a, str>,

    /// Input data string.
    #[serde(default)]
    input: Cow<'a, str>,
}

/// Deserialize fuel u64, and ensure it's less than configured fuel limit
fn de_fuel<'de, D: Deserializer<'de>>(de: D) -> Result<u64, D::Error> {
    let n = u64::deserialize(de)?;
    if n <= MAX_FUEL_LIMIT {
        Ok(n)
    } else {
        Err(serde::de::Error::custom(format!(
            "requested fuel limit greater than maximum ({MAX_FUEL_LIMIT})"
        )))
    }
}

impl ServiceRequest<'_> {
    /// Maximum and default fuel limit (~40 Billion)
    const fn max_fuel_limit() -> u64 {
        crate::config::MAX_FUEL_LIMIT
    }

    /// Default function name to run (`main`)
    const fn default_function_name() -> Cow<'static, str> {
        Cow::Borrowed("main")
    }

    /// Hashing function for request parameters
    ///
    /// ## Pseudo-code
    ///
    /// ```text
    /// Sha256(
    ///   "MODULE_HASH" . hex encoded hash .
    ///   "MODULE_DECRYPT" . 0 or 1 .
    ///   "FUEL_LIMIT" . be u64 .
    ///   "FUNCTION_NAME" . u8 length . name .
    ///   "INPUT_DATA" . be u64 length . data
    /// )
    /// ```
    pub fn hash_parameters(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();

        // UTF8 hex-encoded blake3 hash
        hasher.update(b"MODULE_HASH");
        hasher.update(self.hash.as_bytes());
        // Decrypt flag (0 or 1)
        hasher.update(b"MODULE_DECRYPT");
        hasher.update([self.decrypt as u8]);
        // Big endian encoded 128 bit fuel limit
        hasher.update(b"FUEL_LIMIT");
        hasher.update(u64::to_be_bytes(self.fuel));
        // Function name to call
        hasher.update(b"FUNCTION_NAME");
        hasher.update((self.function.len() as u8).to_be_bytes());
        hasher.update(self.function.as_bytes());
        // Input data provided
        hasher.update(b"INPUT_DATA");
        hasher.update((self.input.len() as u64).to_be_bytes());
        hasher.update(self.input.as_bytes());

        hasher.finalize().into()
    }
}

#[derive(Serialize, Deserialize)]
struct ServiceResponseHeader {
    /// Hex-encoded sha256 hash for the input parameters
    #[serde(with = "hex")]
    input_hash: [u8; 32],

    /// Amount of fuel used in the request
    fuel_used: u64,

    /// Hex-encoded blake3 hash for the output
    #[serde(with = "hex")]
    output_hash: [u8; 32],

    /// Blake3 tree for the output.
    /// If content is only one block (256KiB), the tree is ignored
    #[serde(with = "hex")]
    #[serde(skip_serializing_if = "tree_is_one_hash")]
    output_tree: Vec<u8>,

    /// Network shared key signature for sha256(hash . input hash), encoded as [ r . s . v ]
    #[serde(with = "hex")]
    signature: [u8; 65],
}

const fn tree_is_one_hash(tree: &[u8]) -> bool {
    tree.len() == 32
}

impl ServiceResponseHeader {
    /// Sign a new response header for a given input and output with the shared seal key
    ///
    /// ## Pseudo-code
    ///
    /// ```text
    /// hash = Sha256(
    ///     "INPUT_HASH" . input hash .
    ///     "FUEL_USED" . be u64 .
    ///     "OUTPUT_HASH" . output hash
    /// )
    /// signature = shared_key.sign(hash)
    /// ```
    fn sign_request(
        req: &ServiceRequest,
        fuel_used: u64,
        output_hash: [u8; 32],
        output_tree: Vec<u8>,
        shared_seal_key: &SealKeyPair,
    ) -> Self {
        let input_hash = req.hash_parameters();

        let mut hasher = Sha256::new();
        hasher.update(b"INPUT_HASH");
        hasher.update(input_hash);
        hasher.update(b"FUEL_USED");
        hasher.update(u64::to_be_bytes(fuel_used));
        hasher.update(b"OUTPUT_HASH");
        hasher.update(output_hash);
        let hash = hasher.finalize();

        // Sign output with shared key
        let (Signature { r, s }, v) = libsecp256k1::sign(
            &libsecp256k1::Message::parse(hash.as_ref()),
            &shared_seal_key.secret.private_key().0,
        );

        // Encode signature
        let mut signature = [0u8; 65];
        signature[0..32].copy_from_slice(&r.b32());
        signature[32..64].copy_from_slice(&s.b32());
        signature[64] = v.into();

        Self {
            input_hash,
            fuel_used,
            output_hash,
            output_tree,
            signature,
        }
    }
}

pub fn start_handshake_server(shared_seal_key: Arc<SealKeyPair>) -> Result<(), EnclaveError> {
    // check if debug printing should be enabled
    let debug_print = std::env::args().any(|v| v == "--debug");

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
                if let Err(e) = handle_connection(shared_seal_key, &mut conn, debug_print) {
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
fn handle_connection(
    shared_seal_key: Arc<SealKeyPair>,
    conn: &mut (impl Read + Write),
    debug_print: bool,
) -> anyhow::Result<()> {
    println!("handling connection in enclave");

    // Read length delimiter
    let mut buf = [0; 4];
    conn.read_exact(&mut buf)?;
    let len = u32::from_be_bytes(buf) as usize;

    if len >= config::MAX_INPUT_SIZE {
        bail!("input too large");
    }

    // Read and parse payload
    let mut payload = vec![0; len];
    conn.read_exact(&mut payload)?;
    let request: ServiceRequest = serde_json::from_slice(&payload)?;

    // Fetch content from blockstore
    let (hash, mut module) = blockstore::get_verified_content(&request.hash)?;

    // Optionally decrypt the module
    if request.decrypt {
        module = ecies::decrypt(&shared_seal_key.secret.to_bytes(), &module)?;
    }

    // Run wasm module
    // TODO: Should we rehash encrypted content, since the encryption hash is
    // non-determanistic, and thus permissions might differ even though module is the same?
    let output = crate::runtime::execute_module(
        hash,
        module,
        request.fuel,
        &request.function,
        request.input.as_bytes(),
        shared_seal_key.clone(),
        debug_print,
    )?;

    // Sign and construct output header
    let signed_header = ServiceResponseHeader::sign_request(
        &request,
        output.fuel_used,
        output.hash.into(),
        output.tree.into_iter().flatten().collect(),
        &shared_seal_key,
    );

    // TODO: Response encodings
    //       - For http: send hash, proof, signature via headers, stream payload in response body.
    //         Should we also allow setting the content-type header from the wasm module?
    //         - X-FLEEK-SGX-OUTPUT-HASH: hex encoded
    //         - X-FLEEK-SGX-OUTPUT-TREE: base64
    //         - X-FLEEK-SGX-OUTPUT-SIGNATURE: base64
    //       - For all others: send hash, signature, then verified b3 stream of content

    // For now, send a json header before the output data, delimiting with a CRLF `\r\n`
    let mut header = serde_json::to_vec(&signed_header)?;
    header.put_slice(b"\r\n");

    // Write to output
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
