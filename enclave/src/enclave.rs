use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
use bytes::BufMut;
use ra_tls::cert::{generate_cert, generate_key, AttestationPayload};
use ra_tls::server::build_config;
use ra_tls::{EncodeRsaPublicKey, ServerConfig, ServerConnection, StreamOwned};
use ra_verify::types::report::MREnclave;
use sgx_isa::{Keyname, Keypolicy, Keyrequest, Report};
use sha2::Digest;

use crate::codec::{Codec, FramedStream, Request, Response, PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
use crate::error::EnclaveError;
use crate::req_res::{generate_for_report_data, save_sealed_key};
use crate::seal_key::SealKeyPair;
use crate::{blockstore, config, ServiceRequest, ServiceResponseHeader};

pub struct Enclave {
    semaphore: Arc<Semaphore>,
    pub shared_seal_key: Arc<SealKeyPair>,
    pub report: Report,
    // we will take these when we start the key sharing server
    pub tls_secret_key: Option<Vec<u8>>,
    pub tls_cert: Option<Vec<u8>>,
}

impl Enclave {
    pub fn init() -> Result<Self, EnclaveError> {
        let report = Report::for_self();
        let seal_key = get_seal_key(&report)?;

        // Generate key for TLS certificate
        let (priv_key_tls, pub_key_tls) =
            generate_key(config::TLS_KEY_SIZE).map_err(|_| EnclaveError::FailedToGenerateTlsKey)?;

        // Append a public key to the report data for the quote
        let mut hasher = sha2::Sha256::new();
        hasher.update(
            pub_key_tls
                .to_pkcs1_der()
                .map_err(|_| EnclaveError::FailedToGenerateTlsKey)?
                .as_bytes(),
        );
        let pk_hash = hasher.finalize();
        let pk_hash_bytes = pk_hash.into_iter().collect::<Vec<_>>();
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&pk_hash_bytes[..32]);

        // Generate quote and collateral
        let (quote, collateral) =
            generate_for_report_data(report_data).expect("failed to generate http report data");

        let (tls_secret_key, tls_cert) = generate_cert(
            priv_key_tls,
            pub_key_tls,
            AttestationPayload {
                quote: quote.clone(),
                collateral: serde_json::to_vec(&collateral)
                    .map_err(|_| EnclaveError::BadCollateral)?,
            },
            // 1 year
            Duration::from_secs(31536000),
            get_our_ip()?,
        )
        .map_err(|_| EnclaveError::FailedToGenerateTlsKey)?;

        let shared_seal_key = Arc::new(match get_shared_secret_method()? {
            SharedSecretMethod::SealedOnDisk(encoded_secret_key) => {
                println!("Recovering seal key from disk");
                // We already have previously recieved the secret key just need to unencrypt it
                SealKeyPair::from_secret_key_slice(&seal_key.unseal(&encoded_secret_key)?)
                    .map_err(|_| EnclaveError::GeneratedBadSharedKey)?
            },
            SharedSecretMethod::FetchFromPeers(peer_ips) => {
                println!("Fetching seal key from peers");
                // We need to get the secret key from our peers

                let secret_key_pair = get_secret_key_from_peers(
                    peer_ips,
                    &tls_secret_key,
                    &tls_cert,
                    report.mrenclave,
                )?;

                // Now that we have the secret key we should seal it and send it to the runner
                // to save to disk for next time we start up
                let mut sealed_shared_secret =
                    seal_key.seal(&secret_key_pair.secret.serialize())?;
                sealed_shared_secret.extend(&secret_key_pair.public.serialize_compressed());
                save_sealed_key(sealed_shared_secret);

                secret_key_pair
            },
            SharedSecretMethod::InitialNode => {
                println!("Initializing seal key");
                let shared_secret_key = initialize_shared_secret_key()?;

                // Now that we have the secret key we should seal it and send it to the runner
                // to save to disk for next time we start up
                let mut sealed_shared_secret =
                    seal_key.seal(&shared_secret_key.secret.serialize())?;
                sealed_shared_secret.extend(&shared_secret_key.public.serialize_compressed());
                save_sealed_key(sealed_shared_secret);

                shared_secret_key
            },
        });

        println!(
            "Shared seal key: {}",
            hex::encode(shared_seal_key.public.serialize_compressed())
        );

        Ok(Self {
            shared_seal_key,
            report,
            semaphore: Arc::new(Semaphore::new(config::MAX_CONCURRENT_WASM_THREADS)),
            tls_secret_key: Some(tls_secret_key),
            tls_cert: Some(tls_cert),
        })
    }

    pub fn run(&mut self) -> Result<(), EnclaveError> {
        // run key sharing server
        let shared_priv_key = self.shared_seal_key.secret.serialize();
        let tls_secret_key = self.tls_secret_key.take().expect("TLS secret key not set");
        let tls_cert = self.tls_cert.take().expect("TLS cert not set");
        let our_mrenclave = self.report.mrenclave;

        // Start mutual TLS server for communication with the enclaves on the other nodes
        let server_config = build_config(
            tls_secret_key.clone(),
            tls_cert.clone(),
            Some(our_mrenclave),
        )
        .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
        std::thread::spawn(move || {
            start_mutual_tls_server(server_config, config::MTLS_PORT, shared_priv_key)
        });

        // Start TLS server for client remote attetation
        let shared_pub_key = self.shared_seal_key.public;
        let server_config = build_config(tls_secret_key.clone(), tls_cert, None)
            .map_err(|_| EnclaveError::FailedToBuildTlsConfig)?;
        std::thread::spawn(move || {
            start_tls_server(
                server_config,
                config::TLS_PORT,
                shared_pub_key.serialize_compressed(),
            )
        });

        // bind to userspace address for incoming requests from handshake
        let listener = TcpListener::bind("requests.fleek.network")
            .map_err(|_| EnclaveError::RunnerConnectionFailed)?;

        // Setup a worker thread to spawn connection threads
        let (tx, rx) = std::sync::mpsc::sync_channel(2048);
        let shared_seal_key = self.shared_seal_key.clone();
        let semaphore = self.semaphore.clone();
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

        // Handle incoming handshake connections
        loop {
            let (conn, _) = listener
                .accept()
                .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
            tx.send(conn)
                .map_err(|_| EnclaveError::RunnerConnectionFailed)?;
        }
    }
}

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

fn start_mutual_tls_server(
    config: ServerConfig,
    port: u16,
    shared_priv_key: [u8; SECRET_KEY_SIZE],
) -> Result<(), EnclaveError> {
    let config = Arc::new(config);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .context("Failed to bind to TCP port")
        .map_err(|_| EnclaveError::TlsServerError)?;

    while let Ok((stream, _client_ip)) = listener.accept() {
        let Ok(conn) = ServerConnection::new(config.clone()) else {
            continue;
        };

        let mut tls = StreamOwned::new(conn, stream);
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

fn start_tls_server(
    config: ServerConfig,
    port: u16,
    shared_pub_key: [u8; PUBLIC_KEY_SIZE],
) -> Result<(), EnclaveError> {
    let config = Arc::new(config);

    let listener = TcpListener::bind(format!("0.0.0.0:{}", port))
        .context("Failed to bind to TCP port")
        .map_err(|_| EnclaveError::TlsServerError)?;

    while let Ok((stream, _client_ip)) = listener.accept() {
        let Ok(conn) = ServerConnection::new(config.clone()) else {
            continue;
        };

        let mut tls = StreamOwned::new(conn, stream);
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

fn get_seal_key(report: &Report) -> Result<SealKeyPair, EnclaveError> {
    let key = Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributemask: [!0; 2],
        // This field would typically be used to make a label for this seal key incase we needed a
        // seal key in multiple parts of the enclave. Since we only need it to seal the shared
        // secret key this should be fine
        keyid: [1; 32],
        miscmask: !0,
        ..Default::default()
    }
    .egetkey()
    .map_err(|_| EnclaveError::EGetKeyFailed)?;

    Ok(SealKeyPair::from_seed_key(&key))
}

fn get_our_ip() -> Result<String, EnclaveError> {
    let args = std::env::args();

    for arg in args {
        if arg.starts_with("--our-ip") {
            return Ok(arg
                .split("=")
                .last()
                .ok_or(EnclaveError::InvalidArgs)?
                .to_string());
        }
    }
    panic!("Our ip was not passed to enclave");
}

fn get_secret_key_from_peers(
    peers: Vec<String>,
    tls_private_key: &[u8],
    tls_cert: &[u8],
    our_mrenclave: MREnclave,
) -> Result<SealKeyPair, EnclaveError> {
    // The runner should shuffle these peers before passing to enclave

    for peer in peers {
        if let Ok(mut tls_stream) = ra_tls::client::connect(
            our_mrenclave,
            peer,
            crate::config::TLS_PORT,
            tls_private_key.to_vec(),
            tls_cert.to_vec(),
        ) {
            if tls_stream.write_all("hello".as_bytes()).is_err() {
                continue;
            }

            if tls_stream.conn.negotiated_cipher_suite().is_none() {
                continue;
            }

            let mut fstream = FramedStream::from(tls_stream);

            if fstream.send(Codec::Request(Request::GetKey)).is_err() {
                continue;
            }

            if let Ok(Codec::Response(Response::SecretKey(data))) = fstream.recv() {
                if let Ok(secret_key) = SealKeyPair::from_secret_key_bytes(&data) {
                    return Ok(secret_key);
                }
            }
        }
    }

    Err(EnclaveError::FailedToFetchSharedKey)
}

fn get_shared_secret_method() -> Result<SharedSecretMethod, EnclaveError> {
    let args = std::env::args();

    for arg in args {
        if arg.starts_with("--encoded-secret-key") {
            let hex_encoded_key = arg
                .split('=')
                .last()
                .ok_or(EnclaveError::InvalidArgs)?
                .to_string();

            let key_bytes = hex::decode(hex_encoded_key).map_err(|_| EnclaveError::BadSavedKey)?;
            return Ok(SharedSecretMethod::SealedOnDisk(key_bytes));
        } else if arg.starts_with("--peer-ips") {
            let ips = arg.split("=").last().ok_or(EnclaveError::InvalidArgs)?;

            return Ok(SharedSecretMethod::FetchFromPeers(
                ips.split(",").map(|ip| ip.to_string()).collect(),
            ));
        } else if arg.starts_with("--initial-node") {
            return Ok(SharedSecretMethod::InitialNode);
        }
    }
    Err(EnclaveError::NoPeersProvided)
}

/// generate shared secret via rdrang rng
fn initialize_shared_secret_key() -> Result<SealKeyPair, EnclaveError> {
    let mut rng = rdrand::RdRand::new().map_err(|_| EnclaveError::EGetKeyFailed)?;
    let mut secret = [0; 32];

    loop {
        rng.try_fill_bytes(&mut secret).unwrap();
        if let Ok(sk) = SealKeyPair::from_secret_key_bytes(&secret) {
            return Ok(sk);
        }
    }
}

pub enum SharedSecretMethod {
    InitialNode,
    SealedOnDisk(Vec<u8>),
    FetchFromPeers(Vec<String>),
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
