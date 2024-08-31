use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use ecies::{decrypt, encrypt, PublicKey, SecretKey};
use ra_tls::cert::{generate_cert, generate_key, AttestationPayload};
use ra_tls::codec::{Codec, Response};
use ra_tls::server::handle_enclave_requests;
use ra_tls::EncodeRsaPublicKey;
use ra_verify::types::collateral::SgxCollateral;
use ra_verify::types::report::MREnclave;
use sgx_isa::{Keyname, Keypolicy, Keyrequest, Report};
use sha2::Digest;

use crate::error::EnclaveError;
use crate::{blockstore, config, ServiceRequest};

pub struct Enclave {
    pub shared_secret: KeyPair,
    pub report: Report,
    // we will take these when we start the key sharing server
    pub tls_secret_key: Option<Vec<u8>>,
    pub tls_cert: Option<Vec<u8>>,
    pub quote: Option<Vec<u8>>,
    pub collateral: Option<SgxCollateral>,
}

impl Enclave {
    pub fn init() -> Result<Self, EnclaveError> {
        let report = Report::for_self();
        let seal_key = get_seal_key(&report);

        // Generate key for TLS certificate
        let (priv_key_tls, pub_key_tls) = generate_key(config::TLS_KEY_SIZE).unwrap();

        // Append a public key to the report data for the quote
        let mut hasher = sha2::Sha256::new();
        hasher.update(pub_key_tls.to_pkcs1_der().unwrap().as_bytes());
        let pk_hash = hasher.finalize();
        let pk_hash_bytes = pk_hash.into_iter().collect::<Vec<_>>();
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&pk_hash_bytes[..32]);

        // Generate quote and collateral
        let (quote, collateral) = crate::attest::generate_for_report_data(report_data)
            .expect("failed to generate http report data");

        let (tls_secret_key, tls_cert) = generate_cert(
            priv_key_tls,
            pub_key_tls,
            AttestationPayload {
                quote: quote.clone(),
                collateral: serde_json::to_vec(&collateral).unwrap(),
            },
            // 1 year
            Duration::from_secs(31536000),
            get_our_ip(),
        )
        .unwrap();

        let shared_secret_key = match get_shared_secret_method()? {
            SharedSecretMethod::SealedOnDisk(encoded_secret_key) => {
                // We already have previously recieved the secret key just need to unencrypt it
                SecretKey::parse_slice(&seal_key.unseal(encoded_secret_key.as_bytes()))
                    .expect("Bad Sealed Shared Key")
            },
            SharedSecretMethod::FetchFromPeers(peer_ips) => {
                // We need to get the secret key from our peers

                let secret_key = get_secret_key_from_peers(
                    peer_ips,
                    &tls_secret_key,
                    &tls_cert,
                    report.mrenclave,
                )
                .unwrap();

                // Now that we have the secret key we should seal it and send it to the runner
                // to save to disk for next time we start up
                let _sealed_shared_secret = seal_key.seal(&secret_key.serialize());
                // todo: Send to runner to save to disk

                secret_key
            },
            SharedSecretMethod::InitialNode => {
                let shared_secret_key = initialize_shared_secret_key(&report)?;

                // Now that we have the secret key we should seal it and send it to the runner
                // to save to disk for next time we start up
                let _sealed_shared_secret = seal_key.seal(&shared_secret_key.serialize());
                // todo: Send to runner to save to disk

                shared_secret_key
            },
        };

        Ok(Self {
            shared_secret: KeyPair::new(shared_secret_key),
            report,
            tls_secret_key: Some(tls_secret_key),
            tls_cert: Some(tls_cert),
            quote: Some(quote),
            collateral: Some(collateral),
        })
    }

    pub fn run(&mut self) {
        // run key sharing server
        let shared_priv_key = self.shared_secret.secret.serialize();
        let tls_secret_key = self.tls_secret_key.take().expect("TLS secret key not set");
        let tls_cert = self.tls_cert.take().expect("TLS cert not set");
        let our_mrenclave = self.report.mrenclave;

        std::thread::spawn(move || {
            handle_enclave_requests(
                our_mrenclave,
                tls_secret_key,
                tls_cert,
                config::TLS_PORT,
                shared_priv_key,
            )
        });

        // run wasm request server

        // bind to userspace address for incoming requests from handshake
        let listener = TcpListener::bind("requests.fleek.network").unwrap();

        // Handle incoming handshake connections
        loop {
            let (mut conn, _) = listener.accept().unwrap();
            if let Err(e) = self.handle_connection(&mut conn) {
                let error = format!("Error: {e}");
                eprintln!("{error}");
                let _ = conn.write_all(&(error.len() as u32).to_be_bytes());
                let _ = conn.write_all(error.as_bytes());
            }
        }
    }

    fn handle_connection(&self, conn: &mut TcpStream) -> anyhow::Result<()> {
        println!("handling connection in enclave");
        // read length delimiter
        let mut buf = [0; 4];
        conn.read_exact(&mut buf)?;
        let len = u32::from_be_bytes(buf);

        // read payload
        let mut payload = vec![0; len as usize];
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
            module = ecies::decrypt(&self.shared_secret.secret.serialize(), &module)?;
        }

        // run wasm module
        let output =
            crate::runtime::execute_module(module, &function, input, &self.shared_secret.secret)?;

        // TODO: Response encodings
        //       - For http: send hash, proof, signature via headers, stream payload in response
        //         body. Should we also allow setting the content-type header from the wasm module?
        //         - X-FLEEK-SGX-OUTPUT-HASH: hex encoded
        //         - X-FLEEK-SGX-OUTPUT-TREE: base64
        //         - X-FLEEK-SGX-OUTPUT-SIGNATURE: base64
        //       - For all others: send hash, signature, then verified b3 stream of content

        // temporary: write wasm output directly
        conn.write_all(&(output.payload.len() as u32).to_be_bytes())?;
        conn.write_all(&output.payload)?;

        Ok(())
    }
}

pub struct KeyPair {
    pub public: PublicKey,
    secret: SecretKey,
}

impl KeyPair {
    pub fn new(secret: SecretKey) -> Self {
        Self {
            public: PublicKey::from_secret_key(&secret),
            secret,
        }
    }

    pub fn unseal(&self, msg: &[u8]) -> Vec<u8> {
        decrypt(&self.secret.serialize(), msg).unwrap()
    }

    pub fn seal(&self, msg: &[u8]) -> Vec<u8> {
        encrypt(&self.public.serialize(), msg).unwrap()
    }
}

fn get_seal_key(report: &Report) -> KeyPair {
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
    .unwrap();

    // todo: Is this safe with only [u8; 16]
    let secret_key = SecretKey::parse_slice(&key).unwrap();

    KeyPair::new(secret_key)
}

fn get_our_ip() -> String {
    let args = std::env::args();

    for arg in args {
        if arg.starts_with("--our-ip") {
            return arg.split("=").last().unwrap().to_string();
        }
    }
    panic!("Our ip was not passed to enclave");
}

fn get_secret_key_from_peers(
    peers: Vec<String>,
    tls_private_key: &[u8],
    tls_cert: &[u8],
    our_mrenclave: MREnclave,
) -> Result<SecretKey, EnclaveError> {
    // The runner should shuffle these peers before passing to enclave

    for peer in peers {
        if let Ok((mut fstream, _)) = ra_tls::client::connect(
            our_mrenclave,
            peer,
            crate::config::TLS_PORT,
            tls_private_key.to_vec(),
            tls_cert.to_vec(),
        ) {
            if let Err(_e /* fuck you clippy */) =
                fstream.send(Codec::Request(ra_tls::codec::Request::GetKey))
            {
                continue;
            }

            if let Ok(Codec::Response(Response::SecretKey(data))) = fstream.recv() {
                return Ok(SecretKey::parse_slice(&data).unwrap());
            }
        }
    }

    Err(EnclaveError::FailedToFetchSharedKey)
}

fn get_shared_secret_method() -> Result<SharedSecretMethod, EnclaveError> {
    let args = std::env::args();

    for arg in args {
        if arg.starts_with("--encoded-secret-key") {
            return Ok(SharedSecretMethod::SealedOnDisk(
                arg.split('=').last().unwrap().to_string(),
            ));
        } else if arg.starts_with("--peer-ips") {
            let ips = arg.split("=").last().unwrap();

            return Ok(SharedSecretMethod::FetchFromPeers(
                ips.split(",").map(|ip| ip.to_string()).collect(),
            ));
        } else if arg.starts_with("--initial-node") {
            return Ok(SharedSecretMethod::InitialNode);
        }
    }
    Err(EnclaveError::NoPeersProvided)
}

fn initialize_shared_secret_key(report: &Report) -> Result<SecretKey, EnclaveError> {
    // Since egetkey() returns 16 bytes we will call it twice with different labels to generate 32
    // bytes to seed the shared secret
    let mut rng = rdrand::RdRand::new().unwrap();

    let mut keyid = [0; 32];
    {
        let label = "Shared Secret Key Part 1".as_bytes();

        let (label_dst, rand_dst) = keyid.split_at_mut(16);
        label_dst.copy_from_slice(&label[..16]);
        rng.try_fill_bytes(rand_dst).unwrap();
    }

    let key_part_one = Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributemask: [!0; 2],
        // This field would typically be used to make a label for this seal key incase we needed a
        // seal key in multiple parts of the enclave. Since we only need it to seal the shared
        // secret key this should be fine
        keyid,
        miscmask: !0,
        ..Default::default()
    }
    .egetkey()
    .map_err(|_| EnclaveError::EGetKeyFailed)?;

    let mut key_id = [0; 32];
    {
        let label = "Last Part of Secret Key part 2".as_bytes();

        let (label_dst, rand_dst) = key_id.split_at_mut(16);
        label_dst.copy_from_slice(&label[..16]);
        rng.try_fill_bytes(rand_dst).unwrap();
    }

    let key_part_two = Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributemask: [!0; 2],
        // This field would typically be used to make a label for this seal key incase we needed a
        // seal key in multiple parts of the enclave. Since we only need it to seal the shared
        // secret key this should be fine
        keyid,
        miscmask: !0,
        ..Default::default()
    }
    .egetkey()
    .map_err(|_| EnclaveError::EGetKeyFailed)?;

    let mut shared_secret = [0; 32];
    shared_secret[..16].copy_from_slice(&key_part_one[..16]);
    shared_secret[16..].copy_from_slice(&key_part_two[..16]);

    Ok(SecretKey::parse_slice(&shared_secret).map_err(|_| EnclaveError::GeneratedBadSharedKey)?)
}

pub enum SharedSecretMethod {
    InitialNode,
    SealedOnDisk(String),
    FetchFromPeers(Vec<String>),
}
