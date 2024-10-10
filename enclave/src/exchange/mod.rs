use std::sync::Arc;
use std::time::Duration;

use bip32::Prefix;
use ra_tls::cert::{generate_cert, generate_key, AttestationPayload};
use ra_tls::EncodeRsaPublicKey;
use sgx_isa::{Keyname, Keypolicy, Keyrequest, Report};
use sha2::Digest;

use crate::config;
use crate::error::EnclaveError;
use crate::req_res::{generate_for_report_data, save_sealed_key};
use crate::seal_key::SealKeyPair;

mod client;
mod codec;
pub mod collateral_prov;
pub mod server;

const MAX_QUOTE_SIZE: usize = 64_000;

/// Initialization output needed for starting the wasm and (m)tls servers up
pub struct Enclave {
    pub shared_seal_key: Arc<SealKeyPair>,
    pub report: Report,
    pub tls_secret_key: Vec<u8>,
    pub tls_cert: Vec<u8>,
}

pub enum SharedSecretMethod {
    InitialNode,
    SealedOnDisk(Vec<u8>),
    FetchFromPeers(Vec<String>),
}

pub fn init() -> Result<Enclave, EnclaveError> {
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
    let quote = generate_for_report_data(report_data).expect("failed to generate quote");
    if quote.len() > MAX_QUOTE_SIZE {
        return Err(EnclaveError::MaxQuoteSizeExceeded);
    }

    let (tls_secret_key, tls_cert) = generate_cert(
        priv_key_tls,
        pub_key_tls,
        AttestationPayload {
            quote: quote.clone(),
        },
        // 1 year
        Duration::from_secs(31536000),
        get_our_ip()?,
    )
    .map_err(|_| EnclaveError::FailedToGenerateTlsKey)?;

    let shared_seal_key = Arc::new(match get_shared_secret_method()? {
        // We already have previously recieved the secret key just need to unencrypt it
        SharedSecretMethod::SealedOnDisk(encoded_secret_key) => {
            println!("Recovering seal key from disk");

            // We already have previously recieved the secret key just need to unencrypt it
            SealKeyPair::from_private_bytes(
                seal_key
                    .unseal(&encoded_secret_key[..208])?
                    .try_into()
                    .expect("invalid sealed data length"),
            )
            .map_err(|_| EnclaveError::GeneratedBadSharedKey)?
        },
        // We need to get the secret key from our peers
        SharedSecretMethod::FetchFromPeers(peer_ips) => {
            println!("Fetching seal key from peers");

            let secret_key_pair = client::get_secret_key_from_peers(
                peer_ips,
                &tls_secret_key,
                &tls_cert,
                report.mrenclave,
            )?;

            // Now that we have the secret key we should seal it and send it to the runner
            // to save to disk for next time we start up
            let mut sealed_shared_secret = seal_key.seal(&secret_key_pair.to_private_bytes())?;
            sealed_shared_secret.extend(&secret_key_pair.to_public_bytes());
            save_sealed_key(sealed_shared_secret);

            secret_key_pair
        },
        SharedSecretMethod::InitialNode => {
            println!("Initializing seal key");

            let shared_secret_key = initialize_shared_secret_key()?;

            // Now that we have the secret key we should seal it and send it to the runner
            // to save to disk for next time we start up
            let mut sealed_shared_secret = seal_key.seal(&shared_secret_key.to_private_bytes())?;
            sealed_shared_secret.extend(&shared_secret_key.to_public_bytes());
            save_sealed_key(sealed_shared_secret);

            shared_secret_key
        },
    });

    println!(
        "Shared seal key:\n- Extended public key: {}\n - Raw hex public key: {}",
        shared_seal_key.public.to_string(Prefix::XPUB),
        hex::encode(shared_seal_key.public.to_bytes())
    );

    Ok(Enclave {
        shared_seal_key,
        report,
        tls_secret_key,
        tls_cert,
    })
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

    Ok(SealKeyPair::from_seed_key(key))
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

fn initialize_shared_secret_key() -> Result<SealKeyPair, EnclaveError> {
    let key = Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRSIGNER,
        isvsvn: 0,
        cpusvn: [0; 16],
        attributemask: [!0; 2],
        // unique key id to derive material from
        keyid: [2; 32],
        miscmask: !0,
        ..Default::default()
    }
    .egetkey()
    .map_err(|_| EnclaveError::EGetKeyFailed)?;

    Ok(SealKeyPair::from_seed_key(key))
}
