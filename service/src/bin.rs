use std::future::Future;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Result as IoResult;
use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, LazyLock};

use aesm_client::AesmClient;
use attest::AttestationEndpoint;
use enclave_runner::usercalls::{AsyncStream, UsercallExtension};
use enclave_runner::EnclaveBuilder;
use futures::FutureExt;
use sgxs_loaders::isgx::Device as IsgxDevice;

use crate::blockstore::VerifiedStream;

mod attest;
mod blockstore;
mod connection;

static BLOCKSTORE_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    std::env::var("BLOCKSTORE_PATH")
        .expect("BLOCKSTORE_PATH env variable not found")
        .into()
});
static IPC_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    std::env::var("IPC_PATH")
        .expect("IPC_PATH env variable not found")
        .into()
});

const ENCLAVE: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/enclave.sgxs"));

#[derive(Debug)]
struct ExternalService {
    attest_state: Arc<attest::EndpointState>,
}

impl UsercallExtension for ExternalService {
    fn connect_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
        _peer_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<Box<dyn Future<Output = IoResult<Option<Box<dyn AsyncStream>>>> + 'future>>
    {
        async move {
            if let Some(subdomain) = addr.strip_suffix(".fleek.network") {
                // Connect the enclave to a blockstore content-stream
                if let Some(hash) = subdomain.strip_suffix(".blockstore") {
                    let hash = hex::decode(hash).expect("valid blake3 hex");
                    let stream =
                        Box::new(VerifiedStream::new(arrayref::array_ref![hash, 0, 32]).await?)
                            as Box<dyn AsyncStream>;
                    return Ok(Some(stream));
                }

                // Attestation APIs
                if let Some(method) = subdomain.strip_suffix(".attest") {
                    match method {
                        "target_info" | "quote" | "collateral" => {
                            println!("handle {method} endpoint");
                            let stream = Box::new(AttestationEndpoint::new(
                                method,
                                self.attest_state.clone(),
                            )) as Box<dyn AsyncStream>;
                            return Ok(Some(stream));
                        },
                        _ => {},
                    }
                }
            }

            // Otherwise, fallback to default behavior of parsing as an ip address
            Ok(None)
        }
        .boxed_local()
    }

    fn bind_stream<'future>(
        &'future self,
        addr: &'future str,
        _local_addr: Option<&'future mut String>,
    ) -> std::pin::Pin<
        Box<
            dyn Future<Output = IoResult<Option<Box<dyn enclave_runner::usercalls::AsyncListener>>>>
                + 'future,
        >,
    > {
        async move {
            if addr == "requests.fleek.network" {
                // Bind to request listener. Can only be used once (when enclave starts up).
                static STARTED: AtomicBool = AtomicBool::new(false);
                if !STARTED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                    return Ok(Some(
                        Box::new(connection::ConnectionListener::bind().await) as _
                    ));
                }
            }

            // Otherwise, fallback to default behavior of binding to a tcp address.
            Ok(None)
        }
        .boxed_local()
    }
}

fn main() {
    // Extracting platform and uid from whoami
    let sgx_mode = if cfg!(target_env = "sgx") { "HW" } else { "SW" };
    let platform = format!("{} - {}", whoami::platform(), sgx_mode);
    let uid = {
        let mut hasher = DefaultHasher::new();
        whoami::username().hash(&mut hasher);
        whoami::fallible::hostname().unwrap().hash(&mut hasher);
        platform.hash(&mut hasher);
        format!("{:X}", hasher.finish())
    };
    let custom_agent_id = std::env::var("CUSTOM_AGENT_ID").unwrap_or_default();

    // Running the enclave
    let aesm_client = AesmClient::new();
    let mut device = IsgxDevice::new()
        .unwrap()
        .einittoken_provider(aesm_client)
        .build();

    let mut enclave_builder = EnclaveBuilder::new_from_memory(ENCLAVE);

    fn make_arg(arg_name: &str, arg_value: &str) -> Vec<u8> {
        let mut arg = arg_name.as_bytes().to_vec();
        arg.push(b'=');
        arg.extend_from_slice(arg_value.as_bytes());
        arg
    }
    enclave_builder.args([
        make_arg("--uid", &uid),
        make_arg("--platform", &platform),
        make_arg("--custom_agent_id", &custom_agent_id),
    ]);

    // setup attestation state
    let attest_state =
        Arc::new(attest::EndpointState::init().expect("failed to initialize attestation endpoint"));
    println!("initialized attestation endpoint");

    // TODO: figure out a flow to generate a signature for the compiled enclave and committing it.
    enclave_builder.dummy_signature();
    enclave_builder.usercall_extension(ExternalService { attest_state });
    let enclave = enclave_builder.build(&mut device).unwrap();

    enclave
        .run()
        .map_err(|e| {
            println!("Error while executing SGX enclave.\n{}", e);
            std::process::exit(1)
        })
        .unwrap();
}