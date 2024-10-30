use std::net::IpAddr;
use std::sync::LazyLock;

use bpaf::{Bpaf, Parser};

/// Parsed arguments
pub static ARGS: LazyLock<Arguments> = LazyLock::new(|| arguments().run());

/// Program arguments passed by the runner
#[derive(Debug, bpaf::Bpaf)]
pub struct Arguments {
    #[bpaf(external)]
    pub shared_secret_method: SharedSecretMethod,
    #[bpaf(external)]
    pub tls_config: TlsConfig,
    #[bpaf(external)]
    pub wasm_config: WasmConfig,
}

/// Shared secret bootstrapping methods
#[derive(Debug, Clone, Bpaf)]
pub enum SharedSecretMethod {
    /// Initial node, generate the key
    #[bpaf(long)]
    InitialNode,
    /// Hex encoded sealed key
    SealedOnDisk(
        #[bpaf(
            long("encoded-secret-key"),
            argument::<String>,
            parse(hex::decode)
        )]
        Vec<u8>,
    ),
    /// Fetch the key from a list of possible peers
    FetchFromPeers(
        #[bpaf(
            long("peer-ips"),
            argument::<String>,
            map(|s| s.split(",").map(|ip| ip.to_string()).collect::<Vec<_>>()),
            guard(|v| !v.is_empty(), "must have at least one peer")
        )]
        Vec<String>,
    ),
}

/// TLS related configuration
#[derive(Debug, Bpaf)]
pub struct TlsConfig {
    /// TLS key size
    #[bpaf(long, guard(|v| *v >= 2048, "key must be at least 2048 bytes"))]
    pub tls_key_size: usize,
    /// Current node ip
    #[bpaf(long)]
    pub our_ip: IpAddr,
    /// MTLS port to listen on for incoming enclave requests
    #[bpaf(long)]
    pub mtls_port: u16,
    /// TLS port to listen on for incoming public key requests
    #[bpaf(long)]
    pub tls_port: u16,
}

/// Wasm runtime related configuration
#[derive(Debug, Bpaf)]
pub struct WasmConfig {
    /// Maximum size of blockstore content
    #[bpaf(long, guard(|v| *v != 0, "max blockstore size cannot be zero"))]
    pub max_blockstore_size: usize,
    /// Maxmimum fuel limit allowed to be set by the client
    #[bpaf(long, guard(|v| *v != 0, "max fuel limit cannot be zero"))]
    pub max_fuel_limit: u64,
    /// Maximum size of input parameter
    #[bpaf(long, guard(|v| *v != 0, "max input cannot be zero"))]
    pub max_input_size: usize,
    /// Maximum size of wasm output
    #[bpaf(long, guard(|v| *v != 0, "max input cannot be zero"))]
    pub max_output_size: usize,
    /// Maximum number of concurrent wasm threads.
    /// Must not exceed threads reserved for enclave.
    #[bpaf(long, guard(|v| *v <= 128, "max wasm threads must be <= 128"))]
    pub max_concurrent_wasm_threads: usize,
    /// Whether to enable printing debug logs from wasm to stdout
    #[bpaf(long, fallback(false))]
    pub debug: bool,
}
