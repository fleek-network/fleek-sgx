use std::sync::Arc;

use anyhow::bail;
use blake3_tree::blake3::tree::HashTree;
use blake3_tree::blake3::Hash;
use bytes::Bytes;
use libsecp256k1::Signature;
use wasmi::{Config, Engine, Linker, Module, Store};

use crate::runtime::host::HostState;
use crate::seal_key::SealKeyPair;

mod host;

/// Verified wasm runtime output
#[allow(unused)]
pub struct WasmOutput {
    pub payload: Bytes,
    pub hash: Hash,
    pub tree: Vec<[u8; 32]>,
    pub signature: [u8; 65],
}

pub fn execute_module(
    module: impl AsRef<[u8]>,
    entry: &str,
    request: impl Into<Bytes>,
    shared_secret_key: Arc<SealKeyPair>,
) -> anyhow::Result<WasmOutput> {
    let input = request.into();
    println!("input data: {input:?}");

    // Configure wasm engine
    let mut config = Config::default();
    config
        // TODO(oz): should we use fuel tracking for payments/execution limits?
        .compilation_mode(wasmi::CompilationMode::LazyTranslation)
        .set_stack_limits(wasmi::StackLimits {
            initial_value_stack_height: 512 << 10, // 512 KiB
            maximum_value_stack_height: 5 << 20,   // 5 MiB
            maximum_recursion_depth: 65535,
        });
    let engine = Engine::new(&config);
    let mut store = Store::new(&engine, HostState::new(input));

    // Setup linker and define the host functions
    let mut linker = <Linker<HostState>>::new(&engine);
    host::define(&mut store, &mut linker).expect("failed to define host functions");

    // Initialize the module
    let module = Module::new(&engine, module.as_ref())?;
    let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;

    if instance.get_memory(&mut store, "memory").is_none() {
        bail!("`memory` not found in wasm instance")
    }

    // Get entrypoint function and call it
    // TODO(oz): Should we support calling the function with `int argc, *argv[]`?
    //           We could expose an "args" request parameter with a vec of strings.
    //           If not, how can we eliminate needing to satisfy this signature?
    let func = instance.get_typed_func::<(i32, i32), i32>(&mut store, entry)?;
    func.call(&mut store, (0, 0))?;

    let (HashTree { hash, tree }, payload) = store.into_data().finalize();

    // Sign output
    let (Signature { r, s }, v) = libsecp256k1::sign(
        &libsecp256k1::Message::parse(hash.as_bytes()),
        &shared_secret_key.secret.private_key().0,
    );

    // Encode signature, ethereum style
    let mut signature = [0u8; 65];
    signature[0..32].copy_from_slice(&r.b32());
    signature[32..64].copy_from_slice(&s.b32());
    signature[64] = v.into();

    println!("wasm output: {hash}");

    Ok(WasmOutput {
        payload,
        hash,
        tree,
        signature,
    })
}
