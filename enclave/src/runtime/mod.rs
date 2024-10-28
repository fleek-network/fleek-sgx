use std::sync::Arc;

use anyhow::bail;
use blake3_tree::blake3::tree::HashTree;
use blake3_tree::blake3::Hash;
use bytes::Bytes;
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
}

pub fn execute_module(
    hash: [u8; 32],
    module: impl AsRef<[u8]>,
    name: &str,
    input: &[u8],
    shared_secret_key: Arc<SealKeyPair>,
    debug_print: bool,
) -> anyhow::Result<WasmOutput> {
    let input = input.to_vec().into();
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
    let mut store = Store::new(
        &engine,
        HostState::new(shared_secret_key, hash, input, debug_print),
    );

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
    let func = instance.get_typed_func::<(i32, i32), i32>(&mut store, name)?;
    func.call(&mut store, (0, 0))?;

    let (HashTree { hash, tree }, payload) = store.into_data().finalize();

    println!("wasm output: {hash}");

    Ok(WasmOutput {
        payload,
        hash,
        tree,
    })
}
