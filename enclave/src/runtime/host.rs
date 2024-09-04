use blake3_tree::blake3::tree::{HashTree, HashTreeBuilder};
use bytes::{Bytes, BytesMut};

/// Runtime host state
pub struct HostState {
    input: Bytes,
    output: BytesMut,
    hasher: HashTreeBuilder,
}

impl HostState {
    pub fn new(input: Bytes) -> Self {
        Self {
            input,
            output: BytesMut::new(),
            hasher: HashTreeBuilder::new(),
        }
    }

    pub fn finalize(self) -> (HashTree, Bytes) {
        (self.hasher.finalize(), self.output.freeze())
    }
}

macro_rules! impl_define {
    [ $( $module:tt::$name:tt ),+ ] => {
        /// Define a set of host functions on a given linker and store
        pub fn define(
            store: &mut wasmi::Store<HostState>,
            linker: &mut wasmi::Linker<HostState>
        ) -> Result<(), wasmi::errors::LinkerError> {
            use std::borrow::BorrowMut;
            linker$(.define(
                stringify!($module), stringify!($name),
                wasmi::Func::wrap(store.borrow_mut(), $module::$name),
            )?)+;
            Ok(())
        }
    };
}

impl_define![
    fn0::input_data_size,
    fn0::input_data_copy,
    fn0::output_data_append
];

/// V0 Runtime APIs
pub mod fn0 {
    use bytes::BufMut;
    use wasmi::{AsContextMut, Caller, Extern};

    use super::HostState;

    /// Alias for the caller context
    type Ctx<'a> = Caller<'a, HostState>;

    /// Gets the size of the input data. For use with [`fn0.input_data_copy`](input_data_copy).
    ///
    /// # Returns
    ///
    /// Length of the input data slice.
    pub fn input_data_size(ctx: Ctx) -> u32 {
        ctx.data().input.len() as u32
    }

    /// Copies data from the input into a memory location. Use
    /// [`fn0.input_data_size`](input_data_size) to get the length.
    ///
    /// # Parameters
    ///
    /// * `dst`: memory offset to copy data to
    /// * `offset`: offset of input data to copy from
    /// * `len`: length of input data to copy
    ///
    /// # Returns
    ///
    /// * ` 0`: success
    /// * `-1`: memory not found
    /// * `-2`: out of bounds
    /// * `-3`: unexpected error
    pub fn input_data_copy(mut ctx: Ctx, dst: u32, offset: u32, len: u32) -> i32 {
        let dst = dst as usize;
        let offset = offset as usize;
        let size = len as usize;

        // TODO: perform this validation ahead of time when loading the wasm, before calling main
        let Some(Extern::Memory(memory)) = ctx.get_export("memory") else {
            return -1;
        };

        let ctx = ctx.as_context_mut();
        let (memory, state) = memory.data_and_store_mut(ctx);

        let Some(region) = memory.get_mut(dst..(dst + size)) else {
            return -2;
        };
        let Some(buffer) = state.input.get(offset..(offset + size)) else {
            return -2;
        };

        region.copy_from_slice(buffer);

        0
    }

    /// Copy some bytes from memory and append them into the output buffer.
    ///
    /// # Parameters
    ///
    /// * `ptr`: memory offset to copy data from
    /// * `len`: length of data to copy
    ///
    /// # Returns
    ///
    /// * ` 0`: success
    /// * `-1`: memory not found
    /// * `-2`: out of bounds
    /// * `-3`: unexpected error
    pub fn output_data_append(mut caller: Ctx, ptr: u32, len: u32) -> i32 {
        let ptr = ptr as usize;
        let len = len as usize;

        // TODO: perform this validation ahead of time when loading the wasm, before calling main
        let Some(Extern::Memory(memory)) = caller.get_export("memory") else {
            return -1;
        };

        let ctx = caller.as_context_mut();
        let (memory, state) = memory.data_and_store_mut(ctx);

        if state.output.len() > crate::config::MAX_OUTPUT_SIZE {
            return -2;
        }

        let Some(region) = memory.get(ptr..(ptr + len)) else {
            return -2;
        };

        // hash and store the data
        state.hasher.update(region);
        state.output.put_slice(region);

        0
    }
}
