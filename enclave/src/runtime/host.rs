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
    use wasmi::Caller;

    use super::HostState;

    /// Alias for the ctx context
    type Ctx<'a> = Caller<'a, HostState>;

    /// Various host errors
    #[repr(i32)]
    enum HostError {
        /// Specified pointers were out of bounds
        OutOfBounds = -1,
        /// Unexpected error
        #[allow(unused)]
        Unexpected = -99,
    }

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
    /// * `<0`: Host error
    pub fn input_data_copy(mut ctx: Ctx, dst: u32, offset: u32, len: u32) -> i32 {
        let dst = dst as usize;
        let offset = offset as usize;
        let size = len as usize;

        let memory = ctx.get_export("memory").unwrap().into_memory().unwrap();
        let (memory, state) = memory.data_and_store_mut(&mut ctx);

        let Some(region) = memory.get_mut(dst..(dst + size)) else {
            return HostError::OutOfBounds as i32;
        };
        let Some(buffer) = state.input.get(offset..(offset + size)) else {
            return HostError::OutOfBounds as i32;
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
    /// * `<0`: Host error
    pub fn output_data_append(mut ctx: Ctx, ptr: u32, len: u32) -> i32 {
        let ptr = ptr as usize;
        let len = len as usize;

        let memory = ctx.get_export("memory").unwrap().into_memory().unwrap();
        let (memory, state) = memory.data_and_store_mut(&mut ctx);

        if state.output.len() > crate::config::MAX_OUTPUT_SIZE {
            return HostError::OutOfBounds as i32;
        }

        let Some(region) = memory.get(ptr..(ptr + len)) else {
            return HostError::OutOfBounds as i32;
        };

        // hash and store the data
        state.hasher.update(region);
        state.output.put_slice(region);

        0
    }
}
