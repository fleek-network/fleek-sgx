use std::rc::Rc;
use std::sync::Arc;

use bip32::ChildNumber;
use blake3_tree::blake3::tree::{HashTree, HashTreeBuilder};
use bytes::{Bytes, BytesMut};

use crate::seal_key::SealKeyPair;

/// Runtime host state
pub struct HostState {
    shared: Arc<SealKeyPair>,
    hash: [u8; 32],
    input: Bytes,
    output: BytesMut,
    hasher: HashTreeBuilder,
}

impl HostState {
    pub fn new(shared: Arc<SealKeyPair>, hash: [u8; 32], input: Bytes) -> Self {
        Self {
            shared,
            hash,
            input,
            output: BytesMut::new(),
            hasher: HashTreeBuilder::new(),
        }
    }

    pub fn finalize(self) -> (HashTree, Bytes) {
        (self.hasher.finalize(), self.output.freeze())
    }

    /// Derive a wasm module specific, non-hardened, bip32 key pair from the shared extended key.
    ///
    /// Rough algorithm is as follows:
    ///
    /// ```ignore
    /// // start with shared key
    /// let derived_key = shared_key;
    ///
    /// // wasm module scope
    /// for hash_chunk_u16 in wasm_hash.chunks(2) {
    ///   derived_key = derived_key.derive_child(hash_chunk_u16 as u32, false);
    /// }
    ///
    /// // user provided path scope (<=256, even length)
    /// for path_chunk_u16 in path.chunks(2) {
    ///   derived_key = derived_key.derive_child(path_chunk_u16 as u32, false);
    /// }
    ///
    /// Ok(derived_key)
    /// ```
    pub fn derive_wasm_key(&mut self, path: &[u8]) -> anyhow::Result<Rc<SealKeyPair>> {
        // Derive child for scope
        let mut secret = self
            .shared
            .secret
            .derive_child(ChildNumber::new(0, false)?)?;

        // Derive child for wasm hash (16 iterations)
        for n in self
            .hash
            .chunks_exact(2)
            .map(|v| u16::from_be_bytes(v.try_into().unwrap()).into())
        {
            secret = secret.derive_child(ChildNumber::new(n, false).unwrap())?;
        }

        // Derive user path as chunks of unsized 16 bit integers
        for n in path
            .chunks(2)
            .map(|v| u16::from_be_bytes(v.try_into().unwrap()).into())
        {
            secret = secret.derive_child(bip32::ChildNumber::new(n, false)?)?;
        }

        let public = secret.public_key();
        Ok(Rc::new(SealKeyPair { public, secret }))
    }
}

macro_rules! impl_define {
    // impl_define![ module::foo_function, ];
    [ $( $module:tt::$name:tt ),+ $(,)? ] => {
        /// Define a set of host functions on a given linker and store
        pub fn define(
            store: &mut wasmi::Store<HostState>,
            linker: &mut wasmi::Linker<HostState>
        ) -> Result<(), wasmi::errors::LinkerError> {
            linker$(
                .define(
                    stringify!($module),
                    stringify!($name),
                    wasmi::Func::wrap(&mut *store, $module::$name),
                )?)+;
            Ok(())
        }
    };
}

impl_define![
    fn0::input_data_size,
    fn0::input_data_copy,
    fn0::output_data_append,
    fn0::output_data_clear,
    fn0::shared_key_unseal,
    fn0::derived_key_unseal,
    fn0::derived_key_sign
];

/// V0 Runtime APIs
pub mod fn0 {
    use blake3_tree::blake3::tree::HashTreeBuilder;
    use bytes::{Buf, BufMut, Bytes};
    use libsecp256k1::Signature;
    use sha2::Digest;
    use wasmi::Caller;

    use super::HostState;

    /// Alias for the ctx context
    type Ctx<'a> = Caller<'a, HostState>;

    /// Global key scope's approved wasm header prefix
    const PREFIX: &[u8] = b"FLEEK_ENCLAVE_APPROVED_WASM";

    /// Various host errors
    #[repr(i32)]
    enum HostError {
        /// Specified pointers were out of bounds
        OutOfBounds = -1,
        /// Invalid key derivation path
        KeyDerivationInvalidPath = -2,
        /// Key derivation error
        KeyDerivation = -3,
        /// Invalid permission header for shared key
        UnsealInvalidPermissionHeader = -4,
        /// Current wasm is not approved to access global content
        UnsealPermissionDenied = -5,
        /// Sealed data could not be decrypted
        UnsealFailed = -6,
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

        // SAFETY: We ensure this exists before running anything
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

        // SAFETY: We ensure this exists before running anything
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

    /// Clear output data buffer, for example to be used to write an error mid stream
    pub fn output_data_clear(mut ctx: Ctx) {
        let state = ctx.data_mut();
        state.hasher = HashTreeBuilder::new();
        state.output.clear();
    }

    /// Unseal a section of memory in-place using the shared extended key.
    ///
    /// # Handling permissions
    ///
    /// Unencrypted content must include a header with a list of approved wasm modules.
    ///
    /// This header is made up of;
    /// * a prefix b"FLEEK_ENCLAVE_APPROVED_WASM"
    /// * a u8 number of hashes to read
    /// * the approved 32 byte wasm hashes.
    ///
    /// The content itself is then everything after the header (`prefix + 1 + len * 32`).
    ///
    /// # Parameters
    ///
    /// * `cipher_ptr`: memory offset to read encrypted content from
    /// * `cipher_len`: length of encrypted content
    ///
    /// # Returns
    ///
    /// * `>0`: length of decrypted content written to `cipher_ptr`
    /// * `<0`: Host error
    pub fn shared_key_unseal(mut ctx: Ctx, cipher_ptr: u32, cipher_len: u32) -> i32 {
        let cipher_ptr = cipher_ptr as usize;
        let cipher_len = cipher_len as usize;

        // If we cant fit the length inside an i32, return an error
        if cipher_len > i32::MAX as usize {
            return HostError::OutOfBounds as i32;
        }

        let memory = ctx.get_export("memory").unwrap().into_memory().unwrap();
        let (memory, state) = memory.data_and_store_mut(&mut ctx);

        // Get buffer containing the ciphertext. We will write the plaintext into the buffer later.
        let Some(ciphertext) = memory.get_mut(cipher_ptr..cipher_ptr + cipher_len) else {
            return HostError::OutOfBounds as i32;
        };

        // Unseal the content using the global key
        let Ok(mut plaintext) = state.shared.unseal(ciphertext).map(Bytes::from) else {
            return HostError::UnsealFailed as i32;
        };

        // Parse out the permissions header from the plaintext, and ensure the current wasm
        // hash is approved.

        // Ensure we have enough bytes for the prefix, at least 1 approved hash, and at least
        // 1 byte of raw content.
        if plaintext.len() < PREFIX.len() + 1 + 32 + 1 {
            return HostError::UnsealInvalidPermissionHeader as i32;
        }
        if plaintext.split_to(PREFIX.len()) != PREFIX {
            return HostError::UnsealInvalidPermissionHeader as i32;
        }

        // Ensure decrypted content has the header hashes and at least 1 byte of raw content
        let num_hashes = plaintext.get_u8() as usize;
        if num_hashes == 0 {
            return HostError::UnsealInvalidPermissionHeader as i32;
        }
        if plaintext.len() < num_hashes * 32 + 1 {
            return HostError::UnsealInvalidPermissionHeader as i32;
        }

        // Split off and parse the approved hashes
        let hashes = plaintext
            .split_to(num_hashes * 32)
            .chunks_exact(32)
            .map(|h| h.try_into().unwrap())
            .collect::<Vec<[u8; 32]>>();

        // Ensure the current wasm module hash is included in the list of approved modules
        if !hashes.contains(&state.hash) {
            return HostError::UnsealPermissionDenied as i32;
        }

        // Write over the encrypted content. Decrypted content will always be shorter than encrypted
        ciphertext[..plaintext.len()].copy_from_slice(&plaintext);

        // SAFETY: we return out of bounds earlier if the (bigger) encrypted
        //         content length will not fit inside an i32
        plaintext.len() as i32
    }

    /// Derive a wasm specific key from the shared key, with a given path up to `[u16; 128]`, and
    /// unseal encrypted data with it.
    ///
    /// # Parameters
    ///
    /// * `path_ptr`: Memory offset of key derivation path
    /// * `path_len`: Length of path, must be an even number <= 256
    /// * `cipher_ptr`: memory offset to read encrypted content from
    /// * `cipher_len`: length of encrypted content
    ///
    /// # Returns
    ///
    /// * `>0`: length of decrypted content written to `cipher_ptr`
    /// * `<0`: Host error
    pub fn derived_key_unseal(
        mut ctx: Ctx,
        path_ptr: u32,
        path_len: u32,
        cipher_ptr: u32,
        cipher_len: u32,
    ) -> i32 {
        let path_ptr = path_ptr as usize;
        let path_len = path_len as usize;
        let cipher_ptr = cipher_ptr as usize;
        let cipher_len = cipher_len as usize;

        // Error if path length is greater than 256, or odd
        if path_len > 256 || path_len % 2 != 0 {
            return HostError::KeyDerivationInvalidPath as i32;
        }

        // If we can't fit the length inside an i32, return an error
        if cipher_len > i32::MAX as usize {
            return HostError::OutOfBounds as i32;
        }

        let memory = ctx.get_export("memory").unwrap().into_memory().unwrap();
        let (memory, state) = memory.data_and_store_mut(&mut ctx);

        // Derive the key
        let Some(path) = memory.get(path_ptr..path_ptr + path_len) else {
            return HostError::OutOfBounds as i32;
        };
        let Ok(key) = state.derive_wasm_key(path) else {
            return HostError::KeyDerivation as i32;
        };

        // Get buffer containing the ciphertext. We will write the plaintext into the buffer later.
        let Some(ciphertext) = memory.get_mut(cipher_ptr..cipher_ptr + cipher_len) else {
            return HostError::OutOfBounds as i32;
        };

        // Unseal the content using the derived wasm key
        let Ok(plaintext) = key.unseal(ciphertext) else {
            return HostError::UnsealFailed as i32;
        };

        // Write over the encrypted content. Decrypted content will always be shorter than encrypted
        ciphertext[..plaintext.len()].copy_from_slice(&plaintext);

        // SAFETY: we return out of bounds earlier if the (bigger) encrypted
        //         content length will not fit inside an i32
        plaintext.len() as i32
    }

    /// Derive a wasm specific key from the shared key, with a given path up to `[u16; 128]`, and
    /// sign the sha256 hash of some data with it.
    ///
    /// # Parameters
    ///
    /// * `path_ptr`: Memory offset of key derivation path
    /// * `path_len`: Length of path, must be an even number <= 256
    /// * `data_ptr`: Memory offset of data to hash and sign
    /// * `data_len`: Length of data to hash and sign
    /// * `signature_buf_ptr`: Memory offset to write 65 byte signature to
    ///
    /// # Returns
    ///
    /// * ` 0`: Success
    /// * `<0`: Host error
    pub fn derived_key_sign(
        mut ctx: Ctx,
        path_ptr: u32,
        path_len: u32,
        data_ptr: u32,
        data_len: u32,
        signature_buf_ptr: u32,
    ) -> i32 {
        let path_ptr = path_ptr as usize;
        let path_len = path_len as usize;
        let data_ptr = data_ptr as usize;
        let data_len = data_len as usize;
        let signature_buf_ptr = signature_buf_ptr as usize;

        // Error if path length is greater than 256, or odd
        if path_len > 256 || path_len % 2 != 0 {
            return HostError::KeyDerivationInvalidPath as i32;
        }

        // SAFETY: We ensure this exists before running anything
        let memory = ctx.get_export("memory").unwrap().into_memory().unwrap();
        let (memory, state) = memory.data_and_store_mut(&mut ctx);

        // Get and hash user data to sign
        let Some(data) = memory.get(data_ptr..(data_ptr + data_len)) else {
            return HostError::OutOfBounds as i32;
        };
        let message = sha2::Sha256::digest(data).into();

        // Derive the client key
        let Some(path) = memory.get(path_ptr..path_ptr + path_len) else {
            return HostError::OutOfBounds as i32;
        };
        let Ok(key) = state.derive_wasm_key(path) else {
            return HostError::KeyDerivation as i32;
        };

        // Get output buffer to write signature into
        let Some(signature_buf) = memory.get_mut(signature_buf_ptr..signature_buf_ptr + 65) else {
            return HostError::OutOfBounds as i32;
        };

        // Sign the message
        let (Signature { r, s }, v) = libsecp256k1::sign(
            &libsecp256k1::Message::parse(&message),
            &key.secret.private_key().0,
        );

        // write signature to buffer, ethereum style
        signature_buf[0..32].copy_from_slice(&r.b32());
        signature_buf[32..64].copy_from_slice(&s.b32());
        signature_buf[64] = v.serialize();

        0
    }
}
