use arrayvec::ArrayString;
use std::fmt::Debug;

/// Used internally as a helper to pretty print hashes as hex strings.
pub struct Digest<'d>(pub &'d [u8; 32]);

/// Used internally as a helper to pretty print hashes as hex strings.
pub struct OwnedDigest(pub [u8; 32]);

impl Debug for OwnedDigest {
    #[inline(always)]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", to_hex(&self.0))
    }
}

/// Convert a hash digest to a human-readable string.
#[inline]
pub fn to_hex(slice: &[u8; 32]) -> ArrayString<64> {
    let mut s = ArrayString::new();
    let table = b"0123456789abcdef";
    for &b in slice {
        s.push(table[(b >> 4) as usize] as char);
        s.push(table[(b & 0xf) as usize] as char);
    }
    s
}

/// Validates that the provided number of bytes is a valid number of bytes for a proof
/// buffer. This is only applicable to hashtree inclusion proofs.
#[inline(always)]
pub const fn is_valid_proof_len(n: usize) -> bool {
    const SEG_SIZE: usize = 32 * 8 + 1;
    // get the size of the first segment. we should either deal with a full segment (or n == 0)
    // or a valid partial segment. a valid partial segment has at least 1 item. so just a single
    // sign byte is invalid. then we keep the sign byte away `s - 1` and this should be a valid
    // set of full hashes and a multiple of 32. Also the proof must contain at least 2 hashes,
    // otherwise no merge operation can happen.
    let s = n % SEG_SIZE;
    s == 0 || (n > 64 && ((s - 1) % 32 == 0))
}

// const-fn implementation.
#[inline(always)]
pub const fn words_from_le_bytes_32(bytes: &[u8; 32]) -> [u32; 8] {
    #[inline(always)]
    const fn w(bytes: &[u8; 32], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }
    let mut out = [0; 8];
    out[0] = w(bytes, 0);
    out[1] = w(bytes, 4);
    out[2] = w(bytes, 2 * 4);
    out[3] = w(bytes, 3 * 4);
    out[4] = w(bytes, 4 * 4);
    out[5] = w(bytes, 5 * 4);
    out[6] = w(bytes, 6 * 4);
    out[7] = w(bytes, 7 * 4);
    out
}

// const-fn implementation.
#[inline(always)]
pub const fn le_bytes_from_words_32(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0; 32];
    let mut i = 0;
    let mut j = 0;
    while i < 8 {
        let bytes = words[i].to_le_bytes();
        out[j] = bytes[0];
        j += 1;
        out[j] = bytes[1];
        j += 1;
        out[j] = bytes[2];
        j += 1;
        out[j] = bytes[3];
        j += 1;
        i += 1;
    }
    out
}

/// Compute the index of the n-th leaf in the array representation of the tree.
/// see: <https://oeis.org/A005187>
#[inline(always)]
pub const fn tree_index(block_counter: usize) -> usize {
    2 * block_counter - block_counter.count_ones() as usize
}

/// The largest power of two less than or equal to `n`,.
#[inline]
pub fn largest_power_of_two_leq(n: usize) -> usize {
    ((n / 2) + 1).next_power_of_two()
}

/// Check the given byte and returns true if it can be a valid file name. This checks the validity
/// of the length and ensures that a 'null' byte is not present in the bytes.
#[inline]
pub fn is_valid_filename(bytes: &[u8]) -> bool {
    is_valid_filename_len(bytes.len()) && !bytes.iter().any(|b| *b == 0)
}

/// Check the given byte and returns true if it can be a valid content for a symbolic link.
/// This checks the validity of the length and ensures that a 'null' byte is not present in
/// the bytes.
#[inline]
pub fn is_valid_symlink(bytes: &[u8]) -> bool {
    is_valid_symlink_len(bytes.len()) && !bytes.iter().any(|b| *b == 0)
}

/// Flatten a nested slice.
///
/// From standard library, but it's unstable there so here is a copy because it's good enough
/// for us...
#[inline(always)]
pub fn flatten<const N: usize, T>(slice: &[[T; N]]) -> &[T] {
    let len = if std::mem::size_of::<T>() == 0 {
        slice.len().checked_mul(N).expect("slice len overflow")
    } else {
        // SAFETY: `self.len() * N` cannot overflow because `self` is
        // already in the address space.
        slice.len() * N
    };
    // SAFETY: `[T]` is layout-identical to `[T; N]`
    unsafe { std::slice::from_raw_parts(slice.as_ptr().cast(), len) }
}

/// Returns the previous power of two of a given number, the returned
/// value is always less than the provided `n`.
#[inline(always)]
pub const fn previous_pow_of_two(n: usize) -> usize {
    n.next_power_of_two() / 2
}

/// Returns true if the given number of bytes is valid for a file name. A file name on Unix has
/// a maximum of 255 bytes. And can not be empty.
#[inline(always)]
pub const fn is_valid_filename_len(n: usize) -> bool {
    n > 0 && n < 256
}

/// Returns true if the given number of bytes is valid for content of a symbolic link. A link
/// content may not execeed 1023 bytes.
#[inline(always)]
pub const fn is_valid_symlink_len(n: usize) -> bool {
    n > 0 && n < 1024
}
