// From: https://github.com/signalapp/libsignal/

/// Removes `std::mem::size_of<T>()` bytes from the front of `bytes` and returns it as a `T`.
///
/// Returns `None` and leaves `bytes` unchanged if it isn't long enough.
pub fn read_from_bytes<T: zerocopy::FromBytes>(bytes: &mut &[u8]) -> Option<T> {
    let front = T::read_from_prefix(bytes)?;
    *bytes = &bytes[std::mem::size_of::<T>()..];
    Some(front)
}

/// Removes a slice of `N` from the front of `bytes` and copies
/// it into an owned `[u8; N]`
///
/// Note: Caller must ensure the slice is large enough
pub fn read_array<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
    let mut res = [0u8; N];
    let (front, rest) = bytes.split_at(N);
    res.copy_from_slice(front);
    *bytes = rest;
    res
}

/// Removes a slice of `size` from the front of `bytes` and returns it
///
/// Note: Caller must ensure that the slice is large enough
pub fn read_bytes<'a>(bytes: &mut &'a [u8], size: usize) -> &'a [u8] {
    let (front, rest) = bytes.split_at(size);
    *bytes = rest;
    front
}
