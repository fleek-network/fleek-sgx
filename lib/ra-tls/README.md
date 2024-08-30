# Rust RA-TLS

Remote attestation TLS implemented in pure rust.

## Implementation details

- Uses RDRAND cpu instructions for certificate generation
- Externally provided systemtime to ensure secure time is handled in-enclave.
  (on fortanix targets, SystemTime::now() is insecure)
