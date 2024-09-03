# Fleek Network SGX

## Overview

- `fleek-sgx/`
    - [`lib/`](./lib)
        - [`dcap-quoteprov/`](./lib/dcap-quoteprov): Safe DCAP Quote Provider FFI bindings (Collateral)
        - [`ra-tls/`](./lib/ra-tls): Remote attestation TLS implemented via Rustls and RustCrypto
        - [`ra-verify/`](./lib/ra-verify): Verifing remote attestations implemented via RustCrypto
    - [`enclave/`](./service/enclave): Trusted enclave for WASM TEE

## Build Requirements

Required cargo packages:
- `cargo install fortanix-sgx-tools`

Optional cargo packages:
- `cargo install sgxs-tools`

Required system packages:
- `openssl`
- `protobuf`
- `libsgx-dcap-default-qpl` OR any library providing `libdcap_quoteprov.so`
