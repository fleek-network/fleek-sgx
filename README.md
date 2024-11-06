# Fleek Network SGX

## Overview

This is the Enclave/Trusted code the Fleek SGX WASM service.
Untrusted/Runner code can be found in the lightning repo [here](https://github.com/fleek-network/lightning/tree/main/services/sgx).

- `fleek-sgx/`
    - [`lib/`](./lib)
        - [`ra-tls/`](./lib/ra-tls): Remote attestation TLS implemented via Rustls and RustCrypto
        - [`ra-verify/`](./lib/ra-verify): Verifing remote attestations implemented via RustCrypto
    - [`enclave/`](./service/enclave): Trusted enclave for WASM TEE

## Reproducable enclave

> Requires nix with flake support enabled

```sh
# Build the enclave
nix build

# Hash the result
b3sum result/enclave.sgxs
```
