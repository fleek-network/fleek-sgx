# Fleek Network SGX

## Overview

- `fleek-sgx/`
    - [`lib/`](./lib)
        - [`remote-attestation/`](./lib/remote-attestation): verifing remote-attestations (pure rust)
        - [`ra-tls/`](./lib/ra-tls): rustls server and client for remote attestation auth
    - [`service/`](./service): fleek network service (runner)
        - [`enclave/`](./service/enclave): trusted enclave for wasm tee
