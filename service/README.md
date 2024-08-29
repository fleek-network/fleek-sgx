# Fleek Network SGX Service

## Architecture

The service is divided into 2 parts:

### Runner / Untrusted Userspace

The main service binary acts as a runner which handles:
- starting the enclave
- feeding it requests through a special address `requests`
- exposing blockstore server

### Enclave / Trusted Execution Environment

The enclave is embedded into the service at compile time, which is loaded on startup and run via SGX.
TCP streams are used to connect to the service ipc for accessing node functionality, as well as requesting
file reads from the blockstore. Any information acquired outside the enclave must be regarded as untrusted,
and must have a way to verify the data. For example, client requests will include a signature, and wasm content
will always be read over verified blake3 streams, just like the node to node blockstore server.

#### Keysharing protocol

Nodes will establish and distribute a shared secret key over encrypted RA-TLS channels. This is used to provide
a public key any user of the network can use to encrypt data for any node's enclave. Specifically, users will encrypt
using ECIES (secp256k1/aes-gcm).

Nodes will connect to eachother over the in-house RA-TLS implementation, which proves an ephemeral public key
came from a node and can be used for an encrypted and verified TLS session.

Enclaves are presented the list of other peers to attempt on startup. This does not need to be verified as the
enclave will only connect after the RA has been verified.

#### Client-side Verification

Clients can verify any runtime output via the ecies public key. For those that want the extra verification,
a raw remote attestation can be generated which will prove an ephemeral key that signs off on the shared public key.
