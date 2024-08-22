pub mod test_tls;
pub mod types;

use types::{Quote, SgxCollateral};

pub fn verify_remote_attestation(_quote: Quote, _collateral: SgxCollateral) {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK certificate.
    // 2. Verify no keys in the chain have been revoked.
    // 3. Verify the Quoting Enclave is from a suitable source and is up to date.
    // 4. Verify the status of the Intel® SGX TCB described in the chain.
    // 5. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    todo!()
}
