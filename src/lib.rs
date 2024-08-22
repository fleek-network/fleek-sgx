pub mod test_tls;
pub mod types;

use types::{Quote, SgxCollateral};

pub fn verify_remote_attestation(_quote: Quote, _collateral: SgxCollateral) -> anyhow::Result<()> {
    // 1. Verify the integrity of the signature chain from the Quote to the Intel-issued PCK
    //    certificate.
    verify_integrity()?;

    // 2. Verify no keys in the chain have been revoked.
    verify_revocation()?;

    // 3. Verify the Quoting Enclave is from a suitable source and is up to date.
    verify_quote()?;

    // 4. Verify the status of the Intel® SGX TCB described in the chain.
    verify_tcb_status()?;

    // 5. Verify the enclave measurements in the Quote reflect an enclave identity expected.
    verify_enclave_measurements()?;

    Ok(())
}

fn verify_integrity(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

fn verify_revocation(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

fn verify_quote(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

fn verify_tcb_status(/* ...*/) -> anyhow::Result<()> {
    todo!()
}

fn verify_enclave_measurements(/* ...*/) -> anyhow::Result<()> {
    todo!()
}
