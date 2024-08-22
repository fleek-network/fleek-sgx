use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SgxCollateral {
    /// version = 1. PCK Cert chain is in the Quote.
    pub version: u32,
    /// PCK CRL Issuer Chain in PEM format
    pub pck_crl_issuer_chain: String,
    /// Root CA CRL in PEM format
    pub root_ca_crl: String,
    /// PCK Cert CRL in PEM format
    pub pck_crl: String,
    /// TCB info issuer chain in PEM format
    pub tcb_info_issuer_chain: String,
    // TCB Info structure
    pub tcb_info: String,
    /// Identity issuer chain in PEM format
    pub qe_identity_issuer_chain: String,
    /// QE Identity Structure
    pub qe_identity: String,
    /// PCK certificate in PEM format
    pub pck_certificate: String,
    /// PCK signing chain in PEM format
    pub pck_signing_chain: String,
}

pub struct Quote {}
