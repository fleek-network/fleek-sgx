use serde::{Deserialize, Serialize};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;

use super::tcb_info::TcbInfoAndSignature;
use crate::utils::{cert_chain, crl, de_from_str};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SgxCollateral {
    /// version = 1.
    pub version: u32,

    /* Certficate revokation lists */
    /// Root CA CRL in PEM format
    #[serde(with = "crl")]
    pub root_ca_crl: CertificateList,
    /// PCK Cert CRL in PEM format
    #[serde(with = "crl")]
    pub pck_crl: CertificateList,

    /* Issuer certificate chains */
    /// TCB info issuer chain in PEM format
    #[serde(with = "cert_chain")]
    pub tcb_info_issuer_chain: Vec<Certificate>,
    /// PCK CRL Issuer Chain in PEM format
    #[serde(with = "cert_chain")]
    pub pck_crl_issuer_chain: Vec<Certificate>,
    /// Identity issuer chain in PEM format
    #[serde(with = "cert_chain")]
    pub qe_identity_issuer_chain: Vec<Certificate>,

    /* Structured data */
    /// TCB Info structure
    #[serde(deserialize_with = "de_from_str")]
    pub tcb_info: TcbInfoAndSignature,
    /// QE Identity Structure
    pub qe_identity: String,
}

#[cfg(test)]
mod tests {
    use crate::SgxCollateral;

    #[test]
    fn parse_collateral_success() {
        let json = include_str!("../../data/full_collaterall.json");
        let collat: SgxCollateral = serde_json::from_str(json).expect("json to parse");
        println!("{}", serde_json::to_string_pretty(&collat).unwrap());
    }
}
