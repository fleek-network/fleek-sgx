use serde::{de, Deserialize, Deserializer, Serialize};
use x509_cert::crl::CertificateList;
use x509_cert::Certificate;

use super::qe_identity::QuotingEnclaveIdentityAndSignature;
use super::tcb_info::TcbInfoAndSignature;
use crate::utils::{cert_chain, crl};

#[derive(Debug, Serialize, Deserialize)]
pub struct SgxCollateral {
    /// Version = 3.
    /// Not necessarily a representative of this type, but of all inner values.
    /// For example, a RA-TLS implementation might assemble this struct manually
    /// from certificate extensions.
    #[serde(deserialize_with = "de_require_version_3")]
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
    pub tcb_info: TcbInfoAndSignature,
    /// QE Identity Structure
    pub qe_identity: QuotingEnclaveIdentityAndSignature,
}

/// Deserialize a version tag, requiring the version to be 3
pub fn de_require_version_3<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let version = u32::deserialize(deserializer)?;
    (version == 3)
        .then_some(version)
        .ok_or(de::Error::custom("version must be 3"))
}

#[cfg(test)]
mod tests {
    use crate::SgxCollateral;

    #[test]
    fn encode_decode_collateral_json() {
        let json = include_str!("../../data/full_collateral.json");
        let collat: SgxCollateral = serde_json::from_str(json).expect("json to parse");
        let json2 = serde_json::to_string(&collat).expect("json to serialize");
        println!("{json2}");
        let _: SgxCollateral = serde_json::from_str(&json2).expect("json2 to parse");
    }
}
