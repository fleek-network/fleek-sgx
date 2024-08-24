use std::fmt::Display;

use serde::{de, Deserialize, Deserializer, Serialize};
use x509_cert::crl::CertificateList;
use x509_cert::der::DecodePem;
use x509_cert::Certificate;

use super::tcb_info::TcbInfoAndSignature;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SgxCollateral {
    /// version = 1.
    pub version: u32,

    /// Root CA CRL in PEM format
    #[serde(with = "crl")]
    pub root_ca_crl: CertificateList,
    /// PCK Cert CRL in PEM format
    #[serde(with = "crl")]
    pub pck_crl: CertificateList,

    /// TCB info issuer chain in PEM format
    #[serde(with = "cert_chain")]
    pub tcb_info_issuer_chain: Vec<Certificate>,
    /// PCK CRL Issuer Chain in PEM format
    #[serde(with = "cert_chain")]
    pub pck_crl_issuer_chain: Vec<Certificate>,
    /// Identity issuer chain in PEM format
    #[serde(with = "cert_chain")]
    pub qe_identity_issuer_chain: Vec<Certificate>,

    // TCB Info structure
    #[serde(deserialize_with = "de_from_str")]
    pub tcb_info: TcbInfoAndSignature,
    /// QE Identity Structure
    pub qe_identity: String,

    /* TODO: remove these, they should be gotten from the quote */
    /// PCK signing chain in PEM format
    #[serde(with = "cert_chain")]
    pub pck_signing_chain: Vec<Certificate>,
    /// PCK certificate in PEM format
    #[serde(with = "cert")]
    pub pck_certificate: Certificate,
}

/// Deserialize and serialize certificate chains in place
mod cert_chain {
    use serde::Serializer;
    use x509_cert::certificate::CertificateInner;
    use x509_cert::der::EncodePem;

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<CertificateInner>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        Certificate::load_pem_chain(s.as_bytes()).map_err(de::Error::custom)
    }
    pub fn serialize<S: Serializer>(
        value: &Vec<CertificateInner>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let mut string = String::new();
        for cert in value {
            string.push_str(
                &cert
                    .to_pem(p256::pkcs8::LineEnding::CRLF)
                    .map_err(serde::ser::Error::custom)?,
            )
        }
        serializer.serialize_str(&string)
    }
}

/// Deserialize and serialize a certificate in place
mod cert {
    use serde::{ser, Serializer};
    use x509_cert::der::EncodePem;

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Certificate, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        Certificate::from_pem(s.as_bytes()).map_err(de::Error::custom)
    }
    pub fn serialize<S: Serializer>(value: &Certificate, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(
            &value
                .to_pem(p256::pkcs8::LineEnding::LF)
                .map_err(ser::Error::custom)?,
        )
    }
}

/// Deserialize and serialize a cert revocation list in place
mod crl {
    use std::str::FromStr;

    use pem::Pem;
    use serde::{ser, Serializer};
    use x509_cert::der::{Decode, Encode};

    use super::*;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<CertificateList, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String>::deserialize(deserializer)?;
        let pem = Pem::from_str(&s).map_err(de::Error::custom)?;
        CertificateList::from_der(pem.contents()).map_err(de::Error::custom)
    }
    pub fn serialize<S: Serializer>(
        value: &CertificateList,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let pem = Pem::new("X509 CRL", value.to_der().map_err(ser::Error::custom)?);
        serializer.serialize_str(&pem.to_string())
    }
}

/// wrapper to deserialize nested json from a string
fn de_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<String>,
    <T as TryFrom<String>>::Error: Display,
{
    let s = <String>::deserialize(deserializer)?;
    T::try_from(s).map_err(de::Error::custom)
}

#[cfg(test)]
#[test]
fn test_parse_sgx_collateral() {
    let json = include_str!("../../data/full_collaterall.json");
    let collat: SgxCollateral = serde_json::from_str(json).expect("json to parse");
    println!("{}", serde_json::to_string_pretty(&collat).unwrap());
}

pub struct Quote {}
