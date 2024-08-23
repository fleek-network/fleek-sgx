use std::fmt::Display;
use std::sync::LazyLock;

use anyhow::{bail, Context};
use chrono::Utc;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::VerifyingKey;
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use x509_cert::der::{Any, DecodePem};
use x509_cert::Certificate;

pub const SECP256R1_OID_STRING: &str = "1.2.840.10045.3.1.7";

/// Intel SGX Root Certificate Authority
pub const INTEL_ROOT_CA_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO
SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==
-----END PUBLIC KEY-----";

/// Lazily initialized Intel SGX Root Certificate Authority
pub static INTEL_ROOT_CA: LazyLock<x509_verify::VerifyingKey> = LazyLock::new(|| {
    let spki =
        x509_verify::spki::SubjectPublicKeyInfo::<Any, _>::from_pem(INTEL_ROOT_CA_PEM).unwrap();
    x509_verify::VerifyingKey::try_from(spki).unwrap()
});

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SgxCollateral {
    /// version = 1. PCK Cert chain is in the Quote.
    pub version: u32,
    /// PCK CRL Issuer Chain in PEM format
    #[serde(with = "de_cert_chain")]
    pub pck_crl_issuer_chain: Vec<Certificate>,
    /// Root CA CRL in PEM format
    pub root_ca_crl: String,
    /// PCK Cert CRL in PEM format
    pub pck_crl: String,
    /// TCB info issuer chain in PEM format
    #[serde(with = "de_cert_chain")]
    pub tcb_info_issuer_chain: Vec<Certificate>,
    // TCB Info structure
    #[serde(deserialize_with = "de_from_str")]
    pub tcb_info: TcbInfoAndSignature,
    /// Identity issuer chain in PEM format
    #[serde(with = "de_cert_chain")]
    pub qe_identity_issuer_chain: Vec<Certificate>,
    /// QE Identity Structure
    pub qe_identity: String,
    /// PCK certificate in PEM format
    pub pck_certificate: String,
    /// PCK signing chain in PEM format
    #[serde(with = "de_cert_chain")]
    pub pck_signing_chain: Vec<Certificate>,
}

/// Deserialize certificate chains in place
mod de_cert_chain {
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

fn de_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<String>,
    <T as TryFrom<String>>::Error: Display,
{
    let s = <String>::deserialize(deserializer)?;
    T::try_from(s).map_err(de::Error::custom)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TcbInfoAndSignature {
    #[serde(rename = "tcbInfo")]
    tcb_info_raw: Box<RawValue>,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl TryFrom<String> for TcbInfoAndSignature {
    type Error = serde_json::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

impl TcbInfoAndSignature {
    pub fn as_tcb_info_and_verify(&self, public_key: VerifyingKey) -> anyhow::Result<TcbInfo> {
        let sig = p256::ecdsa::Signature::from_slice(&self.signature).unwrap();
        public_key
            .verify(self.tcb_info_raw.get().as_bytes(), &sig)
            .expect("valid signature, bitch");

        let tcb_info: TcbInfo =
            serde_json::from_str(self.tcb_info_raw.get()).context("tcb info")?;

        if tcb_info
            .tcb_levels
            .iter()
            .any(|e| e.tcb.version() != tcb_info.version)
        {
            bail!(
                "mismatched tcb info versions, should all be {:?}",
                tcb_info.version,
            );
        }

        // tcb_type determines how to compare tcb level
        // currently, only 0 is valid
        if tcb_info.tcb_type != 0 {
            bail!("unsupported tcb type {}", tcb_info.tcb_type,);
        }
        Ok(tcb_info)
    }
}

/// Version of the TcbInfo JSON structure
///
/// In the PCS V3 API the TcbInfo version is V2, in the PCS V4 API the TcbInfo
/// version is V3. The V3 API includes advisoryIDs and changes the format of
/// the TcbLevel

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(try_from = "u16")]
pub(crate) enum TcbInfoVersion {
    V2 = 2,
    V3 = 3,
}

impl TryFrom<u16> for TcbInfoVersion {
    type Error = &'static str;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(TcbInfoVersion::V2),
            3 => Ok(TcbInfoVersion::V3),
            _ => Err("Unsupported TCB Info version"),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbInfo {
    version: TcbInfoVersion,
    _issue_date: chrono::DateTime<Utc>,
    pub next_update: chrono::DateTime<Utc>,
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],
    #[serde(with = "hex")]
    pub pce_id: [u8; 2],
    tcb_type: u16,
    _tcb_evaluation_data_number: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: String,
    #[serde(rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize, Serialize)]
pub enum TcbStatus {
    UpToDate,
    OutOfDate,
    ConfigurationNeeded,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDateConfigurationNeeded,
    Revoked,
}

/// Contains information identifying a TcbLevel.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(untagged)]
pub enum Tcb {
    V2(TcbV2),
    V3(TcbV3),
}

impl Tcb {
    fn version(&self) -> TcbInfoVersion {
        match self {
            Tcb::V2(_) => TcbInfoVersion::V2,
            Tcb::V3(_) => TcbInfoVersion::V3,
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbV3 {
    sgxtcbcomponents: [TcbComponentV3; 16],
    pcesvn: u16,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, Copy)]
pub struct TcbComponentV3 {
    svn: u8,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub struct TcbV2 {
    sgxtcbcomp01svn: u8,
    sgxtcbcomp02svn: u8,
    sgxtcbcomp03svn: u8,
    sgxtcbcomp04svn: u8,
    sgxtcbcomp05svn: u8,
    sgxtcbcomp06svn: u8,
    sgxtcbcomp07svn: u8,
    sgxtcbcomp08svn: u8,
    sgxtcbcomp09svn: u8,
    sgxtcbcomp10svn: u8,
    sgxtcbcomp11svn: u8,
    sgxtcbcomp12svn: u8,
    sgxtcbcomp13svn: u8,
    sgxtcbcomp14svn: u8,
    sgxtcbcomp15svn: u8,
    sgxtcbcomp16svn: u8,
    pcesvn: u16,
}

impl Tcb {
    pub fn pcesvn(&self) -> u16 {
        match self {
            Self::V2(v2) => v2.pcesvn,
            Self::V3(v3) => v3.pcesvn,
        }
    }

    pub fn components(&self) -> [u8; 16] {
        match self {
            Self::V2(v2) => [
                v2.sgxtcbcomp01svn,
                v2.sgxtcbcomp02svn,
                v2.sgxtcbcomp03svn,
                v2.sgxtcbcomp04svn,
                v2.sgxtcbcomp05svn,
                v2.sgxtcbcomp06svn,
                v2.sgxtcbcomp07svn,
                v2.sgxtcbcomp08svn,
                v2.sgxtcbcomp09svn,
                v2.sgxtcbcomp10svn,
                v2.sgxtcbcomp11svn,
                v2.sgxtcbcomp12svn,
                v2.sgxtcbcomp13svn,
                v2.sgxtcbcomp14svn,
                v2.sgxtcbcomp15svn,
                v2.sgxtcbcomp16svn,
            ],
            Self::V3(v3) => v3.sgxtcbcomponents.map(|comp| comp.svn),
        }
    }
}

#[cfg(test)]
#[test]
fn test_parse_sgx_collateral() {
    let json = include_str!("../data/full_collaterall.json");
    let collat: SgxCollateral = serde_json::from_str(json).expect("json to parse");
    println!("{}", serde_json::to_string_pretty(&collat).unwrap());
}

pub struct Quote {}
