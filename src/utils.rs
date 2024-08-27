use std::time::SystemTime;

use x509_cert::certificate::CertificateInner;
use x509_cert::crl::CertificateList;

pub mod u32_hex {
    use serde::Serializer;
    use zerocopy::AsBytes;

    use crate::types::UInt32LE;

    pub fn deserialize<'de, D>(deserializer: D) -> std::result::Result<UInt32LE, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value: [u8; 4] = hex::deserialize(deserializer)?;
        Ok(value.into())
    }
    pub fn serialize<S: Serializer>(value: &UInt32LE, serializer: S) -> Result<S::Ok, S::Error> {
        hex::serialize(value.as_bytes(), serializer)
    }
}

/// Deserialize and serialize certificate chains in place
pub mod cert_chain {
    use serde::{de, ser, Deserialize, Deserializer, Serializer};
    use x509_cert::certificate::CertificateInner;
    use x509_cert::der::EncodePem;
    use x509_cert::Certificate;

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
                    .to_pem(p256::pkcs8::LineEnding::LF)
                    .map_err(ser::Error::custom)?,
            )
        }
        serializer.serialize_str(&string)
    }
}

/// Deserialize and serialize a cert revocation list in place
pub mod crl {
    use std::str::FromStr;

    use pem::Pem;
    use serde::{de, ser, Deserialize, Deserializer, Serializer};
    use x509_cert::crl::CertificateList;
    use x509_cert::der::{Decode, Encode};

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

pub mod wrap_json {
    use serde::de::DeserializeOwned;
    use serde::{de, ser, Deserialize, Deserializer, Serialize, Serializer};

    pub fn deserialize<'de, D, T>(deserializer: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: DeserializeOwned,
    {
        let s = String::deserialize(deserializer)?;
        serde_json::from_str(&s).map_err(de::Error::custom)
    }
    pub fn serialize<S, T>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: Serialize,
    {
        let string = serde_json::to_string(value).map_err(ser::Error::custom)?;
        serializer.serialize_str(&string)
    }
}

pub trait Expireable {
    fn valid_at(&self, timestamp: SystemTime) -> bool;
}

impl Expireable for CertificateList {
    /// Validate CRL creation/expiration
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        if let Some(na) = self.tbs_cert_list.next_update.map(|t| t.to_system_time()) {
            if na <= timestamp {
                return false;
            }
        }

        // return false if the crl is for the future
        // TODO(oz): should this actually be the case?
        let nb = self.tbs_cert_list.this_update.to_system_time();
        if nb >= timestamp {
            return false;
        }

        true
    }
}

impl Expireable for CertificateInner {
    /// Validate a single certificate not_before/not_after
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        let nb = self.tbs_certificate.validity.not_before.to_system_time();
        let na = self.tbs_certificate.validity.not_after.to_system_time();
        !(timestamp <= nb || na <= timestamp)
    }
}

impl Expireable for &[CertificateInner] {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.iter().all(|cert| cert.valid_at(timestamp))
    }
}

impl Expireable for Vec<CertificateInner> {
    fn valid_at(&self, timestamp: SystemTime) -> bool {
        self.as_slice().valid_at(timestamp)
    }
}

// From: https://github.com/signalapp/libsignal/

/// Removes `std::mem::size_of<T>()` bytes from the front of `bytes` and returns it as a `T`.
///
/// Returns `None` and leaves `bytes` unchanged if it isn't long enough.
pub fn read_from_bytes<T: zerocopy::FromBytes>(bytes: &mut &[u8]) -> Option<T> {
    let front = T::read_from_prefix(bytes)?;
    *bytes = &bytes[std::mem::size_of::<T>()..];
    Some(front)
}

/// Removes a slice of `N` from the front of `bytes` and copies
/// it into an owned `[u8; N]`
///
/// Note: Caller must ensure the slice is large enough
pub fn read_array<const N: usize>(bytes: &mut &[u8]) -> [u8; N] {
    let mut res = [0u8; N];
    let (front, rest) = bytes.split_at(N);
    res.copy_from_slice(front);
    *bytes = rest;
    res
}

/// Removes a slice of `size` from the front of `bytes` and returns it
///
/// Note: Caller must ensure that the slice is large enough
pub fn read_bytes<'a>(bytes: &mut &'a [u8], size: usize) -> &'a [u8] {
    let (front, rest) = bytes.split_at(size);
    *bytes = rest;
    front
}
