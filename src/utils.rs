use std::fmt::Display;

use serde::{de, Deserialize, Deserializer};

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

// /// Deserialize and serialize a certificate in place
// pub mod cert {
//     use serde::{de, ser, Deserialize, Deserializer, Serializer};
//     use x509_cert::der::{DecodePem, EncodePem};
//     use x509_cert::Certificate;

//     pub fn deserialize<'de, D>(deserializer: D) -> Result<Certificate, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let s = <String>::deserialize(deserializer)?;
//         Certificate::from_pem(s.as_bytes()).map_err(de::Error::custom)
//     }
//     pub fn serialize<S: Serializer>(value: &Certificate, serializer: S) -> Result<S::Ok,
// S::Error> {         serializer.serialize_str(
//             &value
//                 .to_pem(p256::pkcs8::LineEnding::LF)
//                 .map_err(ser::Error::custom)?,
//         )
//     }
// }

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

/// wrapper to deserialize nested json from a string
pub fn de_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<String>,
    <T as TryFrom<String>>::Error: Display,
{
    let s = <String>::deserialize(deserializer)?;
    T::try_from(s).map_err(de::Error::custom)
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
