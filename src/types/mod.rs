use std::sync::LazyLock;

use uuid::Uuid;
use x509_cert::der::{Any, DecodePem};
use x509_verify::spki::SubjectPublicKeyInfo;
use x509_verify::VerifyingKey;

pub mod collateral;
pub mod qe_identity;
pub mod quote;
pub mod report;
pub mod sgx_x509;
pub mod tcb_info;

/// NIST P256, secp256r1, prime256v1
pub const SECP256R1_OID_STRING: &str = "1.2.840.10045.3.1.7";

/// Intel quoting enclave vendor ID
pub const INTEL_QE_VENDOR_ID: Uuid = uuid::uuid!("939a7233-f79c-4ca9-940a-0db3957f0607");

/// Intel SGX Root Certificate Authority
pub const INTEL_ROOT_CA_PEM: &str = "\
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi71OiO
SLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlA==
-----END PUBLIC KEY-----";

/// Lazily initialized Intel SGX Root Certificate Authority
pub static INTEL_ROOT_CA: LazyLock<VerifyingKey> = LazyLock::new(|| {
    let spki = SubjectPublicKeyInfo::<Any, _>::from_pem(INTEL_ROOT_CA_PEM).unwrap();
    x509_verify::VerifyingKey::try_from(spki).unwrap()
});

pub type UInt16LE = zerocopy::little_endian::U16;
pub type UInt32LE = zerocopy::little_endian::U32;
pub type UInt64LE = zerocopy::little_endian::U64;
