use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use der::asn1::OctetString;
use der::oid::{AssociatedOid, ObjectIdentifier};
use der::Encode;
use rsa::pkcs1::EncodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::sha2::Sha256;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::ext::{AsExtension, Extension};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

// TODO(matthias): I made up this OID
pub const ATTESTATION_OID: der::asn1::ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.3.4");

pub type PrivateKey = Vec<u8>;
pub type Certificate = Vec<u8>;

#[derive(Serialize, Deserialize)]
pub struct AttestationPayload {
    pub quote: Vec<u8>,
    pub collateral: Vec<u8>,
}

struct AttestationExtension {
    data: Vec<u8>,
}

impl AssociatedOid for AttestationExtension {
    const OID: der::asn1::ObjectIdentifier = ATTESTATION_OID;
}

impl der::Encode for AttestationExtension {
    fn encoded_len(&self) -> der::Result<der::Length> {
        Ok(der::Length::new(self.data.len() as u16))
    }

    fn encode(&self, encoder: &mut impl der::Writer) -> der::Result<()> {
        encoder.write(&self.data)
    }
}

impl AsExtension for AttestationExtension {
    fn critical(&self, _subject: &x509_cert::name::Name, _extensions: &[Extension]) -> bool {
        false
    }

    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[Extension],
    ) -> std::prelude::v1::Result<Extension, der::Error> {
        Ok(Extension {
            extn_id: Self::OID,
            critical: self.critical(subject, extensions),
            extn_value: OctetString::new(self.data.clone())?,
        })
    }
}

pub fn generate_key(cert_key_bits: usize) -> Result<(RsaPrivateKey, RsaPublicKey)> {
    let mut rng = rdrand::RdRand::new()?;
    let priv_key =
        RsaPrivateKey::new(&mut rng, cert_key_bits).context("Failed to generate private key")?;
    let pub_key = RsaPublicKey::from(&priv_key);
    Ok((priv_key, pub_key))
}

pub fn generate_cert(
    priv_key: RsaPrivateKey,
    pub_key: RsaPublicKey,
    payload: AttestationPayload,
    validity_duration: Duration,
    ip_address: String,
) -> Result<(PrivateKey, Certificate)> {
    let serial_number = SerialNumber::from(1u32);
    let validity = Validity::from_now(validity_duration)?;
    let profile = Profile::Manual { issuer: None };
    let subject = Name::from_str("CN=FN SGX Service,O=Fleek Network Inc,C=US")?;
    let pub_key =
        SubjectPublicKeyInfoOwned::from_key(pub_key).context("Failed to construct public key")?;
    let sign_key: SigningKey<Sha256> = SigningKey::new(priv_key.clone());

    let mut builder = CertificateBuilder::new(
        profile,
        serial_number,
        validity,
        subject,
        pub_key,
        &sign_key,
    )
    .context("Failed to create certificate")?;

    builder.add_extension(&SubjectAltName(vec![GeneralName::IpAddress(
        OctetString::new(ip_address.as_bytes())?,
    )]))?;

    let payload_bytes =
        serde_json::to_vec(&payload).context("Failed to serialize attestation payload")?;
    let sgx_ext = AttestationExtension {
        data: payload_bytes,
    };
    builder
        .add_extension(&sgx_ext)
        .context("Failed to add attestation extension")?;

    let cert = builder.build::<_>()?;
    let cert_der = cert.to_der().context("Failed to serialize certificate")?;
    let private_key_der = priv_key
        .to_pkcs1_der()
        .context("Failed to serialize private key")?;
    Ok((private_key_der.to_bytes().to_vec(), cert_der))
}
