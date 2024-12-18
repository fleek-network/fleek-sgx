use std::time::SystemTime;

use anyhow::{anyhow, Context};
use der::oid::ObjectIdentifier;
use der::referenced::OwnedToRef;
use der::{Decode, Encode, SliceReader};
use ra_verify::types::collateral::SgxCollateral;
use ra_verify::types::quote::SgxQuote;
use ra_verify::types::report::MREnclave;
use ra_verify::verify_remote_attestation;
use rsa::pkcs1::RsaPssParams;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{
    crypto,
    CertificateError,
    DigitallySignedStruct,
    DistinguishedName,
    Error,
    SignatureScheme,
};
use sha2::{Digest, Sha384};
use x509_cert::certificate::{CertificateInner, Rfc5280};
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::ext::pkix::SubjectAltName;
use x509_cert::spki::AlgorithmIdentifierOwned;

use crate::cert::{AttestationPayload, ATTESTATION_OID};
use crate::collateral_prov::CollateralProvider;

const SAN_OID: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");

pub struct RemoteAttestationVerifier<C>
where
    C: CollateralProvider,
{
    mr_enclave: MREnclave,
    collateral_provider: C,
}

impl<C> RemoteAttestationVerifier<C>
where
    C: CollateralProvider + 'static,
{
    pub fn new(mr_enclave: MREnclave, collateral_provider: C) -> Self {
        Self {
            mr_enclave,
            collateral_provider,
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls_rustcrypto::provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls_rustcrypto::provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
        ]
    }
}

impl<C> std::fmt::Debug for RemoteAttestationVerifier<C>
where
    C: CollateralProvider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RemoteAttestationVerifier")
    }
}

impl<C> ServerCertVerifier for RemoteAttestationVerifier<C>
where
    C: CollateralProvider + Send + Sync + 'static,
{
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        verify_with_remote_attestation(
            &self.mr_enclave,
            &self.collateral_provider,
            end_entity,
            intermediates,
        )
        .map_err(|e| Error::General(format!("Failed to attest: {e:?}")))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_verify_schemes()
    }
}

fn verify_with_remote_attestation<C>(
    mr_enclave: &MREnclave,
    collateral_provider: &C,
    end_entity: &CertificateDer<'_>,
    intermediates: &[CertificateDer<'_>],
) -> anyhow::Result<()>
where
    C: CollateralProvider + Send + Sync + 'static,
{
    if !intermediates.is_empty() {
        return Err(anyhow!("ra-tls requires exactly one certificate"));
    }

    let x509 = CertificateInner::<Rfc5280>::from_der(end_entity.as_ref())
        .map_err(|_| Error::InvalidCertificate(CertificateError::BadEncoding))?;

    verify_cert_signature(&x509, &x509).context("Failed to verify certificate signature")?;

    let pub_key = x509
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key;

    let mut san_ext_exists = false;
    let mut attestation_ext_exists = false;
    for ext in x509
        .tbs_certificate
        .extensions
        .context("Extensions are missing from cert")?
    {
        match &ext.extn_id {
            oid if &SAN_OID == oid => {
                let val = &ext.extn_value;
                let mut reader = SliceReader::new(val.as_bytes())?;

                for name in SubjectAltName::decode(&mut reader)?.0 {
                    if let GeneralName::IpAddress(bytes) = name {
                        let _ip_address = String::from_utf8(bytes.into_bytes())?;
                        // TODO(matthias): verify IP address?
                    }
                }
                san_ext_exists = true;
            },
            oid if &ATTESTATION_OID == oid => {
                let payload: AttestationPayload = serde_json::from_slice(ext.extn_value.as_bytes())
                    .context("Failed to deserialize attestation payload")?;

                let mut quote_bytes: &[u8] = &payload.quote;
                let collat_bytes = collateral_provider.get_collateral(payload.quote.clone())?;
                let collateral: SgxCollateral = serde_json::from_slice(&collat_bytes)
                    .context("Failed to deserialize SGX collateral")?;
                let quote =
                    SgxQuote::read(&mut quote_bytes).context("Failed to deserialize SGX quote")?;

                let mut hasher = sha2::Sha256::new();
                hasher.update(
                    pub_key
                        .as_bytes()
                        .context("Public key is missing from cert")?,
                );
                let pk_hash = hasher.finalize();
                let pk_hash_bytes = pk_hash.into_iter().collect::<Vec<_>>();

                if pk_hash_bytes != quote.quote_body.report_body.sgx_report_data_bytes[..32] {
                    return Err(anyhow!(
                        "Public key hash in report data doesn't match cert public key hash"
                    ));
                }

                if let Err(e) = verify_remote_attestation(
                    // TODO(matthias): can we use system time here?
                    SystemTime::now(),
                    collateral,
                    quote,
                    mr_enclave,
                ) {
                    return Err(anyhow!("Failed to attest: {e:?}"));
                }
                attestation_ext_exists = true;
            },
            oid => {
                return Err(anyhow!("Unknown OID found in x509 extension: {oid:?}"));
            },
        }
    }
    if !san_ext_exists {
        return Err(anyhow!("SAN extension is missing from certificate"));
    }
    if !attestation_ext_exists {
        return Err(anyhow!("Attestation extension missing from certificate"));
    }
    Ok(())
}

impl<C> ClientCertVerifier for RemoteAttestationVerifier<C>
where
    C: CollateralProvider + Send + Sync + 'static,
{
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        verify_with_remote_attestation(
            &self.mr_enclave,
            &self.collateral_provider,
            end_entity,
            intermediates,
        )
        .map_err(|e| Error::General(format!("Failed to attest: {e:?}")))?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        self.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_verify_schemes()
    }
}

fn verify_signature(
    cert: &CertificateInner,
    signed_data: &[u8],
    signature: &[u8],
    algo: &AlgorithmIdentifierOwned,
) -> anyhow::Result<()> {
    let spki = cert.tbs_certificate.subject_public_key_info.owned_to_ref();

    const SHA_1_WITH_RSA_ENCRYPTION: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    const ID_RSASSA_PSS: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.10");
    const ID_SHA_256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
    const ID_SHA_384: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.2");
    const ECDSA_WITH_SHA_256: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
    const ECDSA_WITH_SHA_384: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.3");

    match algo.oid {
        SHA_1_WITH_RSA_ENCRYPTION => {
            rsa::pkcs1v15::VerifyingKey::<Sha256>::new(RsaPublicKey::try_from(spki)?)
                .verify(signed_data, &signature.try_into()?)?;
        },
        ID_RSASSA_PSS => {
            let params = algo
                .parameters
                .as_ref()
                .context("Empty PSS parameters")?
                .decode_as::<RsaPssParams>()?;

            match params.hash.oid {
                ID_SHA_256 => rsa::pss::VerifyingKey::<Sha256>::new(RsaPublicKey::try_from(spki)?)
                    .verify(signed_data, &signature.try_into()?)?,
                ID_SHA_384 => rsa::pss::VerifyingKey::<Sha384>::new(RsaPublicKey::try_from(spki)?)
                    .verify(signed_data, &signature.try_into()?)?,
                _ => return Err(anyhow!("Unknown PSS hash algorithm {}", params.hash.oid)),
            }
        },
        ECDSA_WITH_SHA_256 => {
            let signature = p256::ecdsa::DerSignature::try_from(signature)?;
            p256::ecdsa::VerifyingKey::try_from(spki)?.verify(signed_data, &signature)?;
        },
        ECDSA_WITH_SHA_384 => {
            let signature = p384::ecdsa::DerSignature::try_from(signature)?;
            p384::ecdsa::VerifyingKey::try_from(spki)?.verify(signed_data, &signature)?;
        },
        _ => {
            return Err(anyhow!(
                "Unknown signature algorithm {}",
                cert.tbs_certificate.signature.oid
            ));
        },
    }
    Ok(())
}

fn verify_cert_signature(cert: &CertificateInner, signed: &CertificateInner) -> anyhow::Result<()> {
    if cert.tbs_certificate.subject != signed.tbs_certificate.issuer {
        return Err(anyhow!("Certificate issuer does not match"));
    }

    let signed_data = signed.tbs_certificate.to_der()?;
    let signature = signed
        .signature
        .as_bytes()
        .context("Certificate signature is missing")?;

    verify_signature(cert, &signed_data, signature, &signed.signature_algorithm)
}
