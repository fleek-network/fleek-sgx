// Adapted from: https://github.com/signalapp/libsignal/

use anyhow::{anyhow, Context, Error, Result};
use p256::ecdsa::Signature;
use x509_cert::certificate::CertificateInner;
use zerocopy::{little_endian, AsBytes, FromBytes, FromZeroes};

use super::report::SgxReportBody;
use super::sgx_x509::SgxPckExtension;
use crate::utils;

/// The version of the SGX Quote (A.4.3)
const QUOTE_V3: u16 = 3;

pub struct SgxQuote<'a> {
    /// The Quote Header (A.4.3) and the Independent
    /// Software Vendor (ISV) enclave report
    pub quote_body: SgxQuoteBody,

    /// Contains signatures, the quoting enclave report, and other
    /// material for verifying `quote_body`. The "Quote Signature Data"
    /// in A.4.1
    pub support: SgxQuoteSupport<'a>,
}

impl<'a> SgxQuote<'a> {
    /// Read an SgxQuote from the `bytes`, advancing bytes
    /// by the number of bytes consumed
    pub fn read(bytes: &mut &'a [u8]) -> Result<Self> {
        if bytes.len() < std::mem::size_of::<SgxQuoteBody>() {
            return Err(anyhow!("incorrect buffer size"));
        }

        // check the version before we try to deserialize (don't advance bytes)
        let version = u16::from_le_bytes(bytes[0..2].try_into().expect("correct size"));
        if version != QUOTE_V3 {
            return Err(anyhow!("unsupported quote version"));
        }
        let quote_body = utils::read_array::<{ std::mem::size_of::<SgxQuoteBody>() }>(bytes);
        let quote_body = SgxQuoteBody::try_from(quote_body)?;

        let signature_len = utils::read_from_bytes::<little_endian::U32>(bytes)
            .ok_or_else(|| anyhow!("underflow reading signature length"))?
            .get();
        if bytes.len() < signature_len as usize {
            return Err(anyhow!("underflow reading signature"));
        }
        let support = SgxQuoteSupport::read(bytes)?;

        Ok(SgxQuote {
            quote_body,
            support,
        })
    }
}

// https://github.com/openenclave/openenclave/tree/v0.17.7
// sgx_quote.h
#[derive(Debug, FromBytes, FromZeroes, AsBytes)]
#[repr(C)]
pub struct SgxQuoteBody {
    //    /* (0) */
    //    uint16_t version;
    version: little_endian::U16,

    //    /* (2) */
    //    uint16_t sign_type;
    sign_type: little_endian::U16,

    //    /* (4) */
    //    uint8_t reserved[4];
    reserved: [u8; 4],

    //    /* (8) */
    //    uint16_t qe_svn;
    qe_svn: little_endian::U16,

    //    /* (10) */
    //    uint16_t pce_svn;
    pce_svn: little_endian::U16,

    //    /* (12) */
    //    uint8_t uuid[16];
    pub qe_vendor_id: [u8; 16],

    //    /* (28) */
    //    uint8_t user_data[20];
    user_data: [u8; 20],

    //    /* (48) */
    //    sgx_report_body_t report_body;
    pub report_body: SgxReportBody,
    //    /* (432) */
}

#[derive(Debug)]
enum SgxAttestationAlgorithm {
    _EPID = 0,
    _Reserved,
    EcdsaP256,
    _EcdsaP384,
}

impl TryFrom<[u8; std::mem::size_of::<SgxQuoteBody>()]> for SgxQuoteBody {
    type Error = Error;

    fn try_from(bytes: [u8; std::mem::size_of::<SgxQuoteBody>()]) -> Result<Self> {
        let quote_body =
            <Self as zerocopy::FromBytes>::read_from(&bytes).expect("size was already checked");
        if quote_body.version.get() != QUOTE_V3 {
            return Err(anyhow!(format!(
                "unsupported SGX quote version: {}",
                quote_body.version.get(),
            )));
        }
        // the type of the attestation signing key - we only speak ECDSA-256-with-P-256 curve
        if quote_body.sign_type.get() != SgxAttestationAlgorithm::EcdsaP256 as u16 {
            return Err(anyhow!(format!(
                "unsupported SGX attestation algorithm: {}",
                quote_body.sign_type.get(),
            )));
        }

        Ok(quote_body)
    }
}

/// In the intel docs, this is A4.4: "ECDSA 256-bit Quote Signature Data Structure"
///
/// This can be used to validate that the quoting enclave itself is valid, and then that
/// the quoting enclave has signed the ISV enclave report
pub struct SgxQuoteSupport<'a> {
    /// signature of the report header + report (SgxQuoteBody) by the attest key
    pub isv_signature: Signature,
    /// The public key used to generate isv_signature
    pub attest_pub_key: [u8; 64],
    /// report of the quoting enclave (QE)
    pub qe_report_body: SgxReportBody,
    /// signature of the quoting enclave report using the PCK cert key
    pub qe_report_signature: Signature,
    /// sha256(attest pub key + auth_data) should match QE report data
    pub auth_data: &'a [u8],
    /// the certificate chain for the pck signer
    pub pck_cert_chain: Vec<CertificateInner>,
    /// custom SGX extension that should be present on the pck signer cert
    pub pck_extension: SgxPckExtension,
}

impl<'a> SgxQuoteSupport<'a> {
    pub fn read(src: &mut &'a [u8]) -> Result<Self> {
        let header: SgxEcdsaSignatureHeader =
            utils::read_from_bytes(src).ok_or_else(|| anyhow!("incorrect buffer size"))?;

        if src.len() < header.auth_data_size.get() as usize {
            return Err(anyhow!("buffer underflow"));
        }
        let auth_data = utils::read_bytes(src, header.auth_data_size.get() as usize);
        let (cert_key_type, cert_data_size) = utils::read_from_bytes::<little_endian::U16>(src)
            .zip(utils::read_from_bytes::<little_endian::U32>(src))
            .ok_or_else(|| anyhow!("buffer underflow"))?;

        if cert_key_type.get() != CertificationKeyType::PckCertChain as u16 {
            return Err(anyhow!("unsupported certification key type"));
        }
        let cert_data_size = cert_data_size.get() as usize;

        if src.len() < cert_data_size {
            return Err(anyhow!("remaining data does not match expected size"));
        }
        let pck_cert_chain = utils::read_bytes(src, cert_data_size);
        // strip zero byte
        let pck_cert_chain = pck_cert_chain.strip_suffix(&[0]).unwrap_or(pck_cert_chain);
        let pck_cert_chain =
            CertificateInner::load_pem_chain(pck_cert_chain).context("CertChain")?;

        // deserialize the custom intel sgx extension on the pck certificate
        // find the extension on the pck_cert that has the sgx ext OID

        let pck_ext = pck_cert_chain
            .first()
            .context("CertChain")?
            .tbs_certificate
            .extensions
            .as_ref()
            .and_then(|extensions| {
                extensions
                    .iter()
                    .find(|ext| SgxPckExtension::is_pck_ext(ext.extn_id.to_string().clone()))
            })
            .ok_or_else(|| anyhow!("PCK certificate is missing SGX extension"))?;

        let pck_extension =
            SgxPckExtension::from_der(pck_ext.extn_value.as_bytes()).context("SgxPckExtension")?;

        let signature = SgxQuoteSupport {
            isv_signature: Signature::from_slice(&header.signature).context("isv_signature")?,
            attest_pub_key: header.attest_pub_key,
            qe_report_body: header.qe_report_body,
            qe_report_signature: Signature::from_slice(&header.qe_report_signature)
                .context("qe_report_signature")?,
            auth_data,
            pck_cert_chain,
            pck_extension,
        };

        Ok(signature)
    }
}

#[derive(Debug, zerocopy::FromBytes, zerocopy::FromZeroes)]
#[repr(C)]
struct SgxEcdsaSignatureHeader {
    signature: [u8; 64],
    attest_pub_key: [u8; 64],
    qe_report_body: SgxReportBody,
    qe_report_signature: [u8; 64],
    auth_data_size: little_endian::U16,
}

#[derive(Debug, PartialEq)]
enum CertificationKeyType {
    _PpidCleartext = 1,
    _PpidRsa2048Encrypted,
    _PpidRsa3072Encrypted,
    _PckCleartext,
    PckCertChain,
    _EcdsaSigAuxData,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_quote_success() {
        let our_evidence_bytes = include_bytes!("../../data/quote.bin").to_vec();
        let mut our_evidence_bytes_slice: &[u8] = &our_evidence_bytes;
        let _quote = SgxQuote::read(&mut our_evidence_bytes_slice).unwrap();
    }
}
