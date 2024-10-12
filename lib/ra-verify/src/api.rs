use anyhow::{Context, Result};
use ureq::Agent;
use x509_cert::certificate::{CertificateInner, Rfc5280};
use x509_cert::crl::CertificateList;
use x509_cert::der::Decode;
use x509_cert::Certificate;

use crate::types::collateral::SgxCollateral;
use crate::types::qe_identity::QuotingEnclaveIdentityAndSignature;
use crate::types::tcb_info::TcbInfoAndSignature;

pub enum CaIdentifier {
    Processor,
    Platform,
}

impl CaIdentifier {
    fn as_str(&self) -> &str {
        match self {
            Self::Processor => "processor",
            Self::Platform => "platform",
        }
    }
}

pub fn get_collateral(
    pccs_url: &str,
    fmspc: [u8; 6],
    ca_ident: CaIdentifier,
) -> Result<SgxCollateral> {
    let agent = Agent::new();
    let root_ca_crl = get_root_ca_crl_internal(pccs_url, &agent)?;
    let (pck_crl, pck_crl_issuer_chain) = get_pck_crl_internal(pccs_url, ca_ident, &agent)?;
    let (tcb_info, tcb_info_issuer_chain) = get_tcb_internal(pccs_url, fmspc, &agent)?;
    let (qe_identity, qe_identity_issuer_chain) = get_qe_identity_internal(pccs_url, &agent)?;
    Ok(SgxCollateral {
        version: 3,
        root_ca_crl,
        pck_crl,
        tcb_info_issuer_chain,
        pck_crl_issuer_chain,
        qe_identity_issuer_chain,
        tcb_info,
        qe_identity,
    })
}

pub fn get_root_ca_crl(pccs_url: &str) -> Result<CertificateList> {
    let agent = Agent::new();
    get_root_ca_crl_internal(pccs_url, &agent)
}

fn get_root_ca_crl_internal(pccs_url: &str, agent: &Agent) -> Result<CertificateList> {
    let crl_hex = agent
        .request(
            "GET",
            &format!("https://{pccs_url}/sgx/certification/v3/rootcacrl"),
        )
        .call()?
        .into_string()?;

    let bytes = hex::decode(&crl_hex)?;
    Ok(CertificateList::from_der(&bytes)?)
}

fn get_pck_crl_internal(
    pccs_url: &str,
    ca_ident: CaIdentifier,
    agent: &Agent,
) -> Result<(CertificateList, Vec<Certificate>)> {
    let res = agent
        .request(
            "GET",
            &format!(
                "https://{pccs_url}/sgx/certification/v4/pckcrl?ca={}",
                ca_ident.as_str()
            ),
        )
        .call()?;
    let issuer_chain = res
        .header("sgx-pck-crl-issuer-chain")
        .context("Issuer chain missing from response headers")?;
    let issuer_chain_bytes = urlencoding::decode_binary(issuer_chain.as_bytes());
    let issuer_chain = CertificateInner::<Rfc5280>::load_pem_chain(&issuer_chain_bytes)?;
    let crl_hex = res.into_string()?;
    let bytes = hex::decode(&crl_hex)?;
    Ok((CertificateList::from_der(&bytes)?, issuer_chain))
}

fn get_tcb_internal(
    pccs_url: &str,
    fmspc: [u8; 6],
    agent: &Agent,
) -> Result<(TcbInfoAndSignature, Vec<Certificate>)> {
    let fmspc = base16::encode_upper(&fmspc);
    let res = agent
        .request(
            "GET",
            &format!("https://{pccs_url}/sgx/certification/v4/tcb?fmspc={fmspc}"),
        )
        .call()?;
    let issuer_chain = res
        .header("tcb-info-issuer-chain")
        .context("Issuer chain missing from response headers")?;

    let issuer_chain_bytes = urlencoding::decode_binary(issuer_chain.as_bytes());
    let issuer_chain = CertificateInner::<Rfc5280>::load_pem_chain(&issuer_chain_bytes)?;
    let tcb_info = res.into_string()?;
    let tcb_info: TcbInfoAndSignature = serde_json::from_str(&tcb_info)?;
    Ok((tcb_info, issuer_chain))
}

fn get_qe_identity_internal(
    pccs_url: &str,
    agent: &Agent,
) -> Result<(QuotingEnclaveIdentityAndSignature, Vec<Certificate>)> {
    let res = agent
        .request(
            "GET",
            &format!("https://{pccs_url}/sgx/certification/v4/qe/identity"),
        )
        .call()?;
    let issuer_chain = res
        .header("sgx-enclave-identity-issuer-chain")
        .context("Issuer chain missing from response headers")?;

    let issuer_chain_bytes = urlencoding::decode_binary(issuer_chain.as_bytes());
    let issuer_chain = CertificateInner::<Rfc5280>::load_pem_chain(&issuer_chain_bytes)?;
    let identity = res.into_string()?;
    let identity: QuotingEnclaveIdentityAndSignature = serde_json::from_str(&identity)?;
    Ok((identity, issuer_chain))
}
