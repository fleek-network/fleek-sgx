//! TODO: Add trusted time verification to all certificates we verify using the TrustStore

use std::collections::{BTreeMap, BTreeSet};
use std::time::SystemTime;

use anyhow::{anyhow, bail};
use x509_cert::certificate::CertificateInner;
use x509_cert::crl::CertificateList;
use x509_verify::VerifyingKey;

use crate::utils::Expireable;

/// Trust store for verifying certificate chains
pub struct TrustStore {
    /// Trusted CAs
    pub trusted: BTreeMap<String, TrustedIdentity>,
    /// Trusted certificate revokation list
    pub crl: BTreeSet<String>,
    pub current_time: SystemTime,
}

/// Wrapper for a pre-parsed trusted identity for verification
pub struct TrustedIdentity {
    pub cert: CertificateInner,
    pub pk: VerifyingKey,
}

impl TrustStore {
    /// Create a new trust store with a list of trusted CAs.
    ///
    /// # Security implications
    ///
    /// Consumers *MUST* use a secure implementation of time.
    /// (ie, SystemTime::now() on fortanix is insecure)
    pub fn new(current_time: SystemTime, trusted: Vec<CertificateInner>) -> anyhow::Result<Self> {
        let mut map = BTreeMap::new();
        for cert in trusted {
            let pk = (&cert)
                .try_into()
                .map_err(|e| anyhow!("failed to decode key from certificate: {e}"))?;
            map.insert(
                cert.tbs_certificate.subject.to_string(),
                TrustedIdentity { pk, cert },
            );
        }

        Ok(Self {
            trusted: map,
            crl: Default::default(),
            current_time,
        })
    }

    /// Push a single trusted crl to an existing trust store
    pub fn push_trusted_crl(&mut self, crl: CertificateList) {
        if let Some(list) = crl.tbs_cert_list.revoked_certificates {
            for cert in list {
                self.crl.insert(cert.serial_number.to_string());
            }
        }
    }

    /// Verify an untrusted CRL against a trusted or intermediary signer in the store,
    /// and push the new CRL to the store. Does *not* affect or remove any existing
    /// trusted identities in the store.
    pub fn push_unverified_crl(&mut self, crl: CertificateList) -> anyhow::Result<()> {
        let signer = self.find_issuer(crl.tbs_cert_list.issuer.to_string(), None)?;
        signer
            .pk
            .verify_strict(&crl)
            .map_err(|e| anyhow!("failed to verify crl signature: {e}"))?;

        if !crl.valid_at(self.current_time) {
            bail!("Expired or future CRL")
        }

        self.push_trusted_crl(crl);
        Ok(())
    }

    /// Verify the leaf node in a certificate chain is rooted in
    /// the trust store and does not use any revoked signatures.
    pub fn verify_chain_leaf(&self, chain: &[CertificateInner]) -> anyhow::Result<TrustedIdentity> {
        if chain.is_empty() {
            bail!("empty certificate chain")
        }
        if !chain.valid_at(self.current_time) {
            bail!("cert chain contains expired or future certificates")
        }

        // work through the certificate chain from the root (last) certificate
        let mut chain = chain.iter().rev().peekable();
        let mut intermediary = BTreeMap::new();
        loop {
            let cert = chain.next().expect("should have returned after leaf");
            let issuer = cert.tbs_certificate.issuer.to_string();
            let subject = cert.tbs_certificate.subject.to_string();

            // Ensure this cert is not revoked
            self.check_crls(cert)?;
            let signer = self.find_issuer(issuer, Some(&intermediary))?;

            // Validate issuer signature
            signer
                .pk
                .verify_strict(cert)
                .map_err(|e| anyhow!("failed to verify certificate: {e}"))?;

            let pk = (cert)
                .try_into()
                .map_err(|e| anyhow!("failed to parse key from certificate: {e}"))?;
            let ident = TrustedIdentity {
                pk,
                cert: cert.clone(),
            };

            if chain.peek().is_none() {
                // If we're the leaf (end) of the chain, discard intermediaries,
                // and return the verified identity
                intermediary.clear();
                return Ok(ident);
            } else {
                // Otherwise, push to intermediaries and process the next certificate
                intermediary.insert(subject, ident);
            }
        }
    }

    /// Check the current crls to ensure a certificate is not revoked
    fn check_crls(&self, cert: &CertificateInner) -> anyhow::Result<()> {
        if self
            .crl
            .contains(&cert.tbs_certificate.serial_number.to_string())
        {
            bail!("certificate is revoked");
        }

        Ok(())
    }

    /// Find an issuer in the trusted or intermediary stores
    fn find_issuer<'a>(
        &'a self,
        issuer: String,
        intermediary: Option<&'a BTreeMap<String, TrustedIdentity>>,
    ) -> anyhow::Result<&'a TrustedIdentity> {
        if let Some(signer) = self.trusted.get(&issuer) {
            return Ok(signer);
        }
        if let Some(intermediary) = intermediary {
            if let Some(signer) = intermediary.get(&issuer) {
                return Ok(signer);
            }
        }
        bail!("failed to find trusted issuer")
    }
}
