use std::collections::{BTreeMap, BTreeSet};

use anyhow::{anyhow, bail};
use x509_cert::certificate::CertificateInner;
use x509_cert::crl::CertificateList;
use x509_verify::VerifyingKey;

/// Trust store for verifying certificate chains
pub struct TrustStore {
    /// Trusted CAs
    pub trusted: BTreeMap<String, TrustedIdentity>,
    /// Trusted certificate revokation list
    pub crl: BTreeSet<String>,
}

/// Wrapper for a pre-parsed trusted identity for verification
pub struct TrustedIdentity {
    pub cert: CertificateInner,
    pub pk: VerifyingKey,
}

impl TrustStore {
    /// Create a new trust store with a list of trusted CAs
    pub fn new(trusted: Vec<CertificateInner>) -> anyhow::Result<Self> {
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
            .verify(&crl)
            .map_err(|e| anyhow!("failed to verify crl signature: {e}"))?;
        self.push_trusted_crl(crl);
        Ok(())
    }

    /// Verify the leaf node in a certificate chain is rooted in
    /// the trust store and does not use any revoked signatures.
    pub fn verify_chain_leaf(&self, chain: &[CertificateInner]) -> anyhow::Result<TrustedIdentity> {
        if chain.is_empty() {
            bail!("empty certificate chain")
        }

        // work through the certificate chain from the root (last) certificate
        let mut chain = chain.iter().rev().peekable();
        let mut intermediary = BTreeMap::new();
        loop {
            // safety: we
            let cert = chain.next().unwrap();
            let issuer = cert.tbs_certificate.issuer.to_string();
            let subject = cert.tbs_certificate.subject.to_string();

            // Ensure this cert is not revoked
            self.check_crls(cert)?;
            let signer = self.find_issuer(issuer, Some(&intermediary))?;

            // Validate issuer signature
            signer
                .pk
                .verify(cert)
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
