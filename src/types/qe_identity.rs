// Adapted from: https://github.com/signalapp/libsignal/

use anyhow::{bail, Context};
use chrono::Utc;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::UInt32LE;
use crate::utils::u32_hex;

/// The version of EnclaveIdentity JSON structure
const ENCLAVE_IDENTITY_V2: u16 = 2;

#[derive(Debug, Deserialize, Serialize)]
pub struct QuotingEnclaveIdentityAndSignature {
    #[serde(rename = "enclaveIdentity")]
    enclave_identity_raw: Box<RawValue>,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl TryFrom<String> for QuotingEnclaveIdentityAndSignature {
    type Error = serde_json::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

impl QuotingEnclaveIdentityAndSignature {
    pub fn verify_as_enclave_identity(
        &self,
        public_key: &VerifyingKey,
    ) -> anyhow::Result<EnclaveIdentity> {
        public_key
            .verify(
                self.enclave_identity_raw.to_string().as_bytes(),
                &Signature::from_slice(&self.signature).context("failed to parse signature")?,
            )
            .context("failed to verify qe identity signature")?;

        let identity: EnclaveIdentity = serde_json::from_str(self.enclave_identity_raw.get())
            .context("failed to parse enclave identity")?;
        if identity.version != ENCLAVE_IDENTITY_V2 {
            bail!("unsupported enclave identity version {}", identity.version);
        }

        Ok(identity)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveIdentity {
    pub id: EnclaveType,
    version: u16,
    _issue_date: chrono::DateTime<Utc>,
    pub next_update: chrono::DateTime<Utc>,
    _tcb_evaluation_data_number: u16,
    #[serde(with = "u32_hex")]
    pub miscselect: UInt32LE,
    #[serde(with = "u32_hex")]
    pub miscselect_mask: UInt32LE,
    #[serde(with = "hex")]
    pub attributes: [u8; 16],
    #[serde(with = "hex")]
    pub attributes_mask: [u8; 16],
    #[serde(with = "hex")]
    pub mrsigner: [u8; 32],
    pub isvprodid: u16,
    pub tcb_levels: Vec<QeTcbLevel>,
}

impl EnclaveIdentity {
    /// Find the latest tcb level in the Enclave Identity that the
    /// QE report is less than or equal to.
    ///
    /// This follows steps 4.a-c
    /// in <https://api.portal.trustedservices.intel.com/documentation#pcs-qe-identity-v3>
    pub fn tcb_status(&self, report_isvsvn: u16) -> &QeTcbStatus {
        // tcb_levels is in descending order by ISVSVN according to spec
        self.tcb_levels
            .iter()
            .find(|tcb_level| tcb_level.tcb.isvsvn <= report_isvsvn)
            .map(|level| &level.tcb_status)
            .unwrap_or(&QeTcbStatus::Revoked)
    }
}

// impl Expireable for EnclaveIdentity {
//     fn valid_at(&self, timestamp: SystemTime) -> bool {
//         // don't care about issue_date
//         // 1. There's no notion of "valid before" like in X509
//         // 2. These dates might be *very* recent, and we don't want to fail requests because of
//         //    clock skew
//         timestamp <= self.next_update.into()
//     }
// }

#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum EnclaveType {
    /// Quoting Enclave
    Qe,
    /// Quote Verification Enclave (which we won't use)
    Qve,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct QeTcbLevel {
    // We don't bother deserializing the field "advisoryIds" since
    // we fetch the advisory ids from the matching TCB level
    tcb: QeTcb,
    _tcb_date: chrono::DateTime<Utc>,
    tcb_status: QeTcbStatus,
}

#[cfg(test)]
impl QeTcbLevel {
    pub fn from_parts(tcb_status: QeTcbStatus, isvsvn: u16) -> Self {
        Self {
            _tcb_date: Utc::now(),
            tcb_status,
            tcb: QeTcb { isvsvn },
        }
    }
}

#[derive(Deserialize, Serialize, Debug)]
struct QeTcb {
    isvsvn: u16,
}

/// The TCB Status returned by "Get Quoting Enclave Identity"
///
/// Note that this is a subset of the [`TcbStatus`] associated with the
/// the [`TcbLevel`]. If the `QeTcbStatus` is not `UpToDate`, the QE
/// should generally be rejected, otherwise the corresponding
/// `TcbLevel` should be found and consulted.
#[derive(Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum QeTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}

#[cfg(test)]
mod tests {
    use super::QuotingEnclaveIdentityAndSignature;

    #[test]
    fn parse_qe_identity_and_signature() {
        let json = include_str!("../../data/qe_identity.json");
        let tcb_info_and_sig: QuotingEnclaveIdentityAndSignature =
            serde_json::from_str(json).expect("parse json");
        println!(
            "{}",
            serde_json::to_string(&tcb_info_and_sig).expect("serialize json")
        );
    }
}
