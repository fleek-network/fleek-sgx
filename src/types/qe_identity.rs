use chrono::Utc;

/// The version of EnclaveIdentity JSON structure
const ENCLAVE_IDENTITY_V2: u16 = 2;

pub(crate) type UInt16LE = zerocopy::little_endian::U16;
pub(crate) type UInt32LE = zerocopy::little_endian::U32;
pub(crate) type UInt64LE = zerocopy::little_endian::U64;

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct EnclaveIdentity {
    pub id: EnclaveType,
    version: u16,
    _issue_date: chrono::DateTime<Utc>,
    pub next_update: chrono::DateTime<Utc>,
    _tcb_evaluation_data_number: u16,
    #[serde(deserialize_with = "deserialize_u32_hex")]
    pub miscselect: UInt32LE,
    #[serde(deserialize_with = "deserialize_u32_hex")]
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

fn deserialize_u32_hex<'de, D>(deserializer: D) -> std::result::Result<UInt32LE, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value: [u8; 4] = hex::deserialize(deserializer)?;
    Ok(value.into())
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

#[derive(Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub(crate) enum EnclaveType {
    /// Quoting Enclave
    Qe,
    /// Quote Verification Enclave (which we won't use)
    Qve,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct QeTcbLevel {
    // We don't bother deserializing the field "advisoryIds" since
    // we fetch the advisory ids from the matching TCB level
    tcb: QeTcb,
    _tcb_date: chrono::DateTime<Utc>,
    tcb_status: QeTcbStatus,
}

#[cfg(test)]
impl QeTcbLevel {
    pub(crate) fn from_parts(tcb_status: QeTcbStatus, isvsvn: u16) -> Self {
        Self {
            _tcb_date: Utc::now(),
            tcb_status,
            tcb: QeTcb { isvsvn },
        }
    }
}

#[derive(Deserialize, Debug)]
struct QeTcb {
    isvsvn: u16,
}

/// The TCB Status returned by "Get Quoting Enclave Identity"
///
/// Note that this is a subset of the [`TcbStatus`] associated with the
/// the [`TcbLevel`]. If the `QeTcbStatus` is not `UpToDate`, the QE
/// should generally be rejected, otherwise the corresponding
/// `TcbLevel` should be found and consulted.
#[derive(Debug, PartialEq, Eq, Deserialize)]
pub(crate) enum QeTcbStatus {
    UpToDate,
    OutOfDate,
    Revoked,
}
