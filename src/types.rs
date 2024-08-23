use std::ffi::CString;
use std::fmt::Display;
use std::str::FromStr;

use anyhow::{bail, Context};
use chrono::Utc;
use mbedtls::bignum::Mpi;
use mbedtls::ecp::EcPoint;
use mbedtls::pk::{EcGroup, Pk};
use serde::{de, Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;
use x509_parser::nom::AsBytes;

pub const SECP256R1_OID_STRING: &str = "1.2.840.10045.3.1.7";

/// Intel public key that signs all root certificates for DCAP
const INTEL_ROOT_PUB_KEY: &[u8] = &[
    0x04, 0x0b, 0xa9, 0xc4, 0xc0, 0xc0, 0xc8, 0x61, 0x93, 0xa3, 0xfe, 0x23, 0xd6, 0xb0, 0x2c, 0xda,
    0x10, 0xa8, 0xbb, 0xd4, 0xe8, 0x8e, 0x48, 0xb4, 0x45, 0x85, 0x61, 0xa3, 0x6e, 0x70, 0x55, 0x25,
    0xf5, 0x67, 0x91, 0x8e, 0x2e, 0xdc, 0x88, 0xe4, 0x0d, 0x86, 0x0b, 0xd0, 0xcc, 0x4e, 0xe2, 0x6a,
    0xac, 0xc9, 0x88, 0xe5, 0x05, 0xa9, 0x53, 0x55, 0x8c, 0x45, 0x3f, 0x6b, 0x09, 0x04, 0xae, 0x73,
    0x94,
];

pub fn get_intel_pub_key() -> Pk {
    let ec_group = EcGroup::new(mbedtls::pk::EcGroupId::SecP256R1).unwrap();

    let point = EcPoint::from_binary(&ec_group, INTEL_ROOT_PUB_KEY).unwrap();

    Pk::public_from_ec_components(ec_group, point).unwrap()
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SgxCollateral {
    /// version = 1. PCK Cert chain is in the Quote.
    pub version: u32,
    /// PCK CRL Issuer Chain in PEM format
    pub pck_crl_issuer_chain: String,
    /// Root CA CRL in PEM format
    pub root_ca_crl: String,
    /// PCK Cert CRL in PEM format
    pub pck_crl: String,
    /// TCB info issuer chain in PEM format
    pub tcb_info_issuer_chain: CString,
    // TCB Info structure
    #[serde(deserialize_with = "de_from_str")]
    pub tcb_info: TcbInfoAndSignature,
    /// Identity issuer chain in PEM format
    pub qe_identity_issuer_chain: String,
    /// QE Identity Structure
    pub qe_identity: String,
    /// PCK certificate in PEM format
    pub pck_certificate: String,
    /// PCK signing chain in PEM format
    pub pck_signing_chain: String,
}

fn de_from_str<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: TryFrom<String>,
    <T as TryFrom<String>>::Error: Display,
{
    let s = <String>::deserialize(deserializer)?;
    T::try_from(s).map_err(de::Error::custom)
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct TcbInfoAndSignature {
    #[serde(rename = "tcbInfo")]
    tcb_info_raw: Box<RawValue>,
    #[serde(with = "hex")]
    signature: Vec<u8>,
}

impl TryFrom<String> for TcbInfoAndSignature {
    type Error = serde_json::Error;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        serde_json::from_str(&value)
    }
}

impl TcbInfoAndSignature {
    pub fn as_tcb_info_and_verify(&self, public_key: &mut Pk) -> anyhow::Result<TcbInfo> {
        println!("{}", self.tcb_info_raw);
        let hashtype = mbedtls::hash::Type::Sha256;
        let mut bytes = [0u8; 64];
        let len = mbedtls::hash::Md::hash(hashtype, self.tcb_info_raw.get().as_bytes(), &mut bytes)
            .context("failed to hash tcb info raw")?;
        let hash = &bytes[0..len];

        public_key
            .verify(hashtype, hash, &self.signature)
            .context("invalid tcb info signature")?;

        let tcb_info: TcbInfo =
            serde_json::from_str(self.tcb_info_raw.get()).context("tcb info")?;

        if tcb_info
            .tcb_levels
            .iter()
            .any(|e| e.tcb.version() != tcb_info.version)
        {
            bail!(
                "mismatched tcb info versions, should all be {:?}",
                tcb_info.version,
            );
        }

        // tcb_type determines how to compare tcb level
        // currently, only 0 is valid
        if tcb_info.tcb_type != 0 {
            bail!("unsupported tcb type {}", tcb_info.tcb_type,);
        }
        Ok(tcb_info)
    }
}

/// Version of the TcbInfo JSON structure
///
/// In the PCS V3 API the TcbInfo version is V2, in the PCS V4 API the TcbInfo
/// version is V3. The V3 API includes advisoryIDs and changes the format of
/// the TcbLevel

#[derive(Deserialize, Serialize, Clone, Debug, Eq, PartialEq)]
#[serde(try_from = "u16")]
pub(crate) enum TcbInfoVersion {
    V2 = 2,
    V3 = 3,
}

impl TryFrom<u16> for TcbInfoVersion {
    type Error = &'static str;
    fn try_from(value: u16) -> std::result::Result<Self, Self::Error> {
        match value {
            2 => Ok(TcbInfoVersion::V2),
            3 => Ok(TcbInfoVersion::V3),
            _ => Err("Unsupported TCB Info version"),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TcbInfo {
    version: TcbInfoVersion,
    _issue_date: chrono::DateTime<Utc>,
    pub next_update: chrono::DateTime<Utc>,
    #[serde(with = "hex")]
    pub fmspc: [u8; 6],
    #[serde(with = "hex")]
    pub pce_id: [u8; 2],
    tcb_type: u16,
    _tcb_evaluation_data_number: u16,
    pub tcb_levels: Vec<TcbLevel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TcbLevel {
    pub tcb: Tcb,
    pub tcb_date: chrono::DateTime<Utc>,
    pub tcb_status: String,
    #[serde(rename = "advisoryIDs")]
    pub advisory_ids: Vec<String>,
}

#[derive(Debug, Eq, PartialEq, Clone, Copy, Deserialize, Serialize)]
pub(crate) enum TcbStatus {
    UpToDate,
    OutOfDate,
    ConfigurationNeeded,
    SWHardeningNeeded,
    ConfigurationAndSWHardeningNeeded,
    OutOfDateConfigurationNeeded,
    Revoked,
}

/// Contains information identifying a TcbLevel.
#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
#[serde(untagged)]
pub(crate) enum Tcb {
    V2(TcbV2),
    V3(TcbV3),
}

impl Tcb {
    fn version(&self) -> TcbInfoVersion {
        match self {
            Tcb::V2(_) => TcbInfoVersion::V2,
            Tcb::V3(_) => TcbInfoVersion::V3,
        }
    }
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub(crate) struct TcbV3 {
    sgxtcbcomponents: [TcbComponentV3; 16],
    pcesvn: u16,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug, Copy)]
pub(crate) struct TcbComponentV3 {
    svn: u8,
}

#[derive(Deserialize, Serialize, PartialEq, Eq, Clone, Debug)]
pub(crate) struct TcbV2 {
    sgxtcbcomp01svn: u8,
    sgxtcbcomp02svn: u8,
    sgxtcbcomp03svn: u8,
    sgxtcbcomp04svn: u8,
    sgxtcbcomp05svn: u8,
    sgxtcbcomp06svn: u8,
    sgxtcbcomp07svn: u8,
    sgxtcbcomp08svn: u8,
    sgxtcbcomp09svn: u8,
    sgxtcbcomp10svn: u8,
    sgxtcbcomp11svn: u8,
    sgxtcbcomp12svn: u8,
    sgxtcbcomp13svn: u8,
    sgxtcbcomp14svn: u8,
    sgxtcbcomp15svn: u8,
    sgxtcbcomp16svn: u8,
    pcesvn: u16,
}

impl Tcb {
    pub fn pcesvn(&self) -> u16 {
        match self {
            Self::V2(v2) => v2.pcesvn,
            Self::V3(v3) => v3.pcesvn,
        }
    }

    pub fn components(&self) -> [u8; 16] {
        match self {
            Self::V2(v2) => [
                v2.sgxtcbcomp01svn,
                v2.sgxtcbcomp02svn,
                v2.sgxtcbcomp03svn,
                v2.sgxtcbcomp04svn,
                v2.sgxtcbcomp05svn,
                v2.sgxtcbcomp06svn,
                v2.sgxtcbcomp07svn,
                v2.sgxtcbcomp08svn,
                v2.sgxtcbcomp09svn,
                v2.sgxtcbcomp10svn,
                v2.sgxtcbcomp11svn,
                v2.sgxtcbcomp12svn,
                v2.sgxtcbcomp13svn,
                v2.sgxtcbcomp14svn,
                v2.sgxtcbcomp15svn,
                v2.sgxtcbcomp16svn,
            ],
            Self::V3(v3) => v3.sgxtcbcomponents.map(|comp| comp.svn),
        }
    }
}

#[cfg(test)]
#[test]
fn test_parse_sgx_collateral() {
    /* Copyright (c) Fortanix, Inc.
     *
     * Licensed under the GNU General Public License, version 2 <LICENSE-GPL or
     * https://www.gnu.org/licenses/gpl-2.0.html> or the Apache License, Version
     * 2.0 <LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0>, at your
     * option. This file may not be copied, modified, or distributed except
     * according to those terms. */

    use mbedtls_sys::types::raw_types::{c_int, c_uchar, c_void};
    use mbedtls_sys::types::size_t;
    use rand::{Rng, XorShiftRng};

    /// Not cryptographically secure!!! Use for testing only!!!
    pub struct TestInsecureRandom(XorShiftRng);

    impl mbedtls::rng::RngCallbackMut for TestInsecureRandom {
        unsafe extern "C" fn call_mut(
            p_rng: *mut c_void,
            data: *mut c_uchar,
            len: size_t,
        ) -> c_int {
            (*(p_rng as *mut TestInsecureRandom))
                .0
                .fill_bytes(core::slice::from_raw_parts_mut(data, len));
            0
        }

        fn data_ptr_mut(&mut self) -> *mut c_void {
            self as *const _ as *mut _
        }
    }

    impl mbedtls::rng::RngCallback for TestInsecureRandom {
        unsafe extern "C" fn call(p_rng: *mut c_void, data: *mut c_uchar, len: size_t) -> c_int {
            (*(p_rng as *mut TestInsecureRandom))
                .0
                .fill_bytes(core::slice::from_raw_parts_mut(data, len));
            0
        }

        fn data_ptr(&self) -> *mut c_void {
            self as *const _ as *mut _
        }
    }

    pub type TestRandom = TestInsecureRandom;

    /// Not cryptographically secure!!! Use for testing only!!!
    pub fn test_deterministic_rng() -> TestInsecureRandom {
        TestInsecureRandom(rand::XorShiftRng::new_unseeded())
    }

    use mbedtls::pk::EcGroupId;
    let rng = &mut test_deterministic_rng();

    let mut pk = Pk::generate_ec(rng, EcGroupId::SecP256R1).unwrap();

    let hash = [0u8; 32];
    let mut buf = [0u8; 256];
    let len = pk
        .sign(mbedtls::hash::Type::Sha256, &hash, &mut buf, rng)
        .unwrap();
    let sig = &buf[..len];
    pk.verify(mbedtls::hash::Type::Sha256, &hash, sig).unwrap();

    let json = include_str!("../data/full_collaterall.json");
    let collat: SgxCollateral = serde_json::from_str(json).expect("json to parse");
    // println!("{}", serde_json::to_string_pretty(&collat).unwrap());
}

pub struct Quote {}
