use std::str::FromStr;

use mbedtls::bignum::Mpi;
use mbedtls::ecp::EcPoint;
use mbedtls::pk::{EcGroup, Pk};
use serde::{Deserialize, Serialize};

lazy_static::lazy_static! {
    pub static ref INTEL_PKEY: Pk = {
        let ec_group = get_prime256_v1_ec_group();

        let point = EcPoint::from_binary(&ec_group, INTEL_ROOT_PUB_KEY).unwrap();

        Pk::public_from_ec_components(ec_group, point).unwrap()
    };
}

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
    let ec_group = get_prime256_v1_ec_group();

    let point = EcPoint::from_binary(&ec_group, INTEL_ROOT_PUB_KEY).unwrap();

    Pk::public_from_ec_components(ec_group, point).unwrap()
}

/// Curve used on x509 signatures
/// todo: we should find a way to make this const
pub fn get_prime256_v1_ec_group() -> EcGroup {
    let p = Mpi::from_str("0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
        .unwrap();
    let a = Mpi::from_str("0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc")
        .unwrap();

    let b = Mpi::from_str("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
        .unwrap();

    let g_x = Mpi::from_str("0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
        .unwrap();
    let g_y = Mpi::from_str("0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
        .unwrap();

    let order = Mpi::from_str("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
        .unwrap();

    EcGroup::from_parameters(p, a, b, g_x, g_y, order).unwrap()
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
    pub tcb_info_issuer_chain: String,
    // TCB Info structure
    pub tcb_info: String,
    /// Identity issuer chain in PEM format
    pub qe_identity_issuer_chain: String,
    /// QE Identity Structure
    pub qe_identity: String,
    /// PCK certificate in PEM format
    pub pck_certificate: String,
    /// PCK signing chain in PEM format
    pub pck_signing_chain: String,
}

pub struct Quote {}
