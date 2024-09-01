use ecies::{decrypt, encrypt, PublicKey, SecretKey};
use libsecp256k1::curve::Scalar;
use sha2::{Digest, Sha256};

use crate::error::EnclaveError;

pub struct SealKeyPair {
    pub public: PublicKey,
    pub secret: SecretKey,
}

impl SealKeyPair {
    pub fn from_seed_key(seed: &[u8; 16]) -> Self {
        // Hash the seed
        let mut hasher = Sha256::new();
        hasher.update(seed);
        let mut hashed_seed: [u8; 32] = hasher.finalize().into();

        let mut scalar: Scalar;

        loop {
            scalar = Scalar::default();
            if !bool::from(scalar.set_b32(&hashed_seed)) && !scalar.is_zero() {
                break;
            }
            // If the hash is not on the curve(2^128 chance) or is zero, rehash and try again
            let mut hasher = Sha256::new();
            hasher.update(hashed_seed);
            hashed_seed = hasher.finalize().into();
        }

        let secret = scalar
            .try_into()
            .expect("SAFE: we already checked that its on the curve and !zero");
        let public = PublicKey::from_secret_key(&secret);
        Self { public, secret }
    }

    pub fn from_secret_key_bytes(bytes: &[u8; 32]) -> Result<Self, EnclaveError> {
        SecretKey::parse_slice(bytes)
            .map(|sk| {
                let public = PublicKey::from_secret_key(&sk);
                Self { public, secret: sk }
            })
            .map_err(|_| EnclaveError::GeneratedBadSharedKey)
    }

    pub fn from_secret_key_slice(slice: &[u8]) -> Result<Self, EnclaveError> {
        if slice.len() != 32 {
            return Err(EnclaveError::GeneratedBadSharedKey);
        }
        let mut a = [0; 32];
        a.copy_from_slice(slice);
        Self::from_secret_key_bytes(&a)
    }

    pub fn unseal(&self, msg: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        decrypt(&self.secret.serialize(), msg).map_err(|_| EnclaveError::FailedToUnseal)
    }

    pub fn seal(&self, msg: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        encrypt(&self.public.serialize(), msg).map_err(|_| EnclaveError::FailedToSeal)
    }
}
