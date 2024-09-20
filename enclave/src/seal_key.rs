use std::str::FromStr;

use bip32::{DerivationPath, ExtendedKey, ExtendedPrivateKey, ExtendedPublicKey, Prefix};

use crate::error::EnclaveError;

pub struct SealKeyPair {
    pub public: ExtendedPublicKey<PublicKeyWrapped>,
    pub secret: ExtendedPrivateKey<SecretKeyWrapped>,
}

impl SealKeyPair {
    /// Theoretically, quantum computing can reduce 256 bit secp256k1 keys to an effective entropy
    /// of 128 bits. Therefore, a 128 bit seed will provide the same entrophy as a 256 bit seed.
    pub fn from_seed_key(seed: [u8; 16]) -> Self {
        let secret = ExtendedPrivateKey::derive_from_path(
            seed,
            &DerivationPath::from_str("m/0'/0'").unwrap(),
        )
        .expect("point not on curve. todo: handle this");
        let public = secret.public_key();
        Self { public, secret }
    }

    /// Serialize extended secret key into base58 bytes
    pub fn to_private_bytes(&self) -> [u8; 112] {
        self.secret
            .to_string(Prefix::XPRV)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    /// Serialize extended public key into base58 bytes
    pub fn to_public_bytes(&self) -> [u8; 112] {
        self.public
            .to_string(Prefix::XPUB)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    /// Deserialize extended private fro base58 bytes
    pub fn from_private_bytes(bytes: [u8; 112]) -> anyhow::Result<Self> {
        let string = String::from_utf8(bytes.into())?;
        let ext = ExtendedKey::from_str(&string)?;
        let secret = ExtendedPrivateKey::try_from(ext)?;
        let public = secret.public_key();
        Ok(Self { secret, public })
    }

    /// Unseal content via ECIES
    pub fn unseal(&self, msg: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        ecies::decrypt(&self.secret.to_bytes(), msg).map_err(|_| EnclaveError::FailedToUnseal)
    }

    /// Seal content via ECIES
    pub fn seal(&self, msg: &[u8]) -> Result<Vec<u8>, EnclaveError> {
        ecies::encrypt(&self.public.to_bytes(), msg).map_err(|_| EnclaveError::FailedToSeal)
    }
}

pub struct SecretKeyWrapped(pub libsecp256k1::SecretKey);
impl bip32::PrivateKey for SecretKeyWrapped {
    type PublicKey = PublicKeyWrapped;
    fn from_bytes(bytes: &bip32::PrivateKeyBytes) -> bip32::Result<Self> {
        let secret = libsecp256k1::SecretKey::parse(bytes).map_err(|_| bip32::Error::Decode)?;
        Ok(Self(secret))
    }

    fn to_bytes(&self) -> bip32::PrivateKeyBytes {
        self.0.serialize()
    }

    fn derive_child(&self, other: bip32::PrivateKeyBytes) -> bip32::Result<Self> {
        let m = libsecp256k1::SecretKey::parse(&other).map_err(|_| bip32::Error::Decode)?;
        let mut child = self.0;
        child
            .tweak_add_assign(&m)
            .map_err(|_| bip32::Error::Crypto)?;
        Ok(Self(child))
    }

    fn public_key(&self) -> Self::PublicKey {
        let public = libsecp256k1::PublicKey::from_secret_key(&self.0);
        PublicKeyWrapped(public)
    }
}

#[derive(Clone)]
pub struct PublicKeyWrapped(pub libsecp256k1::PublicKey);
impl bip32::PublicKey for PublicKeyWrapped {
    fn from_bytes(bytes: bip32::PublicKeyBytes) -> bip32::Result<Self> {
        libsecp256k1::PublicKey::parse_compressed(&bytes)
            .map(PublicKeyWrapped)
            .map_err(|_| bip32::Error::Decode)
    }

    fn to_bytes(&self) -> bip32::PublicKeyBytes {
        self.0.serialize_compressed()
    }

    fn derive_child(&self, other: bip32::PrivateKeyBytes) -> bip32::Result<Self> {
        let m = libsecp256k1::SecretKey::parse(&other).map_err(|_| bip32::Error::Decode)?;
        let mut child = self.clone();
        child
            .0
            .tweak_add_assign(&m)
            .map_err(|_| bip32::Error::Crypto)?;
        Ok(child)
    }
}
