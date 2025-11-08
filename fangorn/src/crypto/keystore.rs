use sc_keystore::LocalKeystore;
use sp_application_crypto::RuntimePublic;
use sp_core::{
    Pair as PairT,
    crypto::{KeyTypeId, Ss58Codec},
    sr25519,
};
use sp_keystore::{Keystore as SubstrateKeystore, KeystorePtr};
use std::path::PathBuf;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeystoreError {
    #[error("Keystore error: {0}")]
    Keystore(String),
    #[error("Key not found")]
    KeyNotFound,
    #[error("Invalid signature")]
    InvalidSignature,
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Secret string error: {0}")]
    SecretString(#[from] sp_core::crypto::SecretStringError),
}

/// Generic keystore trait that supports multiple cryptographic curves
pub trait Keystore {
    /// The public key type
    type Public: Clone + PartialEq + std::fmt::Debug;

    /// The signature type
    type Signature: Clone + PartialEq + std::fmt::Debug;

    /// The pair type (private + public key)
    type Pair: PairT;

    /// Generate a new keypair and return the public key
    fn generate_key(&self) -> Result<Self::Public, KeystoreError>;

    /// Generate a new keypair from a mnemonic/seed phrase
    fn generate_key_with_seed(&self, seed: Option<&str>) -> Result<Self::Public, KeystoreError>;

    /// Import a key from a seed or mnemonic
    fn import_key(&self, seed: &str) -> Result<Self::Public, KeystoreError>;

    /// List all public keys in the keystore
    fn list_keys(&self) -> Result<Vec<Self::Public>, KeystoreError>;

    /// Check if a specific key exists
    fn has_key(&self, public: &Self::Public) -> bool;

    /// Sign a message with the specified public key
    fn sign(&self, public: &Self::Public, message: &[u8])
    -> Result<Self::Signature, KeystoreError>;

    /// Verify a signature (can be static since verification only needs the public key)
    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool;

    /// Convert public key to SS58 address format
    fn to_ss58(&self, public: &Self::Public) -> String;

    /// Parse SS58 address to public key
    fn from_ss58(address: &str) -> Result<Self::Public, KeystoreError>;

    /// Get the underlying Substrate keystore pointer
    fn keystore_ptr(&self) -> KeystorePtr;
}

/// Sr25519 keystore implementation
pub struct Sr25519Keystore {
    keystore: KeystorePtr,
    key_type: KeyTypeId,
}

impl Sr25519Keystore {
    pub fn new(path: PathBuf, key_type: KeyTypeId) -> Result<Self, KeystoreError> {
        std::fs::create_dir_all(&path).unwrap();
        let keystore = LocalKeystore::open(path, None)
            .map_err(|e| KeystoreError::Keystore(format!("{:?}", e)))?;

        Ok(Self {
            keystore: Arc::new(keystore),
            key_type,
        })
    }

    // pub fn new_with_password(
    //     path: PathBuf,
    //     key_type: KeyTypeId,
    //     password: Option<&str>,
    // ) -> Result<Self, KeystoreError> {
    //     // TODO: error handling
    //     std::fs::create_dir_all(&path).unwrap();
    //     let password_protected = password.map(|p| secrecy::SecretString::from(p.to_string()));
    //     let keystore = LocalKeystore::open(path, password_protected)
    //         .map_err(|e| KeystoreError::Keystore(format!("{:?}", e)))?;

    //     Ok(Self {
    //         keystore: Arc::new(keystore),
    //         key_type,
    //     })
    // }
}

impl Keystore for Sr25519Keystore {
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
    type Pair = sr25519::Pair;

    fn generate_key(&self) -> Result<Self::Public, KeystoreError> {
        self.keystore
            .sr25519_generate_new(self.key_type, None)
            .map_err(|e| KeystoreError::Keystore(format!("{:?}", e)))
    }

    fn generate_key_with_seed(&self, seed: Option<&str>) -> Result<Self::Public, KeystoreError> {
        self.keystore
            .sr25519_generate_new(self.key_type, seed)
            .map_err(|e| KeystoreError::Keystore(format!("{:?}", e)))
    }

    fn import_key(&self, seed: &str) -> Result<Self::Public, KeystoreError> {
        let pair = Self::Pair::from_string(seed, None).unwrap();
        self.keystore
            .insert(self.key_type, seed, pair.public().as_ref())
            .map_err(|e| KeystoreError::Keystore(format!("{:?}", e)))?;
        Ok(pair.public())
    }

    fn list_keys(&self) -> Result<Vec<Self::Public>, KeystoreError> {
        Ok(self.keystore.sr25519_public_keys(self.key_type))
    }

    fn has_key(&self, public: &Self::Public) -> bool {
        self.keystore
            .has_keys(&[(public.to_raw_vec(), self.key_type)])
    }

    fn sign(
        &self,
        public: &Self::Public,
        message: &[u8],
    ) -> Result<Self::Signature, KeystoreError> {
        self.keystore
            .sr25519_sign(self.key_type, public, message)
            .map_err(|e| KeystoreError::Keystore(format!("{:?}", e)))?
            .ok_or(KeystoreError::KeyNotFound)
    }

    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool {
        Self::Pair::verify(signature, message, public)
    }

    fn to_ss58(&self, public: &Self::Public) -> String {
        public.to_ss58check()
    }

    fn from_ss58(address: &str) -> Result<Self::Public, KeystoreError> {
        Self::Public::from_ss58check(address)
            .map_err(|_| KeystoreError::Keystore("Invalid SS58 address".to_string()))
    }

    fn keystore_ptr(&self) -> KeystorePtr {
        self.keystore.clone()
    }
}
