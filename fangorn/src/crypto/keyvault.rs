
use std::{io::Read, sync::{Arc, RwLock}};
use iroh::SecretKey as IrohSecretKey;
use rust_vault::Vault;
use secrecy::{ExposeSecret, SecretString};
use sp_core::{
    Pair as PairT, crypto::Ss58Codec, sr25519
};
use bip39::Mnemonic;
use thiserror::Error;
use ark_std::rand::rngs::OsRng;

#[derive(Error, Debug)]
pub enum KeyVaultError {
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

pub trait KeyVault {
    /// The public key type
    type Public: Clone + PartialEq + std::fmt::Debug;

    /// The signature type
    type Signature: Clone + PartialEq + std::fmt::Debug;

    /// The pair type (private + public key)
    type Pair: PairT;

    fn get_public_key(&self, key_name: String, file_password: &mut SecretString) -> Result<Self::Public, KeyVaultError>;

    /// Generate a new keypair and return the public key
    fn generate_key(&self, key_name: String, file_password: &mut SecretString) -> Result<Self::Public, KeyVaultError>;

    /// List all public keys in the keystore
    fn list_keys(&self) -> Result<Vec<String>, KeyVaultError>;

    /// Check if a specific key exists
    fn has_key(&self, key_name: String) -> bool;

    /// Sign a message with the specified public key
    fn sign(&self, key_name: String, message: &[u8], file_password: &mut SecretString)
    -> Result<Self::Signature, KeyVaultError>;

    /// Verify a signature (can be static since verification only needs the public key)
    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool;

    // /// Get the underlying Substrate keystore pointer
    // fn keystore_ptr(&self) -> KeystorePtr;
}

pub struct Sr25519KeyVault {
    vault: Arc<RwLock<Vault>>,
}

impl Sr25519KeyVault {

    pub fn new(vault: Vault) -> Self {
        Self {vault: Arc::new(RwLock::new(vault))}
    }

    /// Convert public key to SS58 address format
    pub fn to_ss58(&self, public: &<Sr25519KeyVault as KeyVault>::Public) -> String {
        public.to_ss58check()
    }

    /// Parse SS58 address to public key
    pub fn from_ss58(address: &str) -> Result<<Sr25519KeyVault as KeyVault>::Public, KeyVaultError> {
        <Sr25519KeyVault as KeyVault>::Public::from_ss58check(address)
            .map_err(|_| KeyVaultError::Keystore("Invalid SS58 address".to_string()))
    }
}

impl KeyVault for Sr25519KeyVault {
    type Public = sr25519::Public;
    type Signature = sr25519::Signature;
    type Pair = sr25519::Pair;

    fn generate_key(&self, key_name: String, file_password: &mut SecretString) -> Result<Self::Public, KeyVaultError> {
        // SecretString::new(Mnemonic::ge)
        let secret_mnemonic = SecretString::new(Mnemonic::generate(24).unwrap().to_string().into());

        let (pair, seed) = Self::Pair::from_phrase(&secret_mnemonic.expose_secret(), None)
        .expect("Failed to generate keypair from mnemonic");

        let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());

        // Lock the vault for writing and write the entire keypair
        self.vault.write()
            .map_err(|_| KeyVaultError::Keystore("Failed to lock vault".to_string()))?
            .store_bytes(&key_name, &seed, &mut vault_password, file_password).unwrap();

        Ok(pair.public())

    }

    fn list_keys(&self) -> Result<Vec<String>, KeyVaultError> {
        Ok(self.vault.try_read().unwrap().list())
    }

    fn has_key(&self, key_name: String) -> bool {
        self.vault.try_read().unwrap().contains(key_name.as_str())
    }

    fn get_public_key(&self, key_name: String, file_password: &mut SecretString) -> Result<Self::Public, KeyVaultError> {
        // lock vault for writing since the vault state is modified on read
        let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());
        let seed_bytes = self.vault.write().unwrap().get(&key_name, &mut vault_password, file_password).unwrap();
        let pair = Self::Pair::from_seed_slice(seed_bytes.expose_secret()).unwrap();
        Ok(pair.public())
    }

    fn sign(
        &self,
        key_name: String,
        message: &[u8],
        file_password: &mut SecretString,
    ) -> Result<Self::Signature, KeyVaultError> {
        // lock vault for writing since the vault state is modified on read
        let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());
        let seed_bytes = self.vault.write().unwrap().get(&key_name, &mut vault_password, file_password).unwrap();
        let pair = Self::Pair::from_seed_slice(seed_bytes.expose_secret()).unwrap();
        Ok(pair.sign(message))
    }

    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool {
        Self::Pair::verify(signature, message, public)
    }

}

pub struct IrohKeyVault {
    vault: Arc<RwLock<Vault>>,
}

impl IrohKeyVault {

    pub fn new(vault: Vault) -> Self {
        Self {vault: Arc::new(RwLock::new(vault))}
    }

}

impl KeyVault for IrohKeyVault {
    type Public = iroh::PublicKey;
    type Signature = iroh::Signature;
    // This is not used, but must be fulfilled for the KeyVault trait
    type Pair = sp_core::ed25519::Pair;

    fn generate_key(&self, key_name: String, file_password: &mut SecretString) -> Result<Self::Public, KeyVaultError> {
        let iroh_sk = IrohSecretKey::generate(&mut rand::rng());
        let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());
        self.vault.write().unwrap().store_bytes(key_name.as_str(), &iroh_sk.to_bytes(), &mut vault_password, file_password).unwrap();
        Ok(iroh_sk.public())
    }

    fn list_keys(&self) -> Result<Vec<String>, KeyVaultError> {
        Ok(self.vault.try_read().unwrap().list())
    }

    fn has_key(&self, key_name: String) -> bool {
        self.vault.try_read().unwrap().contains(key_name.as_str())
    }

    fn get_public_key(&self, key_name: String, file_password: &mut SecretString) -> Result<Self::Public, KeyVaultError> {
        // lock vault for writing since the vault state is modified on read
        let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());
        let secret_key = self.vault.write().unwrap().get(&key_name, &mut vault_password, file_password).unwrap();
        let mut secret_bytes = [0u8;32];
        secret_key.expose_secret().read(&mut secret_bytes)?;
        let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
        Ok(secret_key.public())
    }

    fn sign(
        &self,
        key_name: String,
        message: &[u8],
        file_password: &mut SecretString,
    ) -> Result<Self::Signature, KeyVaultError> {
        let mut vault_password = SecretString::new(String::from("vault_password").into_boxed_str());
        let secret_key = self.vault.write().unwrap().get(&key_name, &mut vault_password, file_password).unwrap();
        let mut secret_bytes = [0u8;32];
        secret_key.expose_secret().read(&mut secret_bytes)?;
        let secret_key = IrohSecretKey::from_bytes(&secret_bytes);
        Ok(secret_key.sign(message))
    }

    fn verify(public: &Self::Public, message: &[u8], signature: &Self::Signature) -> bool {
        public.verify(message, signature).is_ok()
    }

}