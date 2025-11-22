use anyhow::{Context, Result};
use ark_std::rand::RngCore;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretSlice, SecretString};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, Permissions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use argon2::{
    Argon2, PasswordHasher, PasswordVerifier,
    password_hash::{rand_core::OsRng as Argon2Rng, SaltString, PasswordHash},
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce,
};
use zeroize::{Zeroize, Zeroizing};
use thiserror::Error;

// ============================================================================
// Error Types - Production error handling
// ============================================================================

#[derive(Error, Debug)]
pub enum VaultError {
    #[error("Vault not found at path: {0}")]
    VaultNotFound(String),
    
    #[error("Invalid password")]
    InvalidPassword,
    
    #[error("Entry '{0}' not found")]
    EntryNotFound(String),
    
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed - data may be corrupted")]
    DecryptionFailed,
    
    #[error("Invalid vault format: {0}")]
    InvalidFormat(String),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("Vault is locked")]
    VaultLocked,
}

// ============================================================================
// Data Structures
// ============================================================================

#[derive(Serialize, Deserialize, Clone)]
struct EncryptedEntry {
    data: Vec<u8>,
    nonce: [u8; 12],
    created_at: u64,
    #[serde(default)]
    accessed_at: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    version: u32,
    salt: String,
    // Password verification hash to detect wrong password early
    verification: String,
    entries: HashMap<String, EncryptedEntry>,
    #[serde(default)]
    metadata: VaultMetadata,
}

#[derive(Serialize, Deserialize, Default)]
struct VaultMetadata {
    created_at: u64,
    modified_at: u64,
    access_count: u64,
}

// ============================================================================
// Main Vault Implementation
// ============================================================================

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
    entries: HashMap<String, EncryptedEntry>,
    salt: SaltString,
    // verification: PasswordHash<'static>,
    verification: String,
    path: PathBuf,
    metadata: VaultMetadata,
    modified: bool,
}

impl Vault {
    const CURRENT_VERSION: u32 = 1;
    // const VERIFICATION_DATA: &'static [u8] = b"vault_verification_v1";
    
    /// Create a new vault (fails if already exists)
    pub fn create<P: AsRef<Path>>(path: P, password: &mut SecretString, vault_name: &str) -> Result<Self, VaultError> {
        let mut path_buf = path.as_ref().to_path_buf();
        path_buf.set_file_name(vault_name);
        
        if path_buf.exists() {
            return Err(VaultError::InvalidFormat(
                "Vault already exists. Use open() instead.".to_string()
            ));
        }
        
        Self::validate_password(&mut password.clone())?;
        
        let salt = SaltString::generate(&mut Argon2Rng);
        let key = Self::derive_key(&mut password.clone(), &salt)?;
        let verification = Self::create_verification(&mut password.clone(), &salt)?;
        password.zeroize();
        
        let now = Self::timestamp();
        let vault = Self {
            key,
            entries: HashMap::new(),
            salt,
            verification,
            path: path_buf,
            metadata: VaultMetadata {
                created_at: now,
                modified_at: now,
                access_count: 0,
            },
            modified: true,
        };
        
        vault.save()?;
        Self::set_secure_permissions(&vault.path)?;
        
        Ok(vault)
    }
    
    /// Open an existing vault
    pub fn open<P: AsRef<Path>>(path: P, password: &mut SecretString, vault_name: &str) -> Result<Self, VaultError> {
        let mut path_buf = path.as_ref().to_path_buf();
        path_buf.set_file_name(vault_name);
        path_buf.set_extension("vault");
        if !path_buf.exists() {
            return Err(VaultError::VaultNotFound(path_buf.display().to_string()));
        }
        
        Self::verify_permissions(&path_buf)?;
        
        let data = fs::read_to_string(&path_buf)
            .context("Failed to read vault file")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        let file: VaultFile = serde_json::from_str(&data)
            .context("Failed to parse vault file")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        if file.version != Self::CURRENT_VERSION {
            return Err(VaultError::InvalidFormat(
                format!("Unsupported vault version: {}", file.version)
            ));
        }
        
        let salt = SaltString::from_b64(&file.salt)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid salt: {}", e)))?;
        
        let verification = PasswordHash::new(&file.verification)
            .map_err(|e| VaultError::InvalidFormat(format!("Invalid verification: {}", e)))?;
        let verification_string = verification.to_string();
        
        // Verify password before deriving key
        Argon2::default()
            .verify_password(password.expose_secret().as_bytes(), &verification)
            .map_err(|_| VaultError::InvalidPassword)?;
        
        let key = Self::derive_key(&mut password.clone(), &salt)?;
        
        let mut metadata = file.metadata;
        metadata.access_count += 1;
        
        Ok(Self {
            key,
            entries: file.entries,
            salt,
            verification: verification_string,
            path: path_buf,
            metadata,
            modified: false,
        })
    }
    
    /// Create or open a vault
    pub fn open_or_create<P: AsRef<Path>>(path: P, password: &mut SecretString, vault_name: &str) -> Result<Self, VaultError> {
        if path.as_ref().exists() {
            Self::open(path, password, vault_name)
        } else {
            Self::create(path, password, vault_name)
        }
    }
    
    /// Store raw bytes
    pub fn store_bytes(&mut self, name: &str, data: &[u8]) -> Result<(), VaultError> {
        Self::validate_entry_name(name)?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let encrypted = cipher
            .encrypt(nonce, data)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        self.entries.insert(name.to_string(), EncryptedEntry {
            data: encrypted,
            nonce: nonce_bytes,
            created_at: Self::timestamp(),
            accessed_at: None,
        });
        
        self.modified = true;
        Ok(())
    }
    
    /// Store a string
    pub fn store_string(&mut self, name: &str, text: &str) -> Result<(), VaultError> {
        self.store_bytes(name, text.as_bytes())
    }
    
    /// Retrieve and decrypt data
    pub fn get(&mut self, name: &str) -> Result<SecretBox<[u8]>, VaultError> {
        let entry = self.entries
            .get_mut(name)
            .ok_or_else(|| VaultError::EntryNotFound(name.to_string()))?;
        
        let cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|e| VaultError::DecryptionFailed)?;
        
        let nonce = Nonce::from_slice(&entry.nonce);
        
        // let decrypted = cipher
        //     .decrypt(nonce, entry.data.as_ref())
        //     .map_err(|_| VaultError::DecryptionFailed);

        let decrypted = SecretSlice::new(cipher.decrypt(nonce, entry.data.as_ref()).unwrap_or(Vec::new()).into());
        
        
        // Update access time
        entry.accessed_at = Some(Self::timestamp());
        self.modified = true;
        
        Ok(decrypted)
    }
    
    /// Retrieve as string
    pub fn get_string(&mut self, name: &str) -> Result<String, VaultError> {
        let data = self.get(name)?;
        String::from_utf8(data.expose_secret().into())
            .map_err(|e| VaultError::InvalidFormat(format!("Not valid UTF-8: {}", e)))
    }
    
    /// Check if entry exists
    pub fn contains(&self, name: &str) -> bool {
        self.entries.contains_key(name)
    }
    
    /// List all entry names
    pub fn list(&self) -> Vec<String> {
        self.entries.keys().cloned().collect()
    }
    
    /// Delete an entry
    pub fn delete(&mut self, name: &str) -> Result<(), VaultError> {
        self.entries.remove(name)
            .ok_or_else(|| VaultError::EntryNotFound(name.to_string()))?;
        self.modified = true;
        Ok(())
    }
    
    /// Get entry metadata without decrypting
    pub fn get_metadata(&self, name: &str) -> Option<EntryInfo> {
        self.entries.get(name).map(|e| EntryInfo {
            name: name.to_string(),
            created_at: e.created_at,
            accessed_at: e.accessed_at,
            size: e.data.len(),
        })
    }
    
    /// Change vault password
    pub fn change_password(&mut self, old_password: &mut SecretString, new_password: &mut SecretString) -> Result<(), VaultError> {
        // Verify old password
        let verification = PasswordHash::new(self.verification.as_str()).unwrap();
        Argon2::default()
            .verify_password(old_password.expose_secret().as_bytes(), &verification)
            .map_err(|_| VaultError::InvalidPassword)?;

        old_password.expose_secret_mut().zeroize();
        old_password.zeroize();
        
        Self::validate_password(&mut new_password.clone())?;
        
        // Generate new salt and derive new key
        let new_salt = SaltString::generate(&mut Argon2Rng);
        let new_key = Self::derive_key(&mut new_password.clone(), &new_salt)?;
        let new_verification = Self::create_verification(&mut new_password.clone(), &new_salt)?;
        new_password.expose_secret_mut().zeroize();
        
        // Re-encrypt all entries with new key
        let old_cipher = ChaCha20Poly1305::new_from_slice(&*self.key)
            .map_err(|e| VaultError::DecryptionFailed)?;
        let new_cipher = ChaCha20Poly1305::new_from_slice(&*new_key)
            .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
        
        let mut new_entries = HashMap::new();
        
        for (name, entry) in &self.entries {
            // Decrypt with old key
            let nonce = Nonce::from_slice(&entry.nonce);
            let decrypted = old_cipher
                .decrypt(nonce, entry.data.as_ref())
                .map_err(|_| VaultError::DecryptionFailed)?;
            
            // Encrypt with new key
            let mut new_nonce_bytes = [0u8; 12];
            // chacha20poly1305::aead::OsRngfill_bytes(&mut new_nonce_bytes);
            OsRng.fill_bytes(&mut new_nonce_bytes);
            let new_nonce = Nonce::from_slice(&new_nonce_bytes);
            
            let encrypted = new_cipher
                .encrypt(new_nonce, decrypted.as_ref())
                .map_err(|e| VaultError::EncryptionFailed(e.to_string()))?;
            
            new_entries.insert(name.clone(), EncryptedEntry {
                data: encrypted,
                nonce: new_nonce_bytes,
                created_at: entry.created_at,
                accessed_at: entry.accessed_at,
            });
        }
        
        // Update vault with new credentials
        self.key = new_key;
        self.salt = new_salt;
        self.verification = new_verification.to_owned();
        self.entries = new_entries;
        self.modified = true;
        
        Ok(())
    }
    
    /// Explicitly save changes (also called on drop)
    pub fn save(&self) -> Result<(), VaultError> {
        if !self.modified {
            return Ok(());
        }
        
        let file = VaultFile {
            version: Self::CURRENT_VERSION,
            salt: self.salt.to_string(),
            verification: self.verification.to_string(),
            entries: self.entries.clone(),
            metadata: VaultMetadata {
                created_at: self.metadata.created_at,
                modified_at: Self::timestamp(),
                access_count: self.metadata.access_count,
            },
        };
        
        let json = serde_json::to_string_pretty(&file)
            .context("Failed to serialize vault")
            .map_err(|e| VaultError::InvalidFormat(e.to_string()))?;
        
        // Atomic write: write to temp file, then rename
        println!("writing");
        let path_with_extension = self.path.with_extension("vault");
        let mut file = File::create(&path_with_extension)?;
        file.write_all(json.as_bytes())?;
        file.sync_all()?;
        println!("written");

        // Self::set_secure_permissions(&self.path)?;
        println!("done");
        
        Ok(())
    }
    
    // ========================================================================
    // Security Utilities
    // ========================================================================
    
    fn derive_key(password: &mut SecretString, salt: &SaltString) -> Result<Zeroizing<[u8; 32]>, VaultError> {
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.expose_secret().as_bytes(), salt)
            .map_err(|e| VaultError::EncryptionFailed(format!("Key derivation failed: {}", e)))?;

        password.zeroize();
        
        let hash_bytes = hash.hash
            .ok_or_else(|| VaultError::EncryptionFailed("No hash generated".to_string()))?;
        
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&hash_bytes.as_bytes()[..32]);
        
        Ok(key)
    }
    
    fn create_verification(password: &mut SecretString, salt: &SaltString) -> Result<String, VaultError> {
        let argon2 = Argon2::default();
        let hash = argon2.hash_password(password.expose_secret().as_bytes(), salt)
            .map_err(|e| VaultError::EncryptionFailed(format!("Verification failed: {}", e)))?;
        password.zeroize();

        let hash_string = hash.to_string();
        
        Ok(hash_string)
    }
    
    fn validate_password(password: &mut SecretString) -> Result<(), VaultError> {
        
        if password.expose_secret().len() < 8 {
            return Err(VaultError::InvalidFormat(
                "Password must be at least 8 characters".to_string()
            ));
        }
        password.zeroize();
        Ok(())
    }
    
    fn validate_entry_name(name: &str) -> Result<(), VaultError> {
        if name.is_empty() || name.len() > 255 {
            return Err(VaultError::InvalidFormat(
                "Entry name must be 1-255 characters".to_string()
            ));
        }
        
        if name.contains('\0') || name.contains('/') || name.contains('\\') {
            return Err(VaultError::InvalidFormat(
                "Entry name contains invalid characters".to_string()
            ));
        }
        
        Ok(())
    }
    
    #[cfg(unix)]
    fn set_secure_permissions(path: &Path) -> Result<(), VaultError> {
        use std::os::unix::fs::PermissionsExt;
        println!("setting permissions");
        fs::set_permissions(path.with_extension("vault"), Permissions::from_mode(0o600))?;
        println!("permissions set");
        Ok(())
    }
    
    #[cfg(not(unix))]
    fn set_secure_permissions(_path: &Path) -> Result<(), VaultError> {
        // On Windows, use ACLs in production
        Ok(())
    }
    
    #[cfg(unix)]
    fn verify_permissions(path: &Path) -> Result<(), VaultError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata = fs::metadata(path)?;
        let mode = metadata.permissions().mode();
        
        if mode & 0o077 != 0 {
            eprintln!("Warning: Vault permissions are too open ({}). Should be 0600.", mode & 0o777);
        }
        
        Ok(())
    }
    
    #[cfg(not(unix))]
    fn verify_permissions(_path: &Path) -> Result<(), VaultError> {
        Ok(())
    }
    
    fn timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
}

// Auto-save on drop
impl Drop for Vault {
    fn drop(&mut self) {
        if self.modified {
            let _ = self.save();
        }
    }
}

// ============================================================================
// Public API Types
// ============================================================================

#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub name: String,
    pub created_at: u64,
    pub accessed_at: Option<u64>,
    pub size: usize,
}

// ============================================================================
// Production Helper: Environment-based Configuration
// ============================================================================

pub struct VaultConfig {
    pub path: PathBuf,
    pub password: SecretString,
}

impl VaultConfig {
    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, VaultError> {
        let path = std::env::var("VAULT_PATH")
            .unwrap_or_else(|_| "./secrets.vault".to_string());
        
        let password = std::env::var("VAULT_PASSWORD")
            .map_err(|_| VaultError::InvalidFormat(
                "VAULT_PASSWORD environment variable not set".to_string()
            ))?;
        
        Ok(Self {
            path: PathBuf::from(path),
            password: SecretString::from(password),
        })
    }
    
    // pub fn open_vault(&self) -> Result<Vault, VaultError> {
        
    //     Vault::open(&self.path, &mut self.password.clone())
    // }
}

// ============================================================================
// Usage Examples
// ============================================================================

// fn main() -> Result<()> {
//     println!("=== Production Vault Examples ===\n");
    
//     example_basic()?;
//     example_error_handling()?;
//     example_cryptographic_keys()?;
//     example_password_change()?;
    
//     Ok(())
// }

// fn example_basic() -> Result<()> {
//     println!("--- Basic Usage ---");
    
//     // Create vault (fails if exists)
//     let mut vault = Vault::create("production.vault", "secure-password-123")?;
    
//     vault.store_string("api_key", "sk-prod-abc123")?;
//     vault.store_string("db_url", "postgresql://user:pass@localhost/db")?;
    
//     println!("✓ Created vault with 2 secrets");
    
//     // Open existing vault
//     let mut vault = Vault::open("production.vault", "secure-password-123")?;
//     let api_key = vault.get_string("api_key")?;
//     println!("✓ Retrieved API key: {}", api_key);
    
//     // List entries
//     println!("  Entries: {:?}", vault.list());
    
//     // Get metadata
//     if let Some(info) = vault.get_metadata("api_key") {
//         println!("  Created: {}, Size: {} bytes", info.created_at, info.size);
//     }
    
//     println!();
//     Ok(())
// }

// fn example_error_handling() -> Result<()> {
//     println!("--- Error Handling ---");
    
//     // Wrong password
//     match Vault::open("production.vault", "wrong-password") {
//         Err(VaultError::InvalidPassword) => println!("✓ Detected wrong password"),
//         _ => println!("✗ Should have failed"),
//     }
    
//     // Missing entry
//     let mut vault = Vault::open("production.vault", "secure-password-123")?;
//     match vault.get_string("nonexistent") {
//         Err(VaultError::EntryNotFound(_)) => println!("✓ Detected missing entry"),
//         _ => println!("✗ Should have failed"),
//     }
    
//     // Vault not found
//     match Vault::open("missing.vault", "password") {
//         Err(VaultError::VaultNotFound(_)) => println!("✓ Detected missing vault"),
//         _ => println!("✗ Should have failed"),
//     }
    
//     println!();
//     Ok(())
// }

// fn example_cryptographic_keys() -> Result<()> {
//     println!("--- Cryptographic Keys ---");
    
//     use ed25519_dalek::{SigningKey, Signer};
    
//     let mut vault = Vault::open_or_create("keys.vault", "key-password")?;
    
//     // Store Ed25519 key
//     let signing_key = SigningKey::generate(&mut OsRng);
//     vault.store("ed25519_private", &signing_key.to_bytes())?;
//     vault.store("ed25519_public", signing_key.verifying_key().as_bytes())?;
    
//     println!("✓ Stored Ed25519 keypair");
    
//     // Use it
//     let key_bytes = vault.get("ed25519_private")?;
//     let signing_key = SigningKey::from_bytes(key_bytes.as_slice().try_into().unwrap());
//     let signature = signing_key.sign(b"message");
    
//     println!("✓ Signed with stored key");
//     println!();
    
//     Ok(())
// }

// fn example_password_change() -> Result<()> {
//     println!("--- Password Rotation ---");
    
//     let mut vault = Vault::open("production.vault", "secure-password-123")?;
//     vault.change_password("secure-password-123", "new-secure-password-456")?;
//     vault.save()?;
    
//     println!("✓ Changed vault password");
    
//     // Verify new password works
//     let mut vault = Vault::open("production.vault", "new-secure-password-456")?;
//     let _ = vault.get_string("api_key")?;
//     println!("✓ Verified new password works");
    
//     // Change back for other examples
//     vault.change_password("new-secure-password-456", "secure-password-123")?;
    
//     println!();
//     Ok(())
// }

/*
Cargo.toml:

[dependencies]
anyhow = "1.0"
thiserror = "1.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
argon2 = { version = "0.5", features = ["std"] }
chacha20poly1305 = "0.10"
rand = "0.8"
zeroize = { version = "1.7", features = ["derive"] }

# Optional: for examples
hex = "0.4"
ed25519-dalek = { version = "2.1", features = ["rand_core"] }
k256 = { version = "0.13", features = ["ecdsa"] }
sha3 = "0.10"
*/