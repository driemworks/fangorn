use sp_core::crypto::KeyTypeId;

pub mod cipher;
pub mod decrypt;
pub mod encrypt;
pub mod keystore;
pub mod vault;

// fangorn key type
pub const FANGORN: KeyTypeId = KeyTypeId(*b"fang");
