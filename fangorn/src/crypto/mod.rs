use sp_core::crypto::KeyTypeId;

pub mod cipher;
pub mod keystore;

// fangorn key type
pub const FANGORN: KeyTypeId = KeyTypeId(*b"fang");
