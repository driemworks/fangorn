use anyhow::Result;
use async_trait::async_trait;

pub mod iroh;
pub use iroh::IrohBackend;

pub mod substrate;
pub use substrate::SubstrateBackend;

/// A generic blockchain backend for querying and calling contracts
/// TODO: if call_contract takes in weights + stuff as a param, we don't need query_contract
/// then we can  impl a dry_run/query function to determine min gas needed
/// Generic key-value backend with contract-like semantics
#[async_trait]
pub trait Backend<L, K, V>: Send + Sync {
    
    /// Read data by key
    /// 
    /// * `loc`: the location to read from
    /// * `key`: the key
    /// * `extras`: optional extra data
    async fn read(&self, loc: &L, key: &K, extras: Option<V>) -> Result<Option<Vec<u8>>>;
    
    /// Write a (key, value) pair to the backend
    /// output some attestation that it completed
    async fn write(&self, loc: &L, key: &K, value: &V) -> Result<Vec<u8>>;
    
    // /// List all keys (for pool enumeration)
    // async fn list_keys(&self) -> Result<Vec<Vec<u8>>>;
    
    // /// Delete a value by key
    // async fn delete(&self, key: &K) -> Result<()>;
}
