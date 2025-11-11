use anyhow::Result;
use async_trait::async_trait;

pub mod substrate;
pub use substrate::SubstrateBackend;

/// A generic blockchain backend for querying and calling contracts
/// TODO: if call_contract takes in weights + stuff as a param, we don't need query_contract
/// then we can  impl a dry_run/query function to determine min gas needed
#[async_trait]
pub trait BlockchainBackend: Send + Sync + std::fmt::Debug {

    /// Fetch the latest nonce from the runtime for the configured signer
    async fn nonce(&self) -> Result<u32>;

    /// Query contract storage (getters)
    async fn query_contract(
        &self,
        contract_address: [u8; 32],
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>>;

    /// Call a contract
    async fn call_contract(
        &self,
        contract_address: [u8;32],
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>>;

    /// Create method selector from method name
    fn selector(&self, name: &str) -> [u8; 4] {
        use sp_core_hashing::blake2_256;
        let hash = blake2_256(name.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }
}
