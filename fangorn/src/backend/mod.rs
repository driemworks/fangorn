use anyhow::Result;
use async_trait::async_trait;

pub mod substrate;
pub use substrate::SubstrateBackend;

/// Generic blockchain backend for querying and calling contracts
#[async_trait]
pub trait BlockchainBackend: Send + Sync + std::fmt::Debug {
    /// Query a contract
    /// Returns the raw response bytes from the contract
    async fn query_contract(
        &self,
        contract_address: [u8; 32],
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>>;

    /// Call a contract
    /// Returns transaction hash or confirmation
    async fn call_contract(
        &self,
        contract_address: &str,
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>>;

    /// Helper to create method selector from method name
    fn selector(&self, name: &str) -> [u8; 4] {
        use sp_core_hashing::blake2_256;
        let hash = blake2_256(name.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }
}
