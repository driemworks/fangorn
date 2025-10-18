use super::*;
use async_trait::async_trait;

pub struct ContractPolicyStore {
    // the contract address
    pub address: Vec<u8>,
}

#[async_trait]
impl PolicyStore for ContractPolicyStore {
    async fn get_policy(&self, cid: &CID) -> Result<Option<Policy>> {
        Ok(None)
    }

    async fn register_policy(&self, cid: CID, policy: Policy) -> Result<()> {
        Ok(())
    }
    
    async fn kill_policy(&self,  cid: &CID) -> Result<()> {
        Ok(())
    }
}