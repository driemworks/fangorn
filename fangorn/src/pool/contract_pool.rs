use super::*;
use crate::backend::Backend;
use crate::pool::pool::*;
use anyhow::Result;
use codec::{Decode, Encode};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

pub struct InkContractPool {
    contract_address: String,
    backend: Arc<dyn Backend>,
}

impl InkContractPool {
    pub fn new(contract_address: String, backend: Arc<dyn Backend>) -> Self {
        Self {
            contract_address,
            backend,
        }
    }
}

#[async_trait]
impl RequestPool for InkContractPool {
    /// add a new message
    async fn add(&mut self, req: DecryptionRequest) -> Result<()> {
        let input = req.encode();
        let selector = self.backend.selector("add");
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .call_contract(contract_addr_bytes, selector, input)
            .await?;

        Ok(())
    }

    /// read all messages (unordered pool)
    async fn read_all(&self) -> Result<Vec<DecryptionRequest>> {
        // TODO: we should pass the selector string and contract_addr to the  query/call functions
        let selector = self.backend.selector("read_all");
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);
        let result = self
            .backend
            .query_contract(contract_addr_bytes, selector, vec![])
            .await?;

        let mut data = result;
        if !data.is_empty() {
            // remove the prefix
            data.remove(0);
        }

        let decoded = <Vec<DecryptionRequest>>::decode(&mut &data[..])?;

        Ok(decoded)
    }

    /// Get the total count of messages
    async fn count(&self) -> Result<usize> {
        let selector = self.backend.selector("count");
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);
        let result = self
            .backend
            .query_contract(contract_addr_bytes, selector, vec![])
            .await?;

        let mut data = result;
        if !data.is_empty() {
            // remove the prefix
            data.remove(0);
        }

        let decoded = u64::decode(&mut &data[..])?;
        Ok(decoded as usize)
    }

    /// submit evidence that a worker has processed a work item
    async fn submit_partial_attestation(&self, id: &[u8], attestation: &[u8]) -> Result<()> {
        let mut data = id.encode();
        data.extend(attestation.encode());

        let selector = self.backend.selector("submit_partial_decryption");
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .call_contract(contract_addr_bytes, selector, data)
            .await?;

        Ok(())
    }
}