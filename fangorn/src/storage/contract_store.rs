use super::*;
use crate::{
    backend::{BlockchainBackend, SubstrateBackend},
    gadget::Intent,
};
use async_trait::async_trait;
use cid::Cid;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder};
use sp_application_crypto::Ss58Codec;
use sp_core::Pair;
use sp_weights::Weight;
use std::sync::Arc;
use subxt::ext::codec::Encode;
use subxt::{
    config::polkadot::AccountId32, dynamic, utils::MultiAddress, OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::{dev, Keypair};

pub struct ContractIntentStore {
    contract_address: String,
    backend: Arc<dyn BlockchainBackend>,
}

impl ContractIntentStore {
    pub fn new(contract_address: String, backend: Arc<dyn BlockchainBackend>) -> Self {
        Self {
            contract_address,
            backend,
        }
    }
}

#[async_trait]
impl IntentStore for ContractIntentStore {
    async fn register_intent(&self, filename: &[u8], cid: &Cid, intent: Vec<Intent>) -> Result<()> {
        let filename = filename.to_vec();
        let cid_bytes = cid.to_bytes().to_vec();
        // convert vec of intents to bytes (scale encoded)
        let intent_bytes = intent.encode();

        let selector = self.backend.selector("register");

        let mut data = Vec::new();
        data.extend(filename.encode());
        data.extend(cid_bytes.encode());
        data.extend(intent_bytes.encode());

        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .call_contract(contract_addr_bytes, selector, data)
            .await?;

        Ok(())
    }

    async fn get_intent(&self, filename: &[u8]) -> Result<Option<(Cid, Vec<Intent>)>> {
        use subxt::ext::codec::Decode;

        let selector = self.backend.selector("read");

        let mut data = Vec::new();
        data.extend(filename.to_vec().encode());

        let contract_addr_bytes: [u8; 32] =
            crate::utils::decode_contract_addr(&self.contract_address);

        let result = self
            .backend
            .query_contract(contract_addr_bytes, selector, data)
            .await?;

        // TODO: use the same struct here and in the contract, exactly
        #[derive(Decode, Debug)]
        struct Entry {
            cid: Vec<u8>,
            intent: Vec<u8>,
        }

        let mut data = result;
        if !data.is_empty() {
            data.remove(0);
        }

        let decoded = <Option<Entry>>::decode(&mut &data[..])?;

        let result = decoded.map(|entry| {
            let intents: Vec<Intent> = Vec::<Intent>::decode(&mut &entry.intent[..]).unwrap();
            (Cid::try_from(entry.cid).expect("Invalid CID"), intents)
        });

        Ok(result)
    }

    async fn remove_intent(&self, filename: &[u8]) -> Result<()> {
        let mut data = Vec::new();
        data.extend(filename.to_vec().encode());

        let selector = self.backend.selector("remove");

        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .call_contract(contract_addr_bytes, selector, data)
            .await?;

        Ok(())
    }
}
