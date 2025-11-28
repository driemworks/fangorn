use super::*;
use crate::{backend::substrate::ContractBackend, gadget::Intent};
use async_trait::async_trait;
use cid::Cid;
use std::sync::Arc;
use subxt::{config::substrate::AccountId32, ext::codec::Encode};

#[derive(Clone)]
pub struct ContractIntentStore {
    contract_address: String,
    backend: Arc<dyn ContractBackend>,
}

impl ContractIntentStore {
    pub fn new(contract_address: String, backend: Arc<dyn ContractBackend>) -> Self {
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

        let selector = "register_predicate";

        let mut data = Vec::new();
        data.extend(filename.encode());
        data.extend(cid_bytes.encode());
        data.extend(intent_bytes.encode());

        // TODO: clean this up, it's used all over rn
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .write(
                &AccountId32(contract_addr_bytes),
                &selector.to_string(),
                &data,
            )
            .await?;

        Ok(())
    }

    async fn get_intent(&self, filename: &[u8]) -> Result<Option<(Cid, Vec<Intent>)>> {
        use subxt::ext::codec::Decode;

        let method = "read";

        let mut data = Vec::new();
        data.extend(filename.to_vec().encode());
        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);
        let result = self
            .backend
            .read(
                &AccountId32(contract_addr_bytes),
                &method.to_string(),
                Some(data),
            )
            .await?;

        // TODO: use the same struct here and in the contract, exactly
        #[derive(Decode, Debug)]
        struct Entry {
            cid: Vec<u8>,
            intent: Vec<u8>,
        }

        // todo
        let mut data = result.unwrap();
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

        let selector = "remove_predicate";

        let contract_addr_bytes = crate::utils::decode_contract_addr(&self.contract_address);

        self.backend
            .write(
                &AccountId32(contract_addr_bytes),
                &selector.to_string(),
                &data,
            )
            .await?;

        Ok(())
    }
}
