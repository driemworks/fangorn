use super::*;
use crate::entish::intents::Intent;
use async_trait::async_trait;
use cid::Cid;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder};
use sp_core::Pair;
use sp_weights::Weight;
use subxt::ext::codec::Encode;
use subxt::{
    config::polkadot::AccountId32, dynamic, utils::MultiAddress, OnlineClient, PolkadotConfig,
};
use subxt_signer::sr25519::{dev, Keypair};

#[subxt::subxt(runtime_metadata_path = "../fangorn/src/storage/metadata.scale")]
pub mod idn {}

pub struct ContractIntentStore {
    client: OnlineClient<PolkadotConfig>,
    rpc_url: String,
    contract_address: AccountId32,
    signer: Keypair,
}

impl ContractIntentStore {
    pub async fn new(
        rpc_url: String,
        contract_address: [u8; 32],
        seed: Option<&str>,
    ) -> Result<Self> {
        let client = OnlineClient::<PolkadotConfig>::from_url(&rpc_url).await?;
        // .map_err(|_| anyhow::anyhow!("Invalid secret key length"))?;
        // let secret_key: [u8; 32] = keypair_bytes[..32].try_into().unwrap();

        // default to alice if no signer is provided
        let mut signer = dev::alice();

        if let Some(raw) = seed {
            let pair = sp_core::sr25519::Pair::from_string(raw, None).unwrap();
            // .map_err(|e| anyhow::anyhow!("Failed to create pair: {:?}", e))?;

            // Convert to subxt Keypair
            let keypair_bytes: [u8; 64] = pair.to_raw_vec().try_into().unwrap();
            let mnemonic = bip39::Mnemonic::parse(raw).unwrap();
            signer = Keypair::from_phrase(&mnemonic, None).unwrap();
        }

        Ok(Self {
            client,
            rpc_url,
            contract_address: AccountId32::from(contract_address),
            signer,
        })
    }

    fn selector(name: &str) -> [u8; 4] {
        use sp_core_hashing::blake2_256;
        let hash = blake2_256(name.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }

    fn cid_to_filename(&self, cid: &Cid) -> Vec<u8> {
        cid.to_string().into_bytes()
    }
}

use sp_application_crypto::Ss58Codec;

#[async_trait]
impl IntentStore for ContractIntentStore {
    async fn register_intent(&self, filename: &[u8], cid: &Cid, intent: &Intent) -> Result<()> {
        let filename = filename.to_vec();
        let cid_bytes = cid.to_bytes().to_vec();
        let intent_bytes = intent.to_bytes();

        let mut data = Self::selector("register").to_vec();
        data.extend(filename.encode());
        data.extend(cid_bytes.encode());
        data.extend(intent_bytes.encode());

        let call = idn::tx().contracts().call(
            MultiAddress::Id(self.contract_address.clone()),
            0u128, // value
            idn::runtime_types::sp_weights::weight_v2::Weight {
                ref_time: 1_000_000_000,
                proof_size: 500_000,
            },
            None, // storage_deposit_limit
            data,
        );

        let tx = self
            .client
            .tx()
            .sign_and_submit_then_watch_default(&call, &self.signer)
            .await?;

        let result = tx.wait_for_finalized_success().await?;

        Ok(())
    }

    async fn get_intent(&self, filename: &[u8]) -> Result<Option<(Cid, Intent)>> {
        use subxt::ext::codec::Decode;

        // Prepare the contract call data
        let mut data = Self::selector("read").to_vec();
        data.extend(filename.to_vec().encode());

        // Use jsonrpsee to call the contract (this is the standard way)
        let http_url = self.rpc_url.replace("ws://", "http://").replace("wss://", "https://");
        let http_client = HttpClientBuilder::default().build(&http_url)?;

        let result: serde_json::Value = http_client
            .request(
                "contracts_call",
                (
                    format!("0x{}", hex::encode::<&[u8]>(self.contract_address.as_ref())),
                    format!("0x{}", hex::encode::<&[u8]>(&data)),
                    0u128,
                    Option::<u64>::None,
                    Option::<u128>::None,
                ),
            )
            .await?;

        // Extract and decode the result
        let data_hex = result["result"]["Ok"]["data"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Contract call failed: {:?}", result))?;

        let data_bytes = hex::decode(data_hex.trim_start_matches("0x"))?;

        // Decode the Option<Entry> from your contract
        #[derive(Decode)]
        struct Entry {
            cid: Vec<u8>,
            intent: Vec<u8>,
        }

        let decoded = <Option<Entry>>::decode(&mut &data_bytes[..])?;

        Ok(decoded.map(|entry| {
            (
                Cid::try_from(entry.cid).expect("Invalid CID"),
                entry.intent.into(),
            )
        }))
    }

    async fn remove_intent(&self, filename: &[u8]) -> Result<()> {
        let filename = filename.to_vec();
        let mut data = Self::selector("remove").to_vec();
        data.extend(filename.encode());

        let call = dynamic::tx(
            "Contracts",
            "call",
            vec![
                dynamic::Value::from_bytes(&self.contract_address),
                dynamic::Value::u128(1),
                dynamic::Value::unnamed_composite([
                    dynamic::Value::u128(10_000_000_000),
                    dynamic::Value::u128(1_000_000),
                ]),
                dynamic::Value::unnamed_composite([]),
                dynamic::Value::from_bytes(&data),
            ],
        );

        let tx = self
            .client
            .tx()
            .sign_and_submit_then_watch_default(&call, &self.signer)
            .await?;

        let result = tx.wait_for_finalized_success().await?;

        // println!("Intent removed in block: {:?}", result.block_hash());
        Ok(())
    }
}
