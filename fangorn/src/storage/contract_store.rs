use super::*;
use crate::gadget::Intent;
use async_trait::async_trait;
use cid::Cid;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder};
use sp_core::Pair;
use sp_weights::Weight;
use subxt::ext::codec::Encode;
use subxt::{
    OnlineClient, PolkadotConfig, config::polkadot::AccountId32, dynamic, utils::MultiAddress,
};
use subxt_signer::sr25519::{Keypair, dev};

#[subxt::subxt(runtime_metadata_path = "../fangorn/src/storage/metadata.scale")]
pub mod runtime {}

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

        let call = runtime::tx().contracts().call(
            MultiAddress::Id(self.contract_address.clone()),
            0u128, // value
            runtime::runtime_types::sp_weights::weight_v2::Weight {
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

        let mut data = Self::selector("read").to_vec();
        data.extend(filename.to_vec().encode());

        let call_request = runtime::apis().contracts_api().call(
            self.signer.public_key().into(),
            self.contract_address.clone(),
            0u128,
            None,
            None,
            data,
        );

        let result = self
            .client
            .runtime_api()
            .at_latest()
            .await?
            .call(call_request)
            .await?;

        match result.result {
            Ok(exec_result) => {
                // TODO: use the same struct here and in the contract, exactly
                #[derive(Decode, Debug)]
                struct Entry {
                    cid: Vec<u8>,
                    intent: Vec<u8>,
                }

                let mut data = exec_result.data;
                data.remove(0);
                let decoded = <Option<Entry>>::decode(&mut &data[..])?;

                Ok(decoded.map(|entry| {
                    (
                        Cid::try_from(entry.cid).expect("Invalid CID"),
                        entry.intent.into(),
                    )
                }))
            }
            Err(e) => Err(anyhow::anyhow!("Contract call failed: {:?}", e)),
        }
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
