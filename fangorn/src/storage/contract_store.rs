use super::*;
use crate::entish::intents::Intent;
use async_trait::async_trait;
use cid::Cid;
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder};
use sp_core::{crypto::AccountId32, Pair};
use subxt::ext::codec::Encode;
use subxt::{dynamic, OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::{dev, Keypair};

pub struct ContractIntentStore {
    client: OnlineClient<PolkadotConfig>,
    rpc_url: String,
    contract_address: AccountId32,
    signer: Keypair,
}

impl ContractIntentStore {
    pub async fn new(rpc_url: String, contract_address: [u8; 32], seed: &str) -> Result<Self> {
        let client = OnlineClient::<PolkadotConfig>::from_url(&rpc_url).await?;

        let pair = sp_core::sr25519::Pair::from_string(seed, None).unwrap();
        // .map_err(|e| anyhow::anyhow!("Failed to create pair: {:?}", e))?;

        // Convert to subxt Keypair
        let keypair_bytes: [u8; 64] = pair.to_raw_vec().try_into().unwrap();
        // .map_err(|_| anyhow::anyhow!("Invalid secret key length"))?;
        let secret_key: [u8; 32] = keypair_bytes[..32].try_into().unwrap();

        let signer = Keypair::from_secret_key(secret_key).unwrap();
        // .map_err(|e| anyhow::anyhow!("Failed to create signer: {:?}", e))?;

        // let signer = dev::alice();

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

#[async_trait]
impl IntentStore for ContractIntentStore {
    async fn register_intent(&self, cid: &Cid, intent: &Intent) -> Result<()> {
        // derive the filename on the fly for now...
        // realistically this shoud be determined by the user though
        let filename = self.cid_to_filename(cid);
        let cid_bytes = cid.to_bytes().to_vec();
        let intent_bytes = intent.to_bytes();

        let mut data = Self::selector("register").to_vec();
        data.extend(filename.encode());
        data.extend(cid_bytes.encode());
        data.extend(intent_bytes.encode());

        let call = dynamic::tx(
            "Contracts",
            "call",
            vec![
                // 0: dest
                dynamic::Value::unnamed_variant(
                    "Id",
                    [dynamic::Value::from_bytes(self.contract_address.clone())],
                ),
                // 1: value
                dynamic::Value::u128(0),
                // 2: gas limit
                dynamic::Value::unnamed_composite([
                    dynamic::Value::u128(10_000_000_000),
                    dynamic::Value::u128(5_000_000),
                ]),
                // 3: storage deposit limit
                dynamic::Value::unnamed_variant("None", []),
                // 4: input data
                dynamic::Value::from_bytes(&data),
            ],
        );

        let tx = self
            .client
            .tx()
            .sign_and_submit_then_watch(&call, &self.signer, Default::default())
            .await?;

        let result = tx.wait_for_finalized_success().await?;

        // println!("Intent registered in block: {:?}", result.block_hash());
        Ok(())
    }

    async fn get_intent(&self, cid: &Cid) -> Result<Option<Intent>> {
        use subxt::ext::codec::Decode;

        let filename = self.cid_to_filename(cid);
        let mut data = Self::selector("read").to_vec();
        data.extend(filename.encode());

        let http_client = HttpClientBuilder::default().build(&self.rpc_url)?;

        // Use tuple approach - simpler and works
        let result: serde_json::Value = http_client
            .request(
                "contracts_call",
                (
                    format!("0x{}", hex::encode(self.contract_address.as_ref() as &[u8])),
                    format!("0x{}", hex::encode(&data)),
                    0u128,
                    Option::<u64>::None,
                    Option::<u128>::None,
                ),
            )
            .await?;

        if let Some(output) = result.get("result").and_then(|r| r.get("Ok")) {
            if let Some(data_hex) = output.get("data").and_then(|d| d.as_str()) {
                let data_bytes = hex::decode(data_hex.trim_start_matches("0x"))?;

                if let Ok(Some((_, intent_bytes))) =
                    <Option<(Vec<u8>, Vec<u8>)>>::decode(&mut &data_bytes[..])
                {
                    let intent: Intent = intent_bytes.into();
                    return Ok(Some(intent));
                }
            }
        }

        Ok(None)
    }

    async fn remove_intent(&self, cid: &Cid) -> Result<()> {
        let filename = self.cid_to_filename(cid);
        let mut data = Self::selector("remove").to_vec();
        data.extend(filename.encode());

        let call = dynamic::tx(
            "Contracts",
            "call",
            vec![
                dynamic::Value::from_bytes(&self.contract_address),
                dynamic::Value::u128(0),
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
