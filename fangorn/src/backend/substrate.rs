//! Substrate-specific blockchain backend
use crate::crypto::keyvault::Sr25519KeyVault;

use super::Backend;
use anyhow::Result;
use async_trait::async_trait;
use subxt::{config::polkadot::AccountId32, utils::MultiAddress, OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::{dev, Keypair};

#[subxt::subxt(runtime_metadata_path = "../fangorn/src/storage/metadata.scale")]
pub mod runtime {}

/// a backend config that supports ink contracts on a substrate based chain
pub trait ContractBackend: Backend<AccountId32, String, Vec<u8>> {}

#[derive(Clone, Debug)]
pub struct SubstrateBackend {
    client: OnlineClient<PolkadotConfig>,
    signer: Keypair,
    // sr25519_vault: Sr25519KeyVault,
}

impl SubstrateBackend {
    // todo: this should use the keystore instead
    pub async fn new(rpc_url: String, seed: Option<&str>) -> Result<Self> {
        let client = OnlineClient::<PolkadotConfig>::from_url(&rpc_url).await?;
        // let sr25519_vault = Sr25519KeyVault::new();
        // sr_vault.get("Node0_sr25519_key")

        let signer = if let Some(raw) = seed {
            let mnemonic = bip39::Mnemonic::parse(raw)?;
            Keypair::from_phrase(&mnemonic, None)?
        } else {
            // default to alice for now
            // should probably use a feature for this
            dev::alice()
        };

        Ok(Self { client, signer })
    }

    pub fn update_signer(&mut self, signer: Keypair) {
        self.signer = signer;
    }
}

impl SubstrateBackend {
    pub async fn nonce(&self, pubkey: [u8; 32]) -> Result<u32> {
        let acct_id = AccountId32(pubkey);
        // query system > account
        let account_storage = runtime::storage().system().account(acct_id);
        let account_info = self
            .client
            .storage()
            .at_latest()
            .await?
            .fetch(&account_storage)
            .await?
            .unwrap();

        // decode the nonce
        let nonce = account_info.nonce;
        Ok(nonce.try_into().unwrap_or_else(|_| {
            // unlikely, but if the nonce exceeds u32::Max then no more calls can be made
            eprintln!("Warning: Nonce value {} truncated to u32::MAX.", nonce);
            u32::MAX
        }))
    }

    /// Create method selector from method name
    fn selector(&self, name: &str) -> [u8; 4] {
        use sp_core_hashing::blake2_256;
        let hash = blake2_256(name.as_bytes());
        [hash[0], hash[1], hash[2], hash[3]]
    }
}

impl ContractBackend for SubstrateBackend {}

#[async_trait]
impl Backend<AccountId32, String, Vec<u8>> for SubstrateBackend {
    async fn read(
        &self,
        contract_address: &AccountId32,
        method: &String,
        data: Option<Vec<u8>>, // does this really need to be an option? probably not
    ) -> Result<Option<Vec<u8>>> { // same here, doesn't need to return an option
        // call_data = selector || call_data
        let mut call_data = self.selector(method).to_vec();
        if let Some(data) = data {
            call_data.extend(data);
        }

        // queries are gasless
        let call_request = runtime::apis().contracts_api().call(
            self.signer.public_key().into(),
            contract_address.clone(),
            0u128,
            None,
            None,
            call_data,
        );

        let result = self
            .client
            .runtime_api()
            .at_latest()
            .await?
            .call(call_request)
            .await?;

        match result.result {
            Ok(exec_result) => Ok(Some(exec_result.data)),
            Err(e) => Err(anyhow::anyhow!("Contract query failed: {:?}", e)),
        }
    }

    async fn write(
        &self,
        contract_address: &AccountId32,
        method: &String,
        data: &Vec<u8>,
    ) -> Result<Vec<u8>> {
        // call_data = selector || data
        let mut call_data = self.selector(method).to_vec();
        call_data.extend(data);

        let call = runtime::tx().contracts().call(
            MultiAddress::Id(contract_address.clone()), // does this really need the outer multiaddress?
            0u128,
            // TODO: proper gas estimation and tracking
            runtime::runtime_types::sp_weights::weight_v2::Weight {
                ref_time: 10_000_000_000,
                proof_size: 500_000,
            },
            None,
            call_data,
        );

        let tx = self
            .client
            .tx()
            .sign_and_submit_then_watch_default(&call, &self.signer)
            .await?;

        let result = tx.wait_for_finalized_success().await?;
        Ok(result.extrinsic_hash().0.to_vec())
    }
}
