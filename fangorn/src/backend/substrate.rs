//! Substrate-specific blockchain backend
use super::BlockchainBackend;
use anyhow::Result;
use async_trait::async_trait;
use subxt::{config::polkadot::AccountId32, utils::MultiAddress, OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::{dev, Keypair};

#[subxt::subxt(runtime_metadata_path = "../fangorn/src/storage/metadata.scale")]
pub mod runtime {}

#[derive(Debug)]
pub struct SubstrateBackend {
    client: OnlineClient<PolkadotConfig>,
    signer: Keypair,
}

impl SubstrateBackend {
    pub async fn new(rpc_url: String, seed: Option<&str>) -> Result<Self> {
        let client = OnlineClient::<PolkadotConfig>::from_url(&rpc_url).await?;

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
}

#[async_trait]
impl BlockchainBackend for SubstrateBackend {
    async fn nonce(&self) -> Result<u32> {
        let acct_id = AccountId32(self.signer.public_key().0);
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

    async fn query_contract(
        &self,
        contract_address: [u8; 32],
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // call_data = selector || data
        let mut call_data = method_selector.to_vec();
        call_data.extend(data);

        let call_request = runtime::apis().contracts_api().call(
            self.signer.public_key().into(),
            AccountId32(contract_address),
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
            Ok(exec_result) => Ok(exec_result.data),
            Err(e) => Err(anyhow::anyhow!("Contract query failed: {:?}", e)),
        }
    }

    async fn call_contract(
        &self,
        contract_address: [u8; 32],
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // call_data = selector || data
        let mut call_data = method_selector.to_vec();
        call_data.extend(data);

        let call = runtime::tx().contracts().call(
            MultiAddress::Id(AccountId32(contract_address)),
            0u128,
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
