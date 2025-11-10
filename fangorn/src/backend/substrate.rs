//! Substrate-specific blockchain backend

use super::BlockchainBackend;
use anyhow::Result;
use async_trait::async_trait;
use subxt::{OnlineClient, PolkadotConfig, config::polkadot::AccountId32, utils::MultiAddress};
use subxt_signer::sr25519::{Keypair, dev};

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
            dev::alice()
        };

        Ok(Self { client, signer })
    }

    // fn parse_contract_address(&self, address: &str) -> Result<AccountId32> {
    //     // Assume hex-encoded address for now
    //     let bytes: [u8; 32] = hex::decode(address)?
    //         .try_into()
    //         .map_err(|_| anyhow::anyhow!("Invalid address length"))?;
    //     Ok(AccountId32::from(bytes))
    // }
}

#[async_trait]
impl BlockchainBackend for SubstrateBackend {
    async fn query_contract(
        &self,
        contract_address: [u8; 32],
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        // let address = crate::utils::decode_contract_addr(contract_address);

        // Prepend selector to data
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
        contract_address: &str,
        method_selector: [u8; 4],
        data: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let address = crate::utils::decode_contract_addr(contract_address);

        // Prepend selector to data
        let mut call_data = method_selector.to_vec();
        call_data.extend(data);

        let call = runtime::tx().contracts().call(
            MultiAddress::Id(AccountId32(address)),
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

        // Return extrinsic hash as confirmation
        Ok(result.extrinsic_hash().0.to_vec())
    }
}
