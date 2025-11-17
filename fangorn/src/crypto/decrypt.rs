use crate::{
    rpc::server::{PartDecRequest, RpcClient},
    storage::*,
    types::*,
};
use anyhow::Result;
use ark_serialize::CanonicalDeserialize;
use codec::Encode;
use silent_threshold_encryption::{
    aggregate::{AggregateKey, SystemPublicKeys},
    decryption::agg_dec,
    setup::PartialDecryption,
    types::Ciphertext,
};
use std::fs;
use thiserror::Error;

const MAX_COMMITTEE_SIZE: usize = 3;

#[derive(Error, Debug)]
pub enum DecryptionClientError {
    #[error("An error occurred while communicating with the docstore: {0}")]
    DocstoreError(String),
    #[error("An error occurred while communicating with the intent store: {0}")]
    IntentStoreError(String),
    #[error("Decryption failed: {0}")]
    DecryptionError(String),
    #[error("Serialization failed")]
    SerializationError,
    #[error("Deserialization failed")]
    DeserializationError,
    #[error("RPC communication error: {0}")]
    RpcError(String),
    #[error("Hex decoding error: {0}")]
    DecodingError(String),
    #[error("Failed to read config: {0}")]
    ConfigReadError(String),
    #[error("Failed to write plaintext: {0}")]
    PlaintextWriteError(String),
    #[error("Intent not found for filename: {0}")]
    IntentNotFound(String),
    #[error("Ciphertext not found")]
    CiphertextNotFound,
}

pub struct DecryptionClient<D: DocStore, I: IntentStore, P: PlaintextStore> {
    config: Config<E>,
    // the Fangorn system keys for the given universe
    // at some point we will want to enable 'multiverse' support
    // and will need to revisit this
    system_keys: SystemPublicKeys<E>,
    // the threshold of shares we need to decrypt
    threshold: u8,
    // the app store
    app_store: AppStore<D, I, P>,
}

impl<D: DocStore, I: IntentStore, P: PlaintextStore> DecryptionClient<D, I, P> {
    pub fn new(
        config_path: &str,
        system_keys: SystemPublicKeys<E>,
        app_store: AppStore<D, I, P>,
    ) -> Result<Self, DecryptionClientError> {
        let config_hex = fs::read_to_string(config_path)
            .map_err(|e| DecryptionClientError::ConfigReadError(e.to_string()))?;
        let config_bytes = hex::decode(&config_hex)
            .map_err(|e| DecryptionClientError::DecodingError(e.to_string()))?;
        let config = Config::<E>::deserialize_compressed(&config_bytes[..])
            .map_err(|_| DecryptionClientError::DeserializationError)?;

        Ok(Self {
            config,
            app_store,
            system_keys,
            threshold: 1, // just hardcoded to 1 for now, easy
        })
    }

    pub async fn decrypt(
        &self,
        filename: &str,
        witnesses: &[&str],
        output_filename: &String,
    ) -> Result<Vec<u8>, DecryptionClientError> {
        // fetch ciphertext
        // todo: use intents for verification?
        let (cid, _intents) = self
            .app_store
            .intent_store
            .get_intent(filename.as_bytes())
            .await
            .map_err(|e| DecryptionClientError::IntentStoreError(e.to_string()))?
            .ok_or_else(|| DecryptionClientError::IntentNotFound(filename.to_string()))?;

        let ciphertext_bytes = self
            .app_store
            .doc_store
            .fetch(&cid)
            .await
            .map_err(|e| DecryptionClientError::DocstoreError(e.to_string()))?
            .ok_or(DecryptionClientError::CiphertextNotFound)?;

        let ciphertext = Ciphertext::<E>::deserialize_compressed(&ciphertext_bytes[..])
            .map_err(|_| DecryptionClientError::DeserializationError)?;

        // prepare witnesses
        let witness_hex = self.encode_witnesses(witnesses)?;

        let subset = vec![0, self.threshold as usize];
        let (ak, _ek) =
            self.system_keys
                .get_aggregate_key(&subset, &self.config.crs, &self.config.lag_polys);

        // collect partial decryptions
        let partial_decryptions = self
            .collect_partial_decryptions(filename, &witness_hex, &ak)
            .await?;

        // decrypt
        let plaintext = self.aggregate_decrypt(&partial_decryptions, &ciphertext, &ak)?;

        // write plaintext to store
        self.app_store
            .pt_store
            .write_to_pt_store(output_filename, &plaintext)
            .await
            .map_err(|e| DecryptionClientError::PlaintextWriteError(e.to_string()))?;

        Ok(plaintext)
    }

    fn encode_witnesses(&self, witnesses: &[&str]) -> Result<String, DecryptionClientError> {
        let witness_bytes: Vec<Vec<u8>> = witnesses.iter().map(|w| w.as_bytes().to_vec()).collect();

        Ok(hex::encode(witness_bytes.encode()))
    }

    async fn collect_partial_decryptions(
        &self,
        filename: &str,
        witness_hex: &str,
        ak: &AggregateKey<E>,
    ) -> Result<Vec<PartialDecryption<E>>, DecryptionClientError> {
        let mut partial_decryptions = vec![PartialDecryption::zero(); ak.lag_pks.len()];

        // TODO: make this configurable/dynamic based on threshold
        for i in 0..self.threshold as usize {
            let node_id = ak.lag_pks[i].id;
            let rpc_port = get_rpc_port(node_id)?;

            let mut client = RpcClient::connect(format!("http://127.0.0.1:{}", rpc_port))
                .await
                .map_err(|e| DecryptionClientError::RpcError(e.to_string()))?;

            let request = tonic::Request::new(PartDecRequest {
                filename: filename.to_string(),
                witness_hex: witness_hex.to_string(),
            });

            let response = client
                .partdec(request)
                .await
                .map_err(|e| DecryptionClientError::RpcError(e.to_string()))?;

            let part_dec_hex = response.into_inner().hex_serialized_decryption;
            let part_dec_bytes = hex::decode(&part_dec_hex)
                .map_err(|e| DecryptionClientError::DecodingError(e.to_string()))?;

            partial_decryptions[i] = PartialDecryption::deserialize_compressed(&part_dec_bytes[..])
                .map_err(|_| DecryptionClientError::DeserializationError)?;
        }

        Ok(partial_decryptions)
    }

    fn aggregate_decrypt(
        &self,
        partial_decryptions: &[PartialDecryption<E>],
        ciphertext: &Ciphertext<E>,
        ak: &AggregateKey<E>,
    ) -> Result<Vec<u8>, DecryptionClientError> {
        let mut selector = vec![false; MAX_COMMITTEE_SIZE];
        selector[0] = true;

        agg_dec(
            partial_decryptions,
            ciphertext,
            &selector,
            ak,
            &self.config.crs,
        )
        .map_err(|e| DecryptionClientError::DecryptionError(e.to_string()))
    }
}

// todo: This needs to be made dynamic when new nodes join
// mapping their index to their ip and port
// in this case we drop ip since everything is runnning locally
// note: this means we can only support three nodes max right now,
// due to the poor design...
fn get_rpc_port(node_id: usize) -> Result<u16, DecryptionClientError> {
    match node_id {
        0 => Ok(30332),
        1 => Ok(30334),
        2 => Ok(30335),
        _ => Err(DecryptionClientError::RpcError(format!(
            "Unknown node ID: {}",
            node_id
        ))),
    }
}
