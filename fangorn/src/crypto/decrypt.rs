use crate::{
    client::node::Node,
    pool::pool::*,
    rpc::{
        // resolver::{IrohRpcResolver, RpcAddressResolver},
        server::{PartDecRequest, RpcClient},
    },
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
use std::sync::Arc;
use thiserror::Error;
use tokio::sync::Mutex;

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
    #[error("Failed to find data in the docstore: {0}")]
    LookupError(String),
    #[error("Failed to map a node index to a known host:port : {0}")]
    MissingRpcAddress(usize),
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
    // the request pool
    pool: Arc<Mutex<dyn RequestPool>>,
    // a node instance
    node: Node<E>,
}

impl<D: DocStore, I: IntentStore, P: PlaintextStore> DecryptionClient<D, I, P> {
    pub fn new(
        config_path: &str,
        system_keys: SystemPublicKeys<E>,
        app_store: AppStore<D, I, P>,
        pool: Arc<Mutex<dyn RequestPool>>,
        node: Node<E>,
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
            pool,
            node,
        })
    }

    // this is a really a 'request decrypt' now?
    // partial decryptions are received by the node using the PartialDecryptionHandler
    pub async fn request_decrypt(
        &self,
        filename: &str,
        witnesses: &[&str],
        output_filename: &String,
    ) -> Result<(), DecryptionClientError> {
        // fetch ciphertext
        // todo: use intents for verification?
        let (cid, _intents) = self
            .app_store
            .intent_store
            .get_intent(filename.as_bytes())
            .await
            .map_err(|e| DecryptionClientError::IntentStoreError(e.to_string()))?
            .ok_or_else(|| DecryptionClientError::IntentNotFound(filename.to_string()))?;

        // let ciphertext_bytes = self
        //     .app_store
        //     .doc_store
        //     .fetch(&cid)
        //     .await
        //     .map_err(|e| DecryptionClientError::DocstoreError(e.to_string()))?
        //     .ok_or(DecryptionClientError::CiphertextNotFound)?;

        // println!("we got the ciphertext");

        // let ciphertext = Ciphertext::<E>::deserialize_compressed(&ciphertext_bytes[..])
        //     .map_err(|_| DecryptionClientError::DeserializationError)?;

        // prepare witnesses
        let witness_hex = self.encode_witnesses(witnesses)?;

        let location: OpaqueEndpointAddr = self.node.router.endpoint().addr().into();

        let decryption_request = DecryptionRequest {
            filename: filename.as_bytes().to_vec(),
            witness_hex: witness_hex.into(),
            location,
        };

        // add decryption requests to the pool
        let mut locked_pool = self.pool.lock().await;
        locked_pool.add(decryption_request).await;
        // let mut pool = self.pool.lock().unwrap();

        // build request and submit it to the pool

        // let subset = vec![0, self.threshold as usize];
        // let (ak, _ek) =
        //     self.system_keys
        //         .get_aggregate_key(&subset, &self.config.crs, &self.config.lag_polys);

        // // collect partial decryptions
        // let partial_decryptions = self
        //     .collect_partial_decryptions(filename, &witness_hex, &ak)
        //     .await?;

        // // decrypt
        // let plaintext = self.aggregate_decrypt(&partial_decryptions, &ciphertext, &ak)?;

        // // write plaintext to store
        // self.app_store
        //     .pt_store
        //     .write_to_pt_store(output_filename, &plaintext)
        //     .await
        //     .map_err(|e| DecryptionClientError::PlaintextWriteError(e.to_string()))?;

        // Ok(plaintext)
        Ok(())
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
        for i in 0..self.threshold as usize {
            let node_id = ak.lag_pks[i].id;

            // let rpc_addr_url = self.resolver.resolve_rpc_address(node_id).await?;

            // let mut client = RpcClient::connect(rpc_addr_url)
            //     .await
            //     .map_err(|e| DecryptionClientError::RpcError(e.to_string()))?;

            // let request = tonic::Request::new(PartDecRequest {
            //     filename: filename.to_string(),
            //     witness_hex: witness_hex.to_string(),
            // });

            // let response = client
            //     .partdec(request)
            //     .await
            //     .map_err(|e| DecryptionClientError::RpcError(e.to_string()))?;

            // let part_dec_hex = response.into_inner().hex_serialized_decryption;
            // let part_dec_bytes = hex::decode(&part_dec_hex)
            //     .map_err(|e| DecryptionClientError::DecodingError(e.to_string()))?;

            // partial_decryptions[i] = PartialDecryption::deserialize_compressed(&part_dec_bytes[..])
            //     .map_err(|_| DecryptionClientError::DeserializationError)?;
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
