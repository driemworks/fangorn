use crate::{
    gadget::GadgetRegistry,
    storage::*,
    types::*,
};
use anyhow::Result;
use ark_bls12_381::{g2::Config as G2Config, G2Projective};
use ark_ec::hashing::curve_maps::wb::WBMap;
use ark_ec::hashing::{
    map_to_curve_hasher::{MapToCurveBasedHasher},
    HashToCurve,
};

use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use sha2::{Digest, Sha256};
use silent_threshold_encryption::{aggregate::SystemPublicKeys, encryption::encrypt};
use std::fs;
use std::sync::Arc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum EncryptionClientError {
    #[error("An error occurred while communicating with the docstore: {0}")]
    DocstoreError(String),
    #[error("{0}")]
    EncryptionError(String),
    #[error("An intent could not be parsed by any configured gadget: {0}")]
    IntentParsingError(String),
    #[error("Serialization failed")]
    SerializationError,
}

pub struct EncryptionClient<D: DocStore, I: IntentStore, P: PlaintextStore> {
    config: Config<E>,
    // the Fangorn encryption key for the given universe
    // at some point we will want to enable 'multiverse' support
    // and will need to revisit this
    system_keys: SystemPublicKeys<E>,
    // the threshold to use when encrypting
    threshold: u8,
    // The app store
    app_store: Arc<AppStore<D, I, P>>,
    // The gadget registry
    registry: GadgetRegistry,
}

impl<D: DocStore, I: IntentStore, P: PlaintextStore> EncryptionClient<D, I, P> {
    pub fn new(
        config_path: &str,
        system_keys: SystemPublicKeys<E>,
        app_store: Arc<AppStore<D, I, P>>,
        registry: GadgetRegistry,
    ) -> Self {
        let config_hex = fs::read_to_string(config_path).expect("Failed to read config file");
        let config_bytes = hex::decode(&config_hex).unwrap();
        let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();

        Self {
            config,
            system_keys,
            threshold: 1, // just hardcoded to 1 for now, easy
            app_store,
            registry,
        }
    }

    pub async fn encrypt(
        &self,
        plaintext: &[u8],
        filename: &[u8],
        raw_intent: &str,
    ) -> Result<(), EncryptionClientError> {
        // parse the intents (fail early on invalid intent)
        let intents = self
            .registry
            .parse_intents(raw_intent)
            .await
            .map_err(|e| EncryptionClientError::IntentParsingError(e.to_string()))?;

        let ciphertext = self.encrypt_inner(plaintext)?;

        // add to shared storage, get cid
        let cid = self
            .app_store
            .doc_store
            .add(&ciphertext)
            .await
            .map_err(|e| EncryptionClientError::DocstoreError(e.to_string()))?;

        // register in intents store
        let _ = self
            .app_store
            .intent_store
            .register_intent(&filename, &cid, intents)
            .await
            .expect("An error occurred when registering intent in shared store");

        Ok(())
    }

    fn encrypt_inner(&self, plaintext: &[u8]) -> Result<Vec<u8>, EncryptionClientError> {
        // Encrypt ciphertext
        let commitment = Sha256::digest(plaintext);
        let gamma_g2 = hash_to_g2(&commitment, b"fangorn");

        // get the encryption key
        let subset = vec![0, self.threshold as usize];
        let (_ak, ek) =
            self.system_keys
                .get_aggregate_key(&subset, &self.config.crs, &self.config.lag_polys);

        let ciphertext = encrypt::<E>(
            &ek,
            self.threshold as usize,
            &self.config.crs,
            gamma_g2.into(),
            plaintext,
        )
        .map_err(|e| EncryptionClientError::EncryptionError(e.to_string()))?;

        // Serialize
        let mut ciphertext_bytes = Vec::new();
        ciphertext
            .serialize_compressed(&mut ciphertext_bytes)
            .map_err(|_| EncryptionClientError::SerializationError)?;

        Ok(ciphertext_bytes)
    }
}

pub fn hash_to_g2(message: &[u8], ctx: &[u8]) -> G2Projective {
    // Create the hasher with domain separation tag
    let hasher = MapToCurveBasedHasher::<
        G2Projective,
        DefaultFieldHasher<Sha256, 128>,
        WBMap<G2Config>,
    >::new(ctx)
    .unwrap();

    // Hash the message to G2
    hasher.hash(message).unwrap().into()
}
