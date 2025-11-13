use anyhow::Result;
use ark_bls12_381::G2Affine as G2;
use ark_ec::hashing::{curve_maps::wb::WBMap, HashToCurve};
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use sha2::Sha256;
use silent_threshold_encryption::{
    aggregate::{EncryptionKey, SystemPublicKeys},
    decryption::agg_dec,
    encryption::encrypt,
    setup::PartialDecryption,
    types::Ciphertext,
};
use std::fs;

use crate::{
    gadget::GadgetRegistry,
    policy::CID,
    rpc::server::{PartDecRequest, PreprocessRequest, RpcClient},
    types::*,
};

const MAX_COMMITTEE_SIZE: usize = 2;

pub struct EncryptionClient {
    config: Config<E>,
    // the endpoint of the coordinator node (e.g. localhost:9944)
    node_endpoint: String,
    // gadget registry
    registry: &GadgetRegistry,
}

impl EncryptionClient {
    pub fn new(config_path: &str, node_endpoint: &str) -> Self {
        let config_hex = fs::read_to_string(config_path).expect("Failed to read config file");
        let config_bytes = hex::decode(&config_hex).unwrap();
        let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();

        Self {
            config,
            node_endpoint: node_endpoint.to_string(),
        }
    }

    pub async fn encrypt(&self, plaintext: &[u8], ek: EncryptionKey, t: u8) -> Result<Vec<u8>> {
        // Encrypt
        // let gamma_g2 = G2::rand(&mut OsRng);
        let gamma_g2 = hash_to_curve_g2::<E>(b"fangorn")?;
        let ciphertext = encrypt::<E>(&ek, t, &self.config.crs, gamma_g2.into(), plaintext)?;

        // Serialize
        let mut ciphertext_bytes = Vec::new();
        ciphertext.serialize_compressed(&mut ciphertext_bytes)?;

        Ok(ciphertext_bytes)
    }

    async fn get_system_keys(&self) -> Result<SystemPublicKeys<E>> {
        let mut client = RpcClient::connect(self.node_endpoint.clone()).await?;
        let response = client.preprocess(PreprocessRequest {}).await?;
        let hex = response.into_inner().hex_serialized_sys_key;
        let bytes = hex::decode(&hex)?;
        Ok(SystemPublicKeys::<E>::deserialize_compressed(&bytes[..])?)
    }
}

pub struct DecryptionClient {
    config: Config<E>,
}

impl DecryptionClient {
    pub async fn decrypt(
        &self,
        ciphertext_bytes: &[u8],
        cid: &CID,
        witness: &[u8],
        coordinator_endpoint: &str,
        threshold: u32,
    ) -> Result<Vec<u8>> {
        let mut client = RpcClient::connect(coordinator_endpoint).await?;

        let request = AggregateDecryptRequest {
            ciphertext_hex: hex::encode(ciphertext_bytes),
            content_id: hex::encode(&cid.0),
            witness_hex: hex::encode(witness),
            threshold,
        };

        let response = client.aggregate_decrypt(request).await?;
        let plaintext = hex::decode(&response.into_inner().plaintext_hex)?;

        Ok(plaintext)
    }
}

fn hash_to_curve_g2<E: Pairing>(data: &[u8]) -> E::G2
where
    E::G2: From<G2Projective>,
{
    const DOMAIN: &[u8] = b"fangorn";

    type Hasher = DefaultFieldHasher<Sha256, 128>;
    type Mapper = WBMap<G2Config>;

    let hasher = <G2Projective as HashToCurve<Mapper>>::new(DOMAIN).unwrap();
    let point = hasher.hash(data).unwrap();

    point.into()
}
