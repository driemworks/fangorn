use anyhow::Result;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use codec::Encode;
use silent_threshold_encryption::{aggregate::SystemPublicKeys, types::Ciphertext};

use crate::{types::*, verifier::*};

use tonic::{Request, Response, Status};

use std::sync::Arc;
use tokio::sync::Mutex;

pub mod rpc {
    tonic::include_proto!("rpc");
}

pub use rpc::rpc_client::RpcClient;
pub use rpc::rpc_server::{Rpc, RpcServer};
pub use rpc::{PartDecRequest, PartDecResponse, PreprocessRequest, PreprocessResponse};

pub struct NodeServer<C: Pairing> {
    pub state: Arc<Mutex<State<C>>>,
    pub verifier: Arc<dyn Verifier>,
}

#[tonic::async_trait]
impl<C: Pairing> Rpc for NodeServer<C> {
    /// preprocess with best known hints to get encryption and aggregate keys
    /// For the hackathon, we can assume this is going to effectively output a static value
    async fn preprocess(
        &self,
        _request: Request<PreprocessRequest>,
    ) -> Result<Response<PreprocessResponse>, Status> {
        let mut serialized_sys_key: Vec<u8> = vec![];

        let state = self.state.lock().await;
        if let (Some(config), Some(hints)) = (&state.config, &state.hints) {
            let crs = &config.crs;
            let lag_polys = &config.lag_polys;
            // TODO: This shouldn't be hardcoded, send as parameter?
            let k = 1;
            println!("Computing the system public keys");
            let system_keys = SystemPublicKeys::<C>::new(hints.clone(), crs, lag_polys, k).unwrap();

            system_keys
                .serialize_compressed(&mut serialized_sys_key)
                .unwrap();

            println!("> Computed system key");
        }

        let hex_serialized_sys_key = hex::encode(serialized_sys_key);

        Ok(Response::new(PreprocessResponse {
            hex_serialized_sys_key,
        }))
    }

    /// partial decryption
    async fn partdec(
        &self,
        request: Request<PartDecRequest>,
    ) -> Result<Response<PartDecResponse>, Status> {
        // build the witness (signature checks out)
        let req_ref = request.get_ref();

        // convert hex encoded inputs to bytes
        let sig_bytes = hex::decode(req_ref.signature.clone()).unwrap();
        let pk_bytes = hex::decode(req_ref.public_key.clone()).unwrap();

        let witness_bytes = Witness((sig_bytes, pk_bytes, req_ref.asset_id).encode());
        // build the statement (acct controlled by PK owns NFT id = X)
        let statement_bytes = Statement(b"".to_vec());
        // then verify it and proceed
        let is_valid = &self
            .verifier
            .verify_witness(witness_bytes, statement_bytes)
            .await
            .unwrap();

        let mut bytes = Vec::new();

        if *is_valid {
            let ciphertext_bytes = hex::decode(req_ref.ciphertext_hex.clone()).unwrap();
            let ciphertext = Ciphertext::<C>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();

            let state = self.state.lock().await;
            let partial_decryption = state.sk.partial_decryption(&ciphertext);

            partial_decryption.serialize_compressed(&mut bytes).unwrap();
        }

        Ok(Response::new(PartDecResponse {
            hex_serialized_decryption: hex::encode(bytes),
        }))
    }
}
