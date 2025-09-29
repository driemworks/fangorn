use anyhow::Result;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use silent_threshold_encryption::{aggregate::SystemPublicKeys, types::Ciphertext};

use crate::types::*;

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
}

#[tonic::async_trait]
impl<C: Pairing> Rpc for NodeServer<C> {
    /// preprocess with best known hints to get encryption and aggregate keys
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
        let ciphertext_bytes = hex::decode(request.get_ref().ciphertext_hex.clone()).unwrap();
        let ciphertext = Ciphertext::<C>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();

        let state = self.state.lock().await;
        let partial_decryption = state.sk.partial_decryption(&ciphertext);

        let mut bytes = Vec::new();
        partial_decryption.serialize_compressed(&mut bytes).unwrap();

        Ok(Response::new(PartDecResponse {
            hex_serialized_decryption: hex::encode(bytes),
        }))
    }
}
