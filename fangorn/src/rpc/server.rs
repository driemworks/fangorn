use anyhow::Result;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use cid::Cid;
use silent_threshold_encryption::{aggregate::SystemPublicKeys, types::Ciphertext};
use std::str::FromStr;

use crate::{
    entish::{
        Statement, Witness,
        verifiers::{PasswordVerifier, Verifier},
    },
    storage::{*, local_store::*},
    types::*,
};

use tonic::{Request, Response, Status};

use std::sync::Arc;
use tokio::sync::Mutex;

pub mod rpc {
    tonic::include_proto!("rpc");
}

pub use rpc::rpc_client::RpcClient;
pub use rpc::rpc_server::{Rpc, RpcServer};
pub use rpc::{
    AggregateDecryptRequest, AggregateDecryptResponse, PartDecRequest, PartDecResponse,
    PreprocessRequest, PreprocessResponse,
};

pub struct NodeServer<C: Pairing> {
    pub doc_store: Arc<dyn DocStore>,
    pub intent_store: Arc<dyn IntentStore>,
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

            println!("Found {:?} hints", hints.len());
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

        let mut bytes = Vec::new();
        // try to fetch the ciphertext based on the cid
        // recover cid
        let cid_string = req_ref.cid.clone();
        println!("got cid: {}", cid_string.clone());
        let cid = Cid::from_str(&cid_string).unwrap();
        let witness = Witness(hex::decode(req_ref.witness_hex.clone()).unwrap());
        println!("got witness");

        let intent = self.intent_store
            .get_intent(&cid)
            .await
            .expect("Something went wrong when looking for intent.")
            .expect("Intent wasn't found");
        println!("found intent");

        let statement = Statement(intent.parameters);
        println!("created statement");

        let verifier = PasswordVerifier::new();

        println!("verifying witness");
        match verifier.verify_witness(witness, statement).await {
            Ok(true) => {
                println!("Witness verification succeeded");
                if let Some(ciphertext_bytes) = self.doc_store.fetch(&cid).await.unwrap() {
                    let ciphertext =
                        Ciphertext::<C>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();

                    println!("recovered the ciphertext");

                    let state = self.state.lock().await;
                    let partial_decryption = state.sk.partial_decryption(&ciphertext);

                    partial_decryption.serialize_compressed(&mut bytes).unwrap();
                    println!("produced a partial decryption");
                } else {
                    println!("data unavailable");
                }
            }
            Ok(false) => {
                println!("Witness verification failed");
            }
            Err(e) => {
                println!("An Error occurred: {}", e);
            }
        }
        Ok(Response::new(PartDecResponse {
            hex_serialized_decryption: hex::encode(bytes),
        }))
    }

    // attempt aggregate decryption keys from peers
    async fn aggregate_decrypt(
        &self,
        _request: Request<AggregateDecryptRequest>,
    ) -> Result<Response<AggregateDecryptResponse>, Status> {
        // let req = request.get_ref();

        // // 1. Verify witness (this node does it)
        // let cid = CID(hex::decode(&req.content_id).unwrap());
        // let witness = Witness(hex::decode(&req.witness_hex).unwrap());

        // let policy = self.policy_store.get_policy(&cid).await.unwrap().unwrap();
        // // .map_err(|e| Status::internal(format!("Failed to fetch policy: {}", e)))?
        // // .ok_or_else(|| Status::not_found("No policy for CID"))?;

        // // // we probably don't need to do this...
        // // let statement = policy.to_statement();
        // // self.verifier.verify_witness(&witness, &statement).await
        // //     .map_err(|e| Status::permission_denied(format!("Verification failed: {}", e)))?;

        // // println!("Witness verified by coordinator");

        // // 2. Get list of peer nodes [hardcoded for now]
        // let peer_endpoints = self.get_peer_endpoints().await?;

        // println!("📡 Fanning out to {} peers", peer_endpoints.len());

        // // fan out to peers for partial decryptions
        // let mut handles = vec![];
        // for endpoint in peer_endpoints {
        //     let ciphertext_hex = req.ciphertext_hex.clone();
        //     let content_id = req.content_id.clone();
        //     let witness_hex = req.witness_hex.clone();

        //     let handle = tokio::spawn(async move {
        //         // request partial decryptions from each peer
        //         let mut client = RpcClient::connect(endpoint).await?;
        //         let response = client
        //             .partdec(PartDecRequest {
        //                 ciphertext_hex,
        //                 content_id,
        //                 witness_hex,
        //             })
        //             .await?;
        //         Ok::<_, anyhow::Error>(response.into_inner().hex_serialized_decryption)
        //     });

        //     handles.push(handle);
        // }

        // // collect responses
        // let mut partial_decryptions = vec![];
        // for handle in handles {
        //     match handle.await {
        //         Ok(Ok(part_dec_hex)) => {
        //             let bytes = hex::decode(&part_dec_hex).unwrap();
        //             let part_dec =
        //                 PartialDecryption::<C>::deserialize_compressed(&bytes[..]).unwrap();
        //             partial_decryptions.push(part_dec);
        //         }
        //         _ => continue, // Skip failed nodes
        //     }

        //     // Stop once we have threshold shares
        //     if partial_decryptions.len() >= req.threshold as usize {
        //         break;
        //     }
        // }

        // if partial_decryptions.len() < req.threshold as usize {
        //     return Err(Status::internal("Failed to collect enough shares"));
        // }

        // println!("Collected {} shares", partial_decryptions.len());

        // // aggregate and decrypt
        // let plaintext = self
        //     .aggregate_and_decrypt(
        //         &req.ciphertext_hex,
        //         &partial_decryptions,
        //         req.threshold as usize,
        //     )
        //     .await?;

        let bytes = Vec::new();
        Ok(Response::new(AggregateDecryptResponse {
            plaintext_hex: hex::encode(bytes),
        }))
    }
}

// impl<C: Pairing> NodeServer<C> {
//     /// Get endpoints of other nodes in the network
//     async fn get_peer_endpoints(&self) -> Result<Vec<String>, Status> {
//         // For now, hardcode or read from config
//         // Later: discover via iroh network
//         Ok(vec![
//             "http://127.0.0.1:30333".to_string(),
//             "http://127.0.0.1:30334".to_string(),
//         ])
//     }

//     async fn aggregate_and_decrypt(
//         &self,
//         ciphertext_hex: &str,
//         partial_decryptions: &[PartialDecryption<C>],
//         threshold: usize,
//     ) -> Result<Vec<u8>, Status> {
//         // Load config
//         let state = self.state.lock().await;
//         let config = state
//             .config
//             .as_ref()
//             .ok_or_else(|| Status::internal("No config"))?;

//         // Deserialize ciphertext
//         let ciphertext_bytes = hex::decode(ciphertext_hex)
//             .map_err(|_| Status::invalid_argument("Invalid ciphertext"))?;
//         let ciphertext = Ciphertext::<C>::deserialize_compressed(&ciphertext_bytes[..])
//             .map_err(|_| Status::invalid_argument("Invalid ciphertext"))?;

//         // Build selector
//         let mut selector = vec![false; partial_decryptions.len()];
//         for i in 0..threshold {
//             selector[i] = true;
//         }

//         // Get aggregate key
//         let hints = state
//             .hints
//             .as_ref()
//             .ok_or_else(|| Status::internal("No hints"))?;
//         let subset: Vec<usize> = (0..threshold).collect();
//         let sys_keys =
//             SystemPublicKeys::<C>::new(hints.clone(), &config.crs, &config.lag_polys, 1).unwrap();
//         let (ak, _) = sys_keys.get_aggregate_key(&subset, &config.crs, &config.lag_polys);

//         // Decrypt
//         let plaintext = agg_dec(
//             partial_decryptions,
//             &ciphertext,
//             &selector,
//             &ak,
//             &config.crs,
//         )
//         .map_err(|e| Status::internal(format!("Decryption failed: {}", e)))?;

//         Ok(plaintext)
//     }
// }
