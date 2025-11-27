use anyhow::Result;
use ark_ec::pairing::Pairing;
use async_trait::async_trait;
use codec::{Decode, Encode};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use silent_threshold_encryption::setup::PartialDecryption;

/// A struct for messaging partial decryption across nodes
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Encode, Decode)]
pub struct PartialDecryptionMessage {
    pub filename: Vec<u8>,
    // The index of the node who sent it
    pub index: u8,
    // todo: should probably encrypt this somehow
    pub partial_decryption_bytes: Vec<u8>,
}

/// A struct for messaging partial decryption across nodes
#[derive(Debug, Clone, Encode, Decode)]
pub struct RawPartialDecryptionMessage<C: Pairing> {
    pub filename: Vec<u8>,
    // The index of the node who sent it
    // note: wrappertypeencode is not implemented for usize
    pub index: u8,
    // todo: should probably encrypt this somehow
    pub partial_decryption: PartialDecryption<C>,
}

/// A message added to the bulletin board
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Encode, Decode)]
pub struct DecryptionRequest {
    /// Unique identifier for the message
    pub filename: Vec<u8>,
    /// The actual message content
    pub witness_hex: Vec<u8>,
    /// The location to dispatch the partial decryption    
    pub location: OpaqueEndpointAddr,
}

impl DecryptionRequest {
    pub fn id(&self) -> Vec<u8> {
        Sha256::digest(self.encode()).to_vec()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Encode, Decode)]
pub struct OpaqueEndpointAddr(pub Vec<u8>);

impl From<EndpointAddr> for OpaqueEndpointAddr {
    fn from(addr: EndpointAddr) -> Self {
        OpaqueEndpointAddr(serde_json::to_vec(&addr).unwrap())
    }
}

impl Into<EndpointAddr> for OpaqueEndpointAddr {
    fn into(self) -> EndpointAddr {
        serde_json::from_slice(&self.0).unwrap()
    }
}

/// can be used in ink contract
// #[cfg_attr(feature = "ink", ink::trait_definition)]
#[async_trait]
pub trait RequestPool {
    /// add a new message
    async fn add(&mut self, req: DecryptionRequest) -> Result<()>;

    /// read all messages (unordered pool)
    async fn read_all(&self) -> Result<Vec<DecryptionRequest>>;

    // check if a message with given id exists
    // fn contains(&self, id: &[u8]) -> Result<bool>;

    /// Get the total count of messages
    async fn count(&self) -> Result<usize>;

    // users could remove their request before it's fulfilled
    // todo
    // fn remove(&mut self, id: &[u8]) -> Result<bool>;

    /// submit evidence that a worker has processed a work item
    async fn submit_partial_attestation(&self, id: &[u8], attestation: &[u8]) -> Result<()>;
}
// pub struct IrohPool<C: Pairing> {
//     backend: Arc<IrohBackend<C>>,
//     // TODO: this shouldn't need the node, it shoudl just use the backend
//     // but I don't feel like figuring that out right now
//     node: Node<C>,
//     doc: Doc,
// }

// impl<C: Pairing> IrohPool<C> {
//     pub async fn new(backend: Arc<IrohBackend<C>>, node: Node<C>, ticket: &str) -> Result<Self> {
//         let doc_ticket = DocTicket::from_str(ticket)?;
//         let doc = backend.node.docs().import(doc_ticket).await?;

//         Ok(Self { backend, node, doc })
//     }
// }

pub const REQUEST_POOL_KEY: &str = "request-pool-";

// #[async_trait]
// impl<C: Pairing> RequestPool for IrohPool<C> {
//     async fn add(&mut self, req: DecryptionRequest) -> Result<()> {
//         println!("*************************** ADDING TO POOL");

//         let id = format!("{}{}", REQUEST_POOL_KEY, req.id());

//         let announcement = Announcement {
//             tag: Tag::DecryptionRequest,
//             data: req.encode(),
//         };

//         self.backend.write(&self.doc, &id, &announcement.encode()).await?;
//         Ok(())
//     }

//     async fn read_all(&self) -> Result<Vec<DecryptionRequest>> {
//         // get all entries with request pool prefix
//         let query = QueryBuilder::<FlatQuery>::default().key_prefix(REQUEST_POOL_KEY);
//         let entries = self.doc.get_many(query.build()).await?;
//         let entries = entries.collect::<Vec<_>>().await;

//         let mut requests = Vec::new();
//         for entry in entries {
//             let data = entry.unwrap();
//             let hash = data.content_hash();
//             let content = self.node.blobs().get_bytes(hash).await?;
//             println!("***************** got the content!");
//         }

//         Ok(requests)
//     }

//     async fn count(&self) -> Result<usize> {
//         let query = QueryBuilder::<FlatQuery>::default();
//         let entries = self.doc.get_many(query.build()).await?;
//         let entries = entries.collect::<Vec<_>>().await;

//         // // Count only request entries (not attestations)
//         // let count = entries
//         //     .into_iter()
//         //     .filter(|e| {
//         //         let data = e.as_ref().unwrap();
//         //         let key = String::from_utf8_lossy(data.key());
//         //         !key.starts_with("attestation:")
//         //     })
//         //     .count();

//         Ok(0)
//     }

//     async fn submit_partial_attestation(&self, id: &[u8], attestation: &[u8]) -> Result<()> {
//         // Key format: "attestation:{request_id}:{worker_id}"
//         let request_id = hex::encode(id);
//         let worker_id = self.backend.node.router.endpoint().addr().id.to_string();
//         let key = format!("attestation:{}:{}", request_id, worker_id);

//         self.backend
//             .write(&self.doc, &key, &attestation.to_vec())
//             .await?;
//         Ok(())
//     }
// }

// // Extension: Get all attestations for a request
// impl<C: Pairing> IrohPool<C> {
//     pub async fn get_attestations(&self, request_id: &[u8]) -> Result<Vec<Vec<u8>>> {
//         let prefix = format!("attestation:{}:", hex::encode(request_id));
//         let query = QueryBuilder::<FlatQuery>::default();
//         let entries = self.doc.get_many(query.build()).await?;
//         let entries = entries.collect::<Vec<_>>().await;

//         let mut attestations = Vec::new();
//         for entry in entries {
//             let data = entry.unwrap();
//             let key = String::from_utf8_lossy(data.key());
//             // if key.starts_with(&prefix) {
//             //     if let Some(bytes) = self.backend.read(&self.doc, &key.to_string(), None).await? {
//             //         attestations.push(bytes);
//             //     }
//             // }
//         }

//         Ok(attestations)
//     }

//     pub async fn attestation_count(&self, request_id: &[u8]) -> Result<usize> {
//         let attestations = self.get_attestations(request_id).await?;
//         Ok(attestations.len())
//     }
// }
