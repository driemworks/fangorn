use crate::backend::{iroh::IrohBackend, Backend};
use anyhow::Result;
use ark_ec::pairing::Pairing;
use async_trait::async_trait;
use codec::{Decode, Encode};
use iroh::EndpointAddr;
use iroh_docs::api::Doc;
use iroh_docs::store::{FlatQuery, QueryBuilder};
use iroh_docs::DocTicket;
use n0_future::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// A message added to the bulletin board
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash, Encode, Decode)]
pub struct DecryptionRequest {
    // pub id: Vec<u8>,
    /// Unique identifier for the message
    pub filename: Vec<u8>,
    /// The actual message content
    pub witness_hex: Vec<u8>,
    /// The location to dispatch the partial decryption    
    pub location: OpaqueEndpointAddr,
}

impl DecryptionRequest {
    pub fn id(&self) -> String {
        let hash = Sha256::digest(self.encode());
        hex::encode(hash)
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
pub struct IrohPool<C: Pairing> {
    backend: Arc<IrohBackend<C>>,
    doc: Doc,
}

impl<C: Pairing> IrohPool<C> {
    pub async fn new(backend: Arc<IrohBackend<C>>, ticket: &str) -> Result<Self> {
        let doc_ticket = DocTicket::from_str(ticket)?;
        let doc = backend.node.docs().import(doc_ticket).await?;

        Ok(Self { backend, doc })
    }
}

pub const RequestPoolKey: &str = "request-pool-";

#[async_trait]
impl<C: Pairing> RequestPool for IrohPool<C> {
    async fn add(&mut self, req: DecryptionRequest) -> Result<()> {
        let id = format!("{}", req.id());
        let data = req.encode();

        self.backend.write(&self.doc, &id, &data).await?;
        Ok(())
    }

    async fn read_all(&self) -> Result<Vec<DecryptionRequest>> {
        // Get all entries from doc
        let query = QueryBuilder::<FlatQuery>::default().key_exact(RequestPoolKey);
        let entries = self.doc.get_many(query.build()).await?;
        let entries = entries.collect::<Vec<_>>().await;

        let mut requests = Vec::new();
        for entry in entries {
            let data = entry.unwrap();
            let key = String::from_utf8_lossy(data.key());
            // Fetch content via backend
            if let Some(bytes) = self.backend.read(&self.doc, &key.to_string(), None).await? {
                if let Ok(req) = DecryptionRequest::decode(&mut &bytes[..]) {
                    requests.push(req);
                }
            }
        }

        Ok(requests)
    }

    async fn count(&self) -> Result<usize> {
        let query = QueryBuilder::<FlatQuery>::default();
        let entries = self.doc.get_many(query.build()).await?;
        let entries = entries.collect::<Vec<_>>().await;

        // Count only request entries (not attestations)
        let count = entries
            .into_iter()
            .filter(|e| {
                let data = e.as_ref().unwrap();
                let key = String::from_utf8_lossy(data.key());
                !key.starts_with("attestation:")
            })
            .count();

        Ok(count)
    }

    async fn submit_partial_attestation(&self, id: &[u8], attestation: &[u8]) -> Result<()> {
        // Key format: "attestation:{request_id}:{worker_id}"
        let request_id = hex::encode(id);
        let worker_id = self.backend.node.router.endpoint().addr().id.to_string();
        let key = format!("attestation:{}:{}", request_id, worker_id);

        self.backend
            .write(&self.doc, &key, &attestation.to_vec())
            .await?;
        Ok(())
    }
}

// Extension: Get all attestations for a request
impl<C: Pairing> IrohPool<C> {
    pub async fn get_attestations(&self, request_id: &[u8]) -> Result<Vec<Vec<u8>>> {
        let prefix = format!("attestation:{}:", hex::encode(request_id));
        let query = QueryBuilder::<FlatQuery>::default();
        let entries = self.doc.get_many(query.build()).await?;
        let entries = entries.collect::<Vec<_>>().await;

        let mut attestations = Vec::new();
        for entry in entries {
            let data = entry.unwrap();
            let key = String::from_utf8_lossy(data.key());
            if key.starts_with(&prefix) {
                if let Some(bytes) = self.backend.read(&self.doc, &key.to_string(), None).await? {
                    attestations.push(bytes);
                }
            }
        }

        Ok(attestations)
    }

    pub async fn attestation_count(&self, request_id: &[u8]) -> Result<usize> {
        let attestations = self.get_attestations(request_id).await?;
        Ok(attestations.len())
    }
}
