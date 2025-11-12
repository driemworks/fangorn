//! a generic policy 'store'
//! the core abstraction workers leverage for mapping content identifiers to policies
use crate::gadget::Intent;
use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;

pub mod contract_store;
pub mod local_store;

/// the raw data type for storage
type Data = Vec<u8>;

/// The SharedStore manages key-value mappings against some shared storage backend
#[async_trait]
pub trait SharedStore<K, V>: Send + Sync {
    /// add the data to storage and get a content identifier
    async fn add(&self, v: &V) -> Result<K>;

    /// fetch data by key
    async fn fetch(&self, k: &K) -> Result<Option<V>>;

    /// Remove data associated with a key
    async fn remove(&self, k: &K) -> Result<()>;
}

/// The docstore is a SharedStore where the key is a cid
/// and the value is the corresponding message
pub trait DocStore: Send + Sync + SharedStore<Cid, Data> {}

/// shared statement storage to associate CID (data) to intent
// TODO: we need to pass some kind of configurable metadata when registering the intent
// e.g. the token_supply
#[async_trait]
pub trait IntentStore: Send + Sync {
    async fn register_intent(&self, filename: &[u8], cid: &Cid, intents: Vec<Intent>) -> Result<()>;
    async fn get_intent(&self, filename: &[u8]) -> Result<Option<(Cid, Vec<Intent>)>>;
    async fn remove_intent(&self, filename: &[u8]) -> Result<()>;
}

#[async_trait]
pub trait PlaintextStore {
    async fn read_plaintext(&self, message_path: &String) -> Result<Vec<u8>>;
    async fn write_to_pt_store(&self, filename: &String, data: &Vec<u8>) -> Result<()>;
}

pub struct AppStore<D: DocStore, I: IntentStore, P: PlaintextStore> {
    pub doc_store: D,
    pub intent_store: I,
    pub pt_store: P,
}

impl<D: DocStore, I: IntentStore, P: PlaintextStore> AppStore<D, I, P> {
    pub fn new(doc_store: D, intent_store: I, pt_store: P) -> Self {
        Self {
            doc_store,
            intent_store,
            pt_store,
        }
    }
}
