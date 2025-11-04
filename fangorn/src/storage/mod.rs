//! a generic policy 'store'
//! the core abstraction workers leverage for mapping content identifiers to policies
use anyhow::Result;
use async_trait::async_trait;
use cid::Cid;
use crate::entish::intents::Intent;

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
#[async_trait]
pub trait IntentStore {
    async fn register_intent(&self, cid: &Cid, intent: &Intent) -> Result<()>;
    async fn get_intent(&self, cid: &Cid) -> Result<Option<Intent>>;
    async fn remove_intent(&self, cid: &Cid) -> Result<()>;
}

#[async_trait]
pub trait PlaintextStore {
    async fn read_plaintext(&self, message_dir: &String) -> Result<String>;
    async fn write_to_pt_store(&self, filename: &String, data: &Vec<u8>) -> Result<()>;
}
