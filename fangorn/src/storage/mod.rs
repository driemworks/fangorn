//! a generic policy 'store'
//! the core abstraction workers leverage for mapping content identifiers to policies
use crate::verifier::{Challenge, Statement};
use anyhow::Result;
use ark_serialize::CanonicalSerialize;
use async_trait::async_trait;
use cid::Cid;
use serde::{Deserialize, Serialize};

pub mod local_store;

/// the raw data type for storage
type Data = Vec<u8>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub policy_type: IntentType,
    pub parameters: Vec<u8>,
}

/// types of policies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IntentType {
    Challenge,
}

impl Intent {
    /// convert a policy to an NP-statement
    // pub fn to_statement(&self) -> Statement {
    //     Statement(self.parameters.clone())
    // }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
    /// Create an NP-hard problem 
    pub fn create_intent<C: Challenge>(
        question: &Vec<u8>,
        answer: &Vec<u8>,
        intent_type: IntentType,
    ) -> Self {
        let stmt = C::create_challenge_statement(question, answer);
        let stmt_unwrap = stmt.expect("There was an issue unwrapping the statement");
        Self {
            policy_type: intent_type,
            parameters: stmt_unwrap.0,
        }
    }
}

impl From<Vec<u8>> for Intent {
    fn from(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).unwrap()
    }
}

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
