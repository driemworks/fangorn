//! a generic policy 'store' 
//! the core abstraction workers leverage for mapping content identifiers to policies

use anyhow::Result;
use async_trait::async_trait;
use serde::{Serialize, Deserialize};
use crate::verifier::Statement;

pub mod local_policy_store;

// a generic content identifier
pub struct CID(pub Vec<u8>);

#[derive(Debug)]
pub struct Policy {
    pub policy_type: PolicyType,
    pub parameters: Vec<u8>,
}

/// types of policies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PolicyType {
    Challenge,
}

impl Policy {
    /// convert a policy to an NP-statement 
    fn to_statement(&self) -> Statement {
        Statement(self.parameters.clone())
    }

    //     /// Create a challenge policy
    // pub fn challenge(question: &str, answer: &str) -> Self {
    //     use crate::verification::challenge::ChallengeStatement;
    //     let stmt = ChallengeStatement::new(question, answer);
    //     Self {
    //         policy_type: PolicyType::Challenge,
    //         parameters: serde_json::to_vec(&stmt).unwrap(),
    //     }
    // }
}

/// The PolicyStore manages content identifier to policy mapping
#[async_trait]
pub trait PolicyStore: Send + Sync {
     /// Get the policy for a given content ID
    async fn get_policy(&self, cid: &CID) -> Result<Option<Policy>>;
    
    /// Register a new policy for content
    async fn register_policy(&self, cid: CID, policy: Policy) -> Result<()>;
    
    /// Remove a cid -> policy mapping
    async fn kill_policy(&self, cid: &CID) -> Result<()>;
}