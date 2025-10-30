//! intents for fangorn.
// intents allow users to associate data access
// with an np-hard problem
use super::challenges::Challenge;
use serde::{Deserialize, Serialize};

/// types of policies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IntentType {
    Challenge,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub policy_type: IntentType,
    pub parameters: Vec<u8>,
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