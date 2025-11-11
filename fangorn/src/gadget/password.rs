use crate::gadget::*;
use async_trait::async_trait;
use multihash_codetable::{Code, MultihashDigest};
use std::fmt::Debug;

#[derive(Debug)]
pub struct PasswordGadget {}

#[async_trait]
impl Gadget for PasswordGadget {
    fn intent_type_id(&self) -> &'static str {
        "Password"
    }

    // The statement is the hash of the password
    fn create_statement(&self, question: &[u8], _answer: &[u8]) -> Result<Vec<u8>, IntentError> {
        Ok(question.to_vec())
    }

    /// verify that the witness hashes to the statement
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError> {
        let hash = Code::Sha2_256.digest(witness).to_bytes();
        Ok(hash == statement)
    }

    // parse raw data to a password verification intent
    // where the question is the hash and the answer is the password
    fn parse_intent_data(&self, data: &str) -> Result<ParsedIntentData, IntentError> {
        let answer = data.as_bytes().to_vec();
        let question = Code::Sha2_256.digest(&answer).to_bytes();

        Ok(ParsedIntentData { question, answer })
    }
}
