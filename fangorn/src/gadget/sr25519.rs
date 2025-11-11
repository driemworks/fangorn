// use crate::gadget::*;
// use async_trait::async_trait;
// use multihash_codetable::{Code, MultihashDigest};
// use std::fmt::Debug;

// #[derive(Debug)]
// pub struct Sr25519Gadget {}

// #[async_trait]
// impl Gadget for Sr25519Gadget {
//     fn intent_type_id(&self) -> &'static str {
//         "Sr25519"
//     }

//     // The statement is: "I know "
//     fn create_statement(&self, question: &[u8], _answer: &[u8]) -> Result<Vec<u8>, IntentError> {
//         Ok(question.to_vec())
//     }

//     /// verify that the witness hashes to the statement
//     async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError> {
//         let hash = Code::Sha2_256.digest(witness).to_bytes();
//         Ok(hash == statement)
//     }

//     // expected format: signature (32 bytes) || message (any length)
//     fn parse_intent_data(&self, data: &str) -> Result<ParsedIntentData, IntentError> {
//         let answer = data.as_bytes().to_vec();
//         let question = Code::Sha2_256.digest(&answer).to_bytes();

//         Ok(ParsedIntentData { question, answer })
//     }
// }
