use crate::gadget::*;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::fmt::Debug;

#[derive(Debug)]
pub struct PasswordGadget {}

#[async_trait]
impl Gadget for PasswordGadget {
    fn intent_type_id(&self) -> &'static str {
        "Password"
    }

    /// verify that the witness hashes to the statement
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError> {
        let hash = Sha256::digest(witness);
        Ok(&hash[..] == statement)
    }

    // parse raw data to a password verification intent
    // where the question is the hash and the answer is the password
    fn parse_intent_data(&self, data: &str) -> Result<Vec<u8>, IntentError> {
        let answer = data.as_bytes().to_vec();
        let question = Sha256::digest(&answer);

        Ok(question.to_vec())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_can_parse_valid_intent_data() {
        let gadget = PasswordGadget {};
        let data: &str = "Password(HelloWorld!)";
        let expected_hash = Sha256::digest(data.as_bytes().to_vec());
        let actual_hash = gadget.parse_intent_data(data).unwrap();
        assert_eq!(&expected_hash[..], actual_hash);
    }
}
