//! verifiers for fangorn
use anyhow::Result;
use async_trait::async_trait;

// for now, we assume it is only asset ownership

pub struct Witness(pub Vec<u8>);
pub struct Statement(pub Vec<u8>);

pub mod verifier_utils;

pub trait Challenge {
    fn create_challenge_statement(question: &Vec<u8>, answer: &Vec<u8>) -> Statement;
}

pub struct LocalFileLocationChallenge;

impl Challenge for LocalFileLocationChallenge {

    // The challenge statement here is whether Bob knows the key that reveals
    // the file's location
    fn create_challenge_statement(file_location: &Vec<u8>, key: &Vec<u8>, ) -> Statement {
        let statement = verifier_utils::xor_padded(key, file_location);
        Statement(statement.to_vec())
    }
}

#[async_trait]
pub trait Verifier: Send + Sync {
    // ToDo; make blocks generic
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError>;
    async fn verify_witness(&self, witness: Witness, statement: Statement) -> Result<bool, VerificationError>;
}

#[derive(Debug)]
pub enum VerificationError {
    Other,
}

pub struct PolkadotVerifier;

impl PolkadotVerifier {
    pub fn new() -> Self {
        Self { }
    }
}

#[async_trait]
impl Verifier for PolkadotVerifier {
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError> {
        Ok(vec![])
    }
    async fn verify_witness(&self, _w:  Witness, _s: Statement) -> Result<bool, VerificationError> {
        Ok(true)
    }
}
