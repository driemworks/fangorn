//! verifiers for fangorn
use anyhow::Result;
use async_trait::async_trait;

// for now, we assume it is only asset ownership

pub struct Witness(pub Vec<u8>);
pub struct Statement(pub Vec<u8>);

#[async_trait]
pub trait Verifier: Send + Sync {
    // ToDo; make blocks generic
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError>;
    async fn verify_witness(&self, witness: Witness, statement: Statement) -> Result<bool, VerificationError>;
}

// pub type Block = ();

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
    async fn verify_witness(&self, w:  Witness, s: Statement) -> Result<bool, VerificationError> {
        Ok(true)
    }
}
