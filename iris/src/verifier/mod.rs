//! verifiers for iris
use anyhow::Result;
use async_trait::async_trait;

// for now, we assume it is only asset ownership

pub struct Witness(Vec<u8>);
pub struct Statement(Vec<u8>);

#[async_trait]
pub trait Verifier<Error>: Send + Sync {
    async fn verify_witness(&self, witness: Witness, statement: Statement) -> Result<bool, Error>;
}

// pub type Block = ();

pub enum PolkadotVerifierError {
    Other,
}

pub struct PolkadotVerifier;

#[async_trait]
impl Verifier<PolkadotVerifierError> for PolkadotVerifier {
    async fn verify_witness(&self, w:  Witness, s: Statement) -> Result<bool, PolkadotVerifierError> {
        Ok(true)
    }
}
