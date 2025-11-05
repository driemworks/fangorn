//! verifiers for fangorn
// verifiers provide the way for fangorn nodes
// to determine proof of knowledge of the solution to
// np-hard problems
use super::{Statement, Witness};
use anyhow::Result;
use async_trait::async_trait;
use multihash_codetable::{Code, MultihashDigest};

#[derive(Debug)]
pub enum VerificationError {
    Other,
    PasswordVerificationError,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationError::Other => write!(f, "Verification error occurred"),
            VerificationError::PasswordVerificationError => {
                write!(f, "Password Verification caused an error")
            }
        }
    }
}

#[async_trait]
pub trait Verifier: Send + Sync {
    // ToDo; make blocks generic
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError>;
    async fn verify_witness(
        &self,
        witness: Witness,
        statement: Statement,
    ) -> Result<bool, VerificationError>;
}

pub struct PasswordVerifier;

impl PasswordVerifier {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Verifier for PasswordVerifier {
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError> {
        Ok(vec![])
    }
    async fn verify_witness(&self, w: Witness, s: Statement) -> Result<bool, VerificationError> {
        let proposed_password = w.0;
        let known_hash = s.0;

        let hash = Code::Sha2_256.digest(&proposed_password).to_bytes();
        if hash == known_hash {
            Ok(true)
        } else {
            Err(VerificationError::PasswordVerificationError)
        }
    }
}

pub struct PolkadotVerifier;

impl PolkadotVerifier {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl Verifier for PolkadotVerifier {
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError> {
        Ok(vec![])
    }
    async fn verify_witness(&self, _w: Witness, _s: Statement) -> Result<bool, VerificationError> {
        Ok(true)
    }
}
