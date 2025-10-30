//! verifiers for fangorn
use anyhow::Result;
use async_trait::async_trait;
use multihash_codetable::{Code, MultihashDigest};

// for now, we assume it is only asset ownership

pub struct Witness(pub Vec<u8>);
pub struct Statement(pub Vec<u8>);

pub mod verifier_utils;

pub trait Challenge {
    fn create_challenge_statement(question: &Vec<u8>, answer: &Vec<u8>) -> Result<Statement>;
}

pub struct LocalFileLocationChallenge;

impl Challenge for LocalFileLocationChallenge {

    // Question: What is the key that reveals the file's name and location?
    fn create_challenge_statement(file_location: &Vec<u8>, key: &Vec<u8>, ) -> Result<Statement> {
        let statement = verifier_utils::xor_padded(key, file_location);
        Ok(Statement(statement.to_vec()))
    }

}

pub struct PasswordChallenge;

impl Challenge for PasswordChallenge {
    // Question: What password produces this hash
    fn create_challenge_statement(pswd_hash: &Vec<u8>, pswd: &Vec<u8>) -> Result<Statement> {
        let hash = Code::Sha2_256.digest(pswd).to_bytes();
        if hash == pswd_hash.clone() {
            Ok(Statement(pswd_hash.clone()))
        } else {
            anyhow::bail!("Hashing the provided password did not match the hash provided.")
        }
    }
}

#[async_trait]
pub trait Verifier: Send + Sync {
    // ToDo; make blocks generic
    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError>;
    async fn verify_witness(&self, witness: Witness, statement: Statement) -> Result<bool, VerificationError>;
}

pub trait Solution {
    fn prepare_witness(witness: Vec<u8>) -> Witness;
}

pub struct PasswordSolution;

impl Solution for PasswordSolution {
    fn prepare_witness(password: Vec<u8>) -> Witness {
        Witness(password)
    }
}

#[derive(Debug)]
pub enum VerificationError {
    Other,
    PasswordVerificationError,
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VerificationError::Other => write!(f, "Verification error occurred"),
            VerificationError::PasswordVerificationError => write!(f, "Password Verification caused an error")
        }
    }
}


pub struct PasswordVerifier;

impl PasswordVerifier {
    pub fn new() -> Self {
        Self { }
    }
}

#[async_trait]
impl Verifier for PasswordVerifier {

    async fn get_latest_finalized_block(&self) -> Result<Vec<u8>, VerificationError> {
        Ok(vec![])
    }
    async fn verify_witness(&self, w:  Witness, s: Statement) -> Result<bool, VerificationError> {
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
