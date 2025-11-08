//! challenges for fangorn.
// challenges are the np-hard problem(s)
// that must be solved in order to prove
// access priveleges
use super::{Statement, utils};
use anyhow::Result;
use multihash_codetable::{Code, MultihashDigest};

pub trait Challenge {
    fn create_challenge_statement(question: &Vec<u8>, answer: &Vec<u8>) -> Result<Statement>;
}

pub struct LocalFileLocationChallenge;

impl Challenge for LocalFileLocationChallenge {
    // Question: What is the key that reveals the file's name and location?
    fn create_challenge_statement(file_location: &Vec<u8>, key: &Vec<u8>) -> Result<Statement> {
        let statement = utils::xor_padded(key, file_location);
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
