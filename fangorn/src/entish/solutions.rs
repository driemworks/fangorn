//! solutions for fangorn.
// These provide a way to provide a "Witness" ie the solution to the NP-hard problem.
use super::Witness;

pub trait Solution {
    fn prepare_witness(witness: Vec<u8>) -> Witness;
}

pub struct PasswordSolution;

impl Solution for PasswordSolution {
    fn prepare_witness(password: Vec<u8>) -> Witness {
        Witness(password)
    }
}
