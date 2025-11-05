pub mod challenges;
pub mod intents;
pub mod solutions;
pub mod utils;
pub mod verifiers;

// for now, we assume it is only asset ownership

pub struct Witness(pub Vec<u8>);
pub struct Statement(pub Vec<u8>);
