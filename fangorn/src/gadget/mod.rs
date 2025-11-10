pub mod challenges;
pub mod intents;
pub mod solutions;
pub mod utils;
pub mod verifiers;

// for now, we assume it is only asset ownership

pub struct Witness(pub Vec<u8>);
pub struct Statement(pub Vec<u8>);

pub trait Gadget: Send + Sync {
    type Statement: Serialize + DeserializeOwned;
    type Witness: Serialize + DeserializeOwned;

    fn id() -> &'static str;
    fn create_statement(params: &[u8]) -> Result<Self::Statement>;
    fn verify(witness: &Self::Witness, statement: &Self::Statement) -> Result<bool>;
}
