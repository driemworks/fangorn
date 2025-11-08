
pub static CONTRACT_ADDR: &str = "144GZEPSStuLiDHKCRBMptUWWV9y7mQoQP5pBWBfGANvN6zJ";
pub static WS_URL:  &str = "ws://localhost:9933";

pub mod cli;
pub mod crypto;
pub mod entish;
pub mod node;
pub mod rpc;
pub mod service;
pub mod storage;
pub mod types;
pub mod utils;

pub mod test;
