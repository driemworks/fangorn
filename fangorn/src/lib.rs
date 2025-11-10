pub static CONTRACT_ADDR: &str = "5CCe2pCQdwrmLis67y15xhmX2ifKnD8JuVFtaENuMhwJXDUD";
pub static WS_URL: &str = "ws://localhost:9944";

pub mod cli;
pub mod crypto;
pub mod gadget;
pub mod node;
pub mod rpc;
pub mod service;
pub mod storage;
pub mod types;
pub mod utils;

pub mod test;
