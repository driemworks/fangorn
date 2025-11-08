pub static CONTRACT_ADDR: &str = "5DCzDAj1Gs4gBN92dDGj82B8FNxPZE4E27xTRU4jJhTi1qky";
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
