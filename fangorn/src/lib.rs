pub static CONTRACT_ADDR: &str = "5CXu35HvZV5EBsa2NAMuqu8kqapZSv4QUWymchRUEuVzKBEw";
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
