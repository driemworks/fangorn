pub static WS_URL: &str = "ws://localhost:9944";

pub mod backend;
pub mod client;
pub mod crypto;
pub mod gadget;
pub mod pool;
pub mod rpc;
pub mod storage;
pub mod types;
pub mod utils;

pub mod test;

pub use client::node::Node;