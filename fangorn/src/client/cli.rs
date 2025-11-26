use clap::{Parser, Subcommand};
use secrecy::SecretString;

#[derive(Parser, Debug)]
#[command(name = "fangorn", version = "1.0")]
pub struct FangornNodeCli {
    #[command(subcommand)]
    pub command: Option<FangornNodeCommands>,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
pub enum FangornNodeCommands {
    Setup {
        /// The output directory (relative path)
        #[arg(long)]
        out_dir: String,
    },
    Run {
        /// Port to bind for incoming connections
        #[arg(long)]
        bind_port: u16,
        /// Port for the RPC interface
        #[arg(long)]
        rpc_port: u16,
        /// The index of a node
        #[arg(long)]
        index: usize,
        /// Determine it the node should act as a bootstrap node
        #[arg(long)]
        is_bootstrap: bool,
        /// The ticket to connect to a swarm
        #[arg(long, default_value = "")]
        ticket: String,
        /// The contract address
        #[arg(long, default_value="")]
        predicate_registry_contract_addr: String,
        /// The request pool contract address
        #[arg(long, default_value="")]
        request_pool_contract_addr: String,
        /// The bootsrap node public key
        #[arg(long, default_value=None)]
        bootstrap_pubkey: Option<String>,
        /// The bootstrap node ip
        #[arg(long, default_value=None)]
        bootstrap_ip: Option<String>,
        #[arg(long,  default_value=None)]
        vault_dir: Option<String>,
        #[arg(long,  default_value=None)]
        vault_pswd: Option<SecretString>,
        #[arg(long,  default_value=None)]
        iroh_key_pswd: Option<SecretString>,
        #[arg(long,  default_value=None)]
        ste_key_pswd: Option<SecretString>
    },
}
