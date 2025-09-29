use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(name = "STE", version = "1.0")]
struct IrisNodeCli {
    #[command(subcommand)]
    command: Option<IrisNodeCommands>,
}


/// Define available subcommands
#[derive(Subcommand, Debug)]
enum IrisNodeCommands {
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

        #[arg(long)]
        index: usize,

        #[arg(long)]
        is_bootstrap: bool,

        #[arg(long, default_value = "")]
        ticket: String,

        #[arg(long, default_value=None)]
        bootstrap_pubkey: Option<String>,

        #[arg(long, default_value=None)]
        bootstrap_ip: Option<String>,
    }
}

// #[derive(Debug)]
// pub struct IrisNodeCli { }

// impl IrisNodeCli {

//     pub fn new() -> Self {
//         Self { }
//     }

//     // /// Setup function (keygen?)
// // pub fn setup() { 
// //     // TODO: keygen
// //     println!("> Nothing happened");
// // }

// // pub fn run() {

// // }
// }
