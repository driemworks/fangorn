use anyhow::Result;
use clap::Parser;
use fangorn::cli::{FangornNodeCli as Cli, FangornNodeCommands as Commands};
use fangorn::service::{ServiceConfig, build_full_service};
use fangorn::types::*;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf
const MAX_COMMITTEE_SIZE: usize = 2;

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Setup { out_dir: _ }) => {
            // TODO: keygen, save to keystore, etc
            println!("> Nothing happened");
        },
        Some(Commands::Run {
            bind_port,
            rpc_port,
            index,
            bootstrap_pubkey,
            bootstrap_ip,
            is_bootstrap,
            ticket,
        }) => {
            let config = ServiceConfig {
                bind_port: *bind_port,
                rpc_port: *rpc_port,
                index: *index,
                is_bootstrap: *is_bootstrap,
                ticket: if ticket.is_empty() {
                    None
                } else {
                    Some(ticket.clone())
                },
                bootstrap_peers: ServiceConfig::build_bootstrap_peers(
                    bootstrap_pubkey.clone(),
                    bootstrap_ip.clone(),
                ),
            };
            // start the service
            build_full_service::<E>(config, MAX_COMMITTEE_SIZE).await?;
        },
        None => {
            // do nothing
        }
    }

    Ok(())
}
