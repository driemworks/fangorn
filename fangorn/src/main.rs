use anyhow::Result;
use clap::Parser;
use fangorn::client::cli::{FangornNodeCli as Cli, FangornNodeCommands as Commands};
use fangorn::client::service::{build_full_service, ServiceConfig};
use fangorn::types::*;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Setup { out_dir: _ }) => {
            // TODO: keygen, save to keystore, etc
            println!("> Nothing happened");
        }
        Some(Commands::Run {
            bind_port,
            rpc_port,
            index,
            bootstrap_pubkey,
            bootstrap_ip,
            is_bootstrap,
            ticket,
            predicate_registry_contract_addr,
            request_pool_contract_addr,
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
                predicate_registry_contract_addr: predicate_registry_contract_addr.to_string(),
                request_pool_contract_addr: request_pool_contract_addr.to_string(),
            };
            // start the service
            build_full_service::<E>(config, MAX_COMMITTEE_SIZE).await?;
            tokio::signal::ctrl_c().await?;
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}
