use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use clap::{Parser, Subcommand};
use codec::{Decode, Encode};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::prelude::*;
use iroh::{NodeAddr, PublicKey as IrohPublicKey};
use iroh_docs::{
    engine::LiveEvent,
    rpc::{
        client::docs::{Doc, ShareMode},
        proto::{Request, Response},
    },
    store::{FlatQuery, QueryBuilder},
    DocTicket,
};
use quic_rpc::transport::flume::FlumeConnector;
use silent_threshold_encryption::{
    aggregate::SystemPublicKeys, decryption::agg_dec, encryption::encrypt,
    setup::PartialDecryption, types::Ciphertext,
};
use std::io::prelude::*;
use std::sync::Arc;
use std::{fs, fs::OpenOptions, thread, time::Duration};
use tokio::sync::Mutex;
use tonic::transport::Server;

mod cli;
mod node;
mod rpc;
mod service;
mod types;

use cli::{IrisNodeCli as Cli, IrisNodeCommands as Commands};
use node::*;
use rpc::server::*;
use service::{ServiceConfig, build_full_service};
use types::*;

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
