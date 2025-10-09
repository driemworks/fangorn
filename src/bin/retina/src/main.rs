use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use clap::{Parser, Subcommand};
use codec::{Decode, Encode};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::prelude::*;
// use hello::{
//     world_client::WorldClient, world_server::WorldServer, PartDecRequest, PreprocessRequest,
// };
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

mod node;
mod rpc;
mod service;
mod types;

use node::*;
use rpc::server::*;
use service::{ServiceConfig, build_full_service};
use types::*;

// https://hackmd.io/3968Gr5hSSmef-nptg2GRw
// https://hackmd.io/xqYBrigYQwyKM_0Sn5Xf4w
// https://eprint.iacr.org/2024/263.pdf
const MAX_COMMITTEE_SIZE: usize = 2;

#[derive(Parser, Debug)]
#[command(name = "STE", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
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
    },
    Encrypt {
        #[arg(long)]
        message: String,
        #[arg(long)]
        config_dir: String,
    },
    Decrypt {
        #[arg(long)]
        config_dir: String,
        #[arg(long)]
        ciphertext_dir: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Setup { out_dir: _ }) => {
            // TODO: keygen, save to keystore, etc
            println!("> Nothing happened");
        }
        Some(Commands::Encrypt {
            message,
            config_dir,
        }) => {
            let config_hex =
                fs::read_to_string(config_dir).expect("you must provide a valid config file.");
            let config_bytes = hex::decode(&config_hex).unwrap();
            let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();

            // get the sys key
            let sys_key_request = tonic::Request::new(PreprocessRequest {});
            // from first node
            let mut client = RpcClient::connect("http://127.0.0.1:30333").await.unwrap();
            let response = client.preprocess(sys_key_request).await.unwrap();
            let hex = response.into_inner().hex_serialized_sys_key;
            let bytes = hex::decode(&hex[..]).unwrap();

            let sys_keys = SystemPublicKeys::<E>::deserialize_compressed(&bytes[..]).unwrap();
            let subset = vec![0, 1];
            let (_ak, ek) = sys_keys.get_aggregate_key(&subset, &config.crs, &config.lag_polys);
            // let mut test = Vec::new();
            // ek.serialize_compressed(&mut test).unwrap();
            // panic!("{:?}", test);
            // t = 1 , n = MAX, k = 1
            let t = 1;
            let gamma_g2 = G2::rand(&mut OsRng);
            let ct = encrypt::<E>(&ek, t, &config.crs, gamma_g2, message.as_bytes()).unwrap();
            let mut ciphertext_bytes = Vec::new();
            ct.serialize_compressed(&mut ciphertext_bytes).unwrap();

            let mut file = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open("ciphertext.txt")
                .unwrap();

            write!(&mut file, "{}", hex::encode(ciphertext_bytes)).unwrap();
            println!("> saved ciphertext to disk");
        }
        Some(Commands::Decrypt {
            config_dir,
            ciphertext_dir,
        }) => {
            // read the config
            let config_hex =
                fs::read_to_string(config_dir).expect("you must provide a valid config file.");
            let config_bytes = hex::decode(&config_hex).unwrap();
            let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();
            // get the ciphertext
            let ciphertext_hex =
                fs::read_to_string(ciphertext_dir).expect("you must provide a ciphertext.");
            let ciphertext_bytes = hex::decode(ciphertext_hex.clone()).unwrap();
            let ciphertext =
                Ciphertext::<E>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();

            // get the sys key
            let sys_key_request = tonic::Request::new(PreprocessRequest {});
            // from first node
            let mut client = RpcClient::connect("http://127.0.0.1:30333").await.unwrap();
            let response = client.preprocess(sys_key_request).await.unwrap();
            let hex = response.into_inner().hex_serialized_sys_key;
            let bytes = hex::decode(&hex[..]).unwrap();
            let sys_keys = SystemPublicKeys::<E>::deserialize_compressed(&bytes[..]).unwrap();
            // hardcoded to be just the first sig
            let subset = vec![0, 1];
            let (ak, _ek) = sys_keys.get_aggregate_key(&subset, &config.crs, &config.lag_polys);

            // get a partial decryption
            let request = tonic::Request::new(PartDecRequest {
                ciphertext_hex: ciphertext_hex.clone(),
            });

            let mut partial_decryptions = vec![PartialDecryption::zero(); MAX_COMMITTEE_SIZE];

            let response = client.partdec(request).await.unwrap();
            let part_dec_0_hex = response.into_inner().hex_serialized_decryption;
            let part_dec_0_bytes = hex::decode(&part_dec_0_hex[..]).unwrap();

            // panic!("{:?}", part_dec_0_bytes);

            let part_dec_0 =
                PartialDecryption::<E>::deserialize_compressed(&part_dec_0_bytes[..]).unwrap();
            partial_decryptions[0] = part_dec_0;

            // get a second one
            // let mut client = WorldClient::connect("http://127.0.0.1:30334")
            //     .await
            //     .unwrap();
            // let request = tonic::Request::new(PartDecRequest { ciphertext_hex });
            // let response = client.partdec(request).await.unwrap();
            // let part_dec_1_hex = response.into_inner().hex_serialized_decryption;
            // let part_dec_1_bytes = hex::decode(&part_dec_1_hex[..]).unwrap();
            // let part_dec_1 =
            //     PartialDecryption::<E>::deserialize_compressed(&part_dec_1_bytes[..]).unwrap();
            // partial_decryptions.p ush(part_dec_1);

            println!("> Collected partial decryptions, attempting to decrypt the ciphertext");

            let mut selector = vec![false; MAX_COMMITTEE_SIZE];
            selector[0] = true;

            let mut pds = Vec::new();
            partial_decryptions.iter().for_each(|pd| {
                let mut test = Vec::new();
                pd.serialize_compressed(&mut test).unwrap();
                pds.push(test);
            });

            let mut ct_bytes = Vec::new();
            ciphertext.serialize_compressed(&mut ct_bytes).unwrap();

            // selector[1] = true;
            let out = agg_dec(
                &partial_decryptions,
                &ciphertext,
                &selector,
                &ak,
                &config.crs,
            )
            .unwrap();
            println!("OUT: {:?}", std::str::from_utf8(&out).unwrap());
        },
        None => {
            // do nothing
        }
    }

    Ok(())
}
