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
mod types;

use crate::node::*;
use crate::rpc::server::{
    RpcClient, RpcServer, PartDecRequest, PreprocessRequest,
};
use crate::rpc::server::*;
use crate::types::*;

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
            // TODO: keygen
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
            let mut client = RpcClient::connect("http://127.0.0.1:30333")
                .await
                .unwrap();
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
            let mut client = RpcClient::connect("http://127.0.0.1:30333")
                .await
                .unwrap();
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
        }
        Some(Commands::Run {
            bind_port,
            rpc_port,
            index,
            bootstrap_pubkey,
            bootstrap_ip,
            is_bootstrap,
            ticket,
        }) => {
            // build bootstrap nodeaddr if provided
            let mut bootstrap: Option<Vec<NodeAddr>> = None;
            let mut bootstrap_addrs: Vec<NodeAddr> = Vec::new();
            if let Some(pubkey) = bootstrap_pubkey {
                if let Some(ip) = bootstrap_ip {
                    let pubkey = IrohPublicKey::from_str(pubkey).unwrap();
                    let socket: SocketAddr = ip.parse().unwrap();
                    bootstrap_addrs.push(NodeAddr::from((pubkey, None, vec![socket].as_slice())));

                    if !bootstrap_addrs.is_empty() {
                        bootstrap = Some(bootstrap_addrs);
                    }
                }
            }

            // a channel for sending and receiving doc announcements
            let (tx, rx) = flume::unbounded();
            let params = StartNodeParams::<E>::rand(*bind_port, *index);
            // let sk = params.secret_key.clone();
            // let mut test = Vec::new();
            // sk.serialize_compressed(&mut test).unwrap();
            // panic!("{:?}", test);

            // a state for storing config and hints
            let state = State::<E>::empty(params.secret_key.clone());
            let arc_state = Arc::new(Mutex::new(state.clone()));
            let arc_state_clone = Arc::clone(&arc_state.clone());
            // build the node
            let mut node = Node::build(params, rx, arc_state).await;
            node.try_connect_peers(bootstrap).await.unwrap();

            // get the document stream
            let doc_stream = if *is_bootstrap {
                // if you are a bootstrap node then you must generate the kzg params
                // and build the initial 'ticket'
                println!("Initial Startup: Generating new config");
                let config_bytes: Vec<u8> = setup(MAX_COMMITTEE_SIZE);

                let doc = node.docs().create().await.unwrap();
                let ticket = doc
                    .share(
                        ShareMode::Write,
                        iroh_docs::rpc::AddrInfoOptions::RelayAndAddresses,
                    )
                    .await
                    .unwrap();

                println!("Entry ticket: {}", ticket);

                // load the doc
                let doc_stream = node.docs().import(ticket.clone()).await.unwrap();

                let config_announcement = Announcement {
                    tag: Tag::Config,
                    data: config_bytes,
                };
                let _ = doc_stream
                    .set_bytes(
                        node.docs().authors().default().await.unwrap(),
                        CONFIG_KEY,
                        config_announcement.encode(),
                    )
                    .await
                    .unwrap();
                doc_stream
            } else {
                let ticket = DocTicket::from_str(ticket).unwrap();
                // load the doc
                node.docs().import(ticket.clone()).await.unwrap()
            };

            // start the state sync loop
            n0_future::task::spawn(run_state_sync(doc_stream.clone(), node.clone(), tx.clone()));
            // wait a few secs for the doc to sync
            thread::sleep(Duration::from_secs(2));

            let config_query = QueryBuilder::<FlatQuery>::default()
                .key_exact(CONFIG_KEY)
                .limit(1);
            // there must be a better way to do this, but I want to ignore author for now...
            let cfg_entry = doc_stream.get_many(config_query.build()).await.unwrap();
            let config = cfg_entry.collect::<Vec<_>>().await;
            let hash = config[0].as_ref().unwrap().content_hash();
            let content = node.blobs().read_to_bytes(hash).await.unwrap();
            // try to decode an announcement (config accouncement)
            let a = Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();
            // send it
            tx.send(a).unwrap();

            // now load all previously published hints if not bootstrap
            // for now we can do this really simply by just looking at all indices less than our
            if !*is_bootstrap {
                for i in 1..(*index) as u32 {
                    // get the entry and extract the announcement
                    let hint_query = QueryBuilder::<FlatQuery>::default()
                        .key_exact(i.to_string())
                        .limit(1);
                    let entry_list = doc_stream.get_many(hint_query.build()).await.unwrap();
                    let entry = entry_list.collect::<Vec<_>>().await;
                    let hash = entry[0].as_ref().unwrap().content_hash();
                    let content = node.blobs().read_to_bytes(hash).await.unwrap();
                    let announcement =
                        Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();
                    tx.send(announcement).unwrap();
                }
            }

            // make sure everything is synced
            thread::sleep(Duration::from_secs(1));

            // write your pubkey and hint and index
            let pk = node.get_pk().await.unwrap();
            println!("Computed the hint");
            let mut pk_bytes = Vec::new();
            pk.serialize_compressed(&mut pk_bytes).unwrap();
            let hint_announcement = Announcement {
                tag: Tag::Hint,
                data: pk_bytes,
            };

            // send yourself your hint
            tx.send(hint_announcement.clone()).unwrap();
            // finally send the hint to peers
            let _ = doc_stream
                .set_bytes(
                    node.docs().authors().default().await.unwrap(),
                    index.to_string(),
                    hint_announcement.encode(),
                )
                .await
                .unwrap();

            // setup the RPC server
            let addr_str = format!("127.0.0.1:{}", rpc_port);
            let addr = addr_str.parse().unwrap();
            let world = NodeServer::<E> {
                state: arc_state_clone,
            };
            // the handle to run the RPC server, runs forever
            n0_future::task::spawn(async move {
                Server::builder()
                    .add_service(RpcServer::new(world))
                    .serve(addr)
                    .await
                    .unwrap()
            });

            println!("> RPC listening on {}", addr);

            loop {}
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}

async fn run_state_sync<C: Pairing>(
    doc_stream: Doc<FlumeConnector<Response, Request>>,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
) {
    // to sync the doc with peers we need to read the state of the doc and load it
    doc_stream.start_sync(vec![]).await.unwrap();

    // subscribe to changes to the doc
    let mut sub = doc_stream.subscribe().await.unwrap();
    let blobs = node.blobs().clone();

    while let Ok(event) = sub.try_next().await {
        if let Some(evt) = event {
            println!("{:?}", evt);
            if let LiveEvent::InsertRemote { entry, .. } = evt {
                let msg_body = blobs.read_to_bytes(entry.content_hash()).await;
                match msg_body {
                    Ok(msg) => {
                        let bytes = msg.to_vec();
                        let announcement = Announcement::decode(&mut &bytes[..]).unwrap();
                        tx.send(announcement).unwrap();
                    }
                    Err(e) => {
                        println!("{:?}", e);
                        // may still be syncing so try again (3x)
                        for _ in 0..3 {
                            thread::sleep(Duration::from_secs(1));
                            let message_content = blobs.read_to_bytes(entry.content_hash()).await;
                            if let Ok(msg) = message_content {
                                let bytes = msg.to_vec();
                                let announcement = Announcement::decode(&mut &bytes[..]).unwrap();
                                tx.send(announcement).unwrap();
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
}

fn setup(size: usize) -> Vec<u8> {
    let config = Config::<E>::rand(size);
    let mut bytes = Vec::new();
    config.serialize_compressed(&mut bytes).unwrap();
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("config.txt")
        .unwrap();
    write!(&mut file, "{}", hex::encode(bytes.clone())).unwrap();
    println!("> saved to disk");
    bytes
}
