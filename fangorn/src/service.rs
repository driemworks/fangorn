// src/service.rs

use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalSerialize;
use codec::{Decode, Encode};
use core::net::SocketAddr;
use core::str::FromStr;
use futures::prelude::*;
use iroh::{NodeAddr, PublicKey as IrohPublicKey};
use iroh_docs::{
    DocTicket,
    engine::LiveEvent,
    rpc::{
        client::docs::{Doc, ShareMode},
        proto::{Request, Response},
    },
    store::{FlatQuery, QueryBuilder},
};
use quic_rpc::transport::flume::FlumeConnector;
use std::sync::Arc;
use std::{fs::OpenOptions, io::Write, thread, time::Duration};
use tokio::sync::Mutex;
use tonic::transport::Server;

use crate::node::*;
use crate::rpc::server::{NodeServer, RpcServer};
use crate::storage::{
    AppStore, DocStore, IntentStore, SharedStore,
    contract_store::ContractIntentStore,
    local_store::{LocalDocStore, LocalPlaintextStore},
};
use crate::types::*;
use crate::utils::decode_contract_addr;

/// Configuration for starting a full node service
pub struct ServiceConfig {
    pub bind_port: u16,
    pub rpc_port: u16,
    pub index: usize,
    pub is_bootstrap: bool,
    pub ticket: Option<String>,
    pub bootstrap_peers: Option<Vec<NodeAddr>>,
}

impl ServiceConfig {
    /// Build bootstrap peers from CLI arguments
    pub fn build_bootstrap_peers(
        pubkey: Option<String>,
        ip: Option<String>,
    ) -> Option<Vec<NodeAddr>> {
        if let (Some(pubkey_str), Some(ip_str)) = (pubkey, ip) {
            let pubkey = IrohPublicKey::from_str(&pubkey_str).ok().unwrap();
            let socket: SocketAddr = ip_str.parse().ok().unwrap();
            Some(vec![NodeAddr::from((
                pubkey,
                None,
                vec![socket].as_slice(),
            ))])
        } else {
            None
        }
    }
}

pub struct ServiceHandle<C: Pairing> {
    pub node: Node<C>,
    pub ticket: String,
    pub doc: Doc<FlumeConnector<Response, Request>>,
}

// build a service that connects to peers but doesn't sync,
// does not produce shares, only operates the 'agg and dec' rpc and peer sync
// this will be used by users to aggregate shares,
// so we don't need to manually configure peer addresses.
// pub async fn build_partial_service<C: Pairing>() -> Result<()> { }

/// Build and start the full Fangorn node service
pub async fn build_full_service<C: Pairing>(
    config: ServiceConfig,
    max_committee_size: usize,
) -> Result<ServiceHandle<C>> {
    // setup channels for state synchronization
    let (tx, rx) = flume::unbounded();

    // initialize node parameters and state
    let params = StartNodeParams::<C>::rand(config.bind_port, config.index);
    let state = State::<C>::empty(params.secret_key.clone());
    let arc_state = Arc::new(Mutex::new(state));
    let arc_state_clone = Arc::clone(&arc_state);

    let mut node = Node::build(params, rx, arc_state).await;

    // panic!("{:?}", node.get_pk().await);
    node.try_connect_peers(config.bootstrap_peers.clone())
        .await
        .unwrap();

    let (doc_stream, ticket) = setup_document_stream(
        &node,
        config.is_bootstrap,
        config.ticket,
        max_committee_size,
        &tx,
    )
    .await
    .unwrap();

    spawn_state_sync_service(
        doc_stream.clone(),
        node.clone(),
        tx.clone(),
        config.bootstrap_peers,
    );

    // wait for initial sync
    thread::sleep(Duration::from_secs(3));

    // sync: load and distribute config
    load_and_distribute_config(&node, &doc_stream, &tx)
        .await
        .unwrap();
    // sync: load previous hints (if not bootstrap)
    if !config.is_bootstrap {
        load_previous_hints(&node, &doc_stream, config.index, &tx)
            .await
            .unwrap();
    }

    // wait for everything to synced
    thread::sleep(Duration::from_secs(1));

    // publish our own hint
    publish_node_hint(&node, &doc_stream, config.index, &tx)
        .await
        .unwrap();

    spawn_rpc_service(arc_state_clone, config.rpc_port)
        .await
        .unwrap();

    // // main service loop
    // run_service_loop().await
    Ok(ServiceHandle {
        node: node.clone(),
        ticket,
        doc: doc_stream,
    })
}

/// Setup the document stream for state synchronization
async fn setup_document_stream<C: Pairing>(
    node: &Node<C>,
    is_bootstrap: bool,
    ticket: Option<String>,
    max_committee_size: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<(Doc<FlumeConnector<Response, Request>>, String)> {
    if is_bootstrap {
        println!("Initial Startup: Generating new config");

        // Generate config and create document
        let config_bytes = generate_config(max_committee_size).unwrap();
        let doc = node.docs().create().await.unwrap();

        // Create and share ticket
        let ticket = doc
            .share(
                ShareMode::Write,
                iroh_docs::rpc::AddrInfoOptions::RelayAndAddresses,
            )
            .await
            .unwrap();

        println!("Entry ticket: {}", ticket);
        let ticket_string = ticket.to_string();

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("ticket.txt")
            .unwrap();

        writeln!(&mut file, "{}", ticket_string).expect("Unable to write ticket to file.");

        // Import the document
        let doc_stream = node.docs().import(ticket.clone()).await.unwrap();

        // Publish config to document
        let config_announcement = Announcement {
            tag: Tag::Config,
            data: config_bytes,
        };

        tx.send(config_announcement.clone()).unwrap();

        doc_stream
            .set_bytes(
                node.docs().authors().default().await?,
                CONFIG_KEY,
                config_announcement.encode(),
            )
            .await
            .unwrap();

        let ticket_str = ticket.clone().to_string();
        Ok((doc_stream, ticket_str))
    } else {
        // Join existing network
        let ticket_str = ticket
            .ok_or_else(|| anyhow::anyhow!("Ticket required for non-bootstrap nodes"))
            .unwrap();
        let doc_ticket = DocTicket::from_str(&ticket_str).unwrap();
        let doc_stream = node.docs().import(doc_ticket).await.unwrap();
        Ok((doc_stream, ticket_str))
    }
}

/// Load config from document and distribute to state
async fn load_and_distribute_config<C: Pairing>(
    node: &Node<C>,
    doc_stream: &Doc<FlumeConnector<Response, Request>>,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    let config_query = QueryBuilder::<FlatQuery>::default()
        .key_exact(CONFIG_KEY)
        .limit(1);

    let cfg_entry = doc_stream.get_many(config_query.build()).await.unwrap();
    let config = cfg_entry.collect::<Vec<_>>().await;

    let hash = config[0].as_ref().unwrap().content_hash();
    let content = node.blobs().read_to_bytes(hash).await.unwrap();
    let announcement = Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();

    tx.send(announcement).unwrap();

    Ok(())
}

/// Load hints from previous nodes in the network
async fn load_previous_hints<C: Pairing>(
    node: &Node<C>,
    doc_stream: &Doc<FlumeConnector<Response, Request>>,
    our_index: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    println!("Loading hints from previous nodes...");

    let mut count = 0;
    for i in 1..(our_index as u32) {
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
        count += 1;
    }

    println!("Loaded {} previous hints", count);
    Ok(())
}

/// Publish this node's hint to the network
async fn publish_node_hint<C: Pairing>(
    node: &Node<C>,
    doc_stream: &Doc<FlumeConnector<Response, Request>>,
    index: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    // publish our own public key, hint, and index
    let pk = node
        .get_pk()
        .await
        .ok_or_else(|| anyhow::anyhow!("Failed to compute public key"))
        .unwrap();

    println!("Computed the hint");

    let mut pk_bytes = Vec::new();
    pk.serialize_compressed(&mut pk_bytes).unwrap();

    let hint_announcement = Announcement {
        tag: Tag::Hint,
        data: pk_bytes,
    };

    // Send to ourselves first
    tx.send(hint_announcement.clone()).unwrap();

    // Publish to network
    doc_stream
        .set_bytes(
            node.docs().authors().default().await.unwrap(),
            index.to_string(),
            hint_announcement.encode(),
        )
        .await
        .unwrap();

    println!("Published hint to network");
    Ok(())
}

/// Spawn the state synchronization background task
fn spawn_state_sync_service<C: Pairing>(
    doc_stream: Doc<FlumeConnector<Response, Request>>,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
    bootstrap_peers: Option<Vec<NodeAddr>>,
) {
    n0_future::task::spawn(async move {
        if let Err(e) = run_state_sync(doc_stream, node, tx, bootstrap_peers).await {
            eprintln!("State sync error: {:?}", e);
        }
    });
}

/// Run the state synchronization loop
async fn run_state_sync<C: Pairing>(
    doc_stream: Doc<FlumeConnector<Response, Request>>,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
    bootstrap_peers: Option<Vec<NodeAddr>>,
) -> Result<()> {
    // to sync the doc with peers we need to read the state of the doc and load it
    // doc_stream.start_sync(vec![]).await.unwrap();
    let peers = bootstrap_peers.unwrap_or_default();
    doc_stream.start_sync(peers).await.unwrap();

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

    Ok(())
}

/// Spawn the RPC server
async fn spawn_rpc_service<C: Pairing>(state: Arc<Mutex<State<C>>>, rpc_port: u16) -> Result<()> {
    let addr_str = format!("127.0.0.1:{}", rpc_port);
    let addr = addr_str.parse().unwrap();

    let doc_store = Arc::new(LocalDocStore::new("tmp/docs/"));

    // let gadget = SmartContractGadget::new(contract_addr, intent_store, verifier)
    let contract_addr_bytes = decode_contract_addr(crate::CONTRACT_ADDR);
    let intent_store = Arc::new(
        ContractIntentStore::new(crate::WS_URL.to_string(), contract_addr_bytes, None)
            .await
            .unwrap(),
    );
    // this should be some kind of "modular gadget factory"
    // since we want to be able to swap verification on demand
    let verifier = Arc::new(crate::gadget::verifiers::PasswordVerifier::new());

    let server = NodeServer::<C> {
        doc_store,
        intent_store,
        state,
        verifier,
    };

    n0_future::task::spawn(async move {
        if let Err(e) = Server::builder()
            .add_service(RpcServer::new(server))
            .serve(addr)
            .await
        {
            eprintln!("RPC server error: {:?}", e);
        }
    });

    println!("> RPC listening on {}", addr);
    Ok(())
}

/// Generate the initial config (for bootstrap nodes)
fn generate_config(size: usize) -> Result<Vec<u8>> {
    use ark_serialize::CanonicalSerialize;

    let config = Config::<E>::rand(size);
    let mut bytes = Vec::new();
    config.serialize_compressed(&mut bytes).unwrap();

    // Save to disk for debugging
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("config.txt")
        .unwrap();

    write!(&mut file, "{}", hex::encode(&bytes)).unwrap();
    println!("> Saved config to disk");

    Ok(bytes)
}
