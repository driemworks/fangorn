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
    engine::LiveEvent,
    rpc::{
        client::docs::{Doc, ShareMode},
        proto::{Request, Response},
    },
    store::{FlatQuery, QueryBuilder},
    DocTicket,
};
use quic_rpc::transport::flume::FlumeConnector;
use std::sync::Arc;
use std::{fs::OpenOptions, io::Write, thread, time::Duration};
use tokio::sync::Mutex;
use tonic::transport::Server;

use crate::node::*;
use crate::rpc::server::{NodeServer, RpcServer};
use crate::types::*;

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
            Some(vec![NodeAddr::from((pubkey, None, vec![socket].as_slice()))])
        } else {
            None
        }
    }
}

/// Build and start the full Iris node service
pub async fn build_full_service<C: Pairing>(
    config: ServiceConfig,
    max_committee_size: usize,
) -> Result<()> {
    // 1. Setup channels for state synchronization
    let (tx, rx) = flume::unbounded();

    // 2. Initialize node parameters and state
    let params = StartNodeParams::<C>::rand(config.bind_port, config.index);
    let state = State::<C>::empty(params.secret_key.clone());
    let arc_state = Arc::new(Mutex::new(state));
    let arc_state_clone = Arc::clone(&arc_state);

    // 3. Build and start the node
    let mut node = Node::build(params, rx, arc_state).await;
    node.try_connect_peers(config.bootstrap_peers).await.unwrap();

    // 4. Setup document stream (bootstrap vs follower)
    let doc_stream = setup_document_stream(
        &node,
        config.is_bootstrap,
        config.ticket,
        max_committee_size,
    )
    .await.unwrap();

    // 5. Start background state sync service
    spawn_state_sync_service(doc_stream.clone(), node.clone(), tx.clone());

    // Wait for initial sync
    thread::sleep(Duration::from_secs(2));

    // 6. Load and distribute config
    load_and_distribute_config(&node, &doc_stream, &tx).await.unwrap();

    // 7. Load previous hints (if not bootstrap)
    if !config.is_bootstrap {
        load_previous_hints(&node, &doc_stream, config.index, &tx).await.unwrap();
    }

    // Ensure everything is synced
    thread::sleep(Duration::from_secs(1));

    // 8. Publish our own hint
    publish_node_hint(&node, &doc_stream, config.index, &tx).await.unwrap();

    // 9. Start RPC server
    spawn_rpc_service(arc_state_clone, config.rpc_port).await.unwrap();

    // 10. Main service loop
    run_service_loop().await
}

/// Setup the document stream for state synchronization
async fn setup_document_stream<C: Pairing>(
    node: &Node<C>,
    is_bootstrap: bool,
    ticket: Option<String>,
    max_committee_size: usize,
) -> Result<Doc<FlumeConnector<Response, Request>>> {
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
            .await.unwrap();
        
        println!("Entry ticket: {}", ticket);
        
        // Import the document
        let doc_stream = node.docs().import(ticket).await.unwrap();
        
        // Publish config to document
        let config_announcement = Announcement {
            tag: Tag::Config,
            data: config_bytes,
        };
        
        doc_stream
            .set_bytes(
                node.docs().authors().default().await?,
                CONFIG_KEY,
                config_announcement.encode(),
            )
            .await.unwrap();
        
        Ok(doc_stream)
    } else {
        // Join existing network
        let ticket_str = ticket.ok_or_else(|| anyhow::anyhow!("Ticket required for non-bootstrap nodes")).unwrap();
        let doc_ticket = DocTicket::from_str(&ticket_str).unwrap();
        let doc_stream = node.docs().import(doc_ticket).await.unwrap();
        Ok(doc_stream)
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
    
    for i in 1..(our_index as u32) {
        let hint_query = QueryBuilder::<FlatQuery>::default()
            .key_exact(i.to_string())
            .limit(1);
        
        let entry_list = doc_stream.get_many(hint_query.build()).await.unwrap();
        let entry = entry_list.collect::<Vec<_>>().await;
        
        if let Some(Ok(entry)) = entry.first() {
            let hash = entry.content_hash();
            let content = node.blobs().read_to_bytes(hash).await.unwrap();
            let announcement = Announcement::decode(&mut content.slice(..).to_vec().as_slice()).unwrap();
            tx.send(announcement).unwrap();
        }
    }
    
    println!("Loaded {} previous hints", our_index - 1);
    Ok(())
}

/// Publish this node's hint to the network
async fn publish_node_hint<C: Pairing>(
    node: &Node<C>,
    doc_stream: &Doc<FlumeConnector<Response, Request>>,
    index: usize,
    tx: &flume::Sender<Announcement>,
) -> Result<()> {
    let pk = node.get_pk().await
        .ok_or_else(|| anyhow::anyhow!("Failed to compute public key")).unwrap();
    
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
        .await.unwrap();
    
    println!("Published hint to network");
    Ok(())
}

/// Spawn the state synchronization background task
fn spawn_state_sync_service<C: Pairing>(
    doc_stream: Doc<FlumeConnector<Response, Request>>,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
) {
    n0_future::task::spawn(async move {
        if let Err(e) = run_state_sync(doc_stream, node, tx).await {
            eprintln!("State sync error: {:?}", e);
        }
    });
}

/// Run the state synchronization loop
async fn run_state_sync<C: Pairing>(
    doc_stream: Doc<FlumeConnector<Response, Request>>,
    node: Node<C>,
    tx: flume::Sender<Announcement>,
) -> Result<()> {
    // Start syncing with peers
    doc_stream.start_sync(vec![]).await.unwrap();
    
    // Subscribe to document changes
    let mut sub = doc_stream.subscribe().await.unwrap();
    let blobs = node.blobs().clone();
    
    while let Ok(Some(evt)) = sub.try_next().await {
        println!("{:?}", evt);
        
        if let LiveEvent::InsertRemote { entry, .. } = evt {
            // Try to read the blob content
            let msg_body = blobs.read_to_bytes(entry.content_hash()).await;
            
            match msg_body {
                Ok(msg) => {
                    let bytes = msg.to_vec();
                    if let Ok(announcement) = Announcement::decode(&mut &bytes[..]) {
                        tx.send(announcement).unwrap();
                    }
                }
                Err(e) => {
                    eprintln!("Failed to read blob: {:?}", e);
                    // Retry a few times in case still syncing
                    for _ in 0..3 {
                        thread::sleep(Duration::from_secs(1));
                        if let Ok(msg) = blobs.read_to_bytes(entry.content_hash()).await {
                            let bytes = msg.to_vec();
                            if let Ok(announcement) = Announcement::decode(&mut &bytes[..]) {
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
async fn spawn_rpc_service<C: Pairing>(
    state: Arc<Mutex<State<C>>>,
    rpc_port: u16,
) -> Result<()> {
    let addr_str = format!("127.0.0.1:{}", rpc_port);
    let addr = addr_str.parse().unwrap();
    
    let server = NodeServer::<C> { state };
    
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

/// Run the main service loop
async fn run_service_loop() -> Result<()> {
    println!("> Iris node service running...");

    loop {
        tokio::time::sleep(Duration::from_secs(60)).await;
    }
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
        .open("config.txt").unwrap();
    
    write!(&mut file, "{}", hex::encode(&bytes)).unwrap();
    println!("> Saved config to disk");
    
    Ok(bytes)
}