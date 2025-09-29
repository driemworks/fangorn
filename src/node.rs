use anyhow::Result;
use iroh::{protocol::Router, Endpoint, NodeAddr};
use iroh_blobs::{net_protocol::Blobs, ALPN as BLOBS_ALPN};
use iroh_docs::{protocol::Docs, ALPN as DOCS_ALPN};
use iroh_gossip::{net::Gossip, ALPN as GOSSIP_ALPN};

use crate::types::*;
use ark_ec::pairing::Pairing;
use silent_threshold_encryption::setup::PublicKey;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};
use tokio::sync::Mutex;

use quic_rpc::transport::flume::FlumeConnector;

pub(crate) type BlobsClient = iroh_blobs::rpc::client::blobs::Client<
    FlumeConnector<iroh_blobs::rpc::proto::Response, iroh_blobs::rpc::proto::Request>,
>;
pub(crate) type DocsClient = iroh_docs::rpc::client::docs::Client<
    FlumeConnector<iroh_docs::rpc::proto::Response, iroh_docs::rpc::proto::Request>,
>;
pub(crate) type GossipClient = iroh_gossip::rpc::client::Client<
    FlumeConnector<iroh_gossip::rpc::proto::Response, iroh_gossip::rpc::proto::Request>,
>;

/// A node...
#[derive(Clone)]
pub struct Node<C: Pairing> {
    /// the iroh endpoint
    endpoint: Endpoint,
    /// the iroh router
    router : Router,
    /// blobs client
    blobs: BlobsClient,
    /// docs client
    docs: DocsClient,
    /// the iroh-gossip protocol
    gossip: GossipClient,
    // / the secret key the node uses to sign messages
    // iroh_secret_key: IrohSecretKey,
    // / the bls secret key
    // secret_key: SecretKey<C>,
    /// the node state
    state: Arc<Mutex<State<C>>>,
}

impl<C: Pairing> Node<C> {
    pub fn blobs(&self) -> BlobsClient {
        self.blobs.clone()
    }

    pub fn docs(&self) -> DocsClient {
        self.docs.clone()
    }
}

impl<C: Pairing> Node<C> {
    /// start the node
    pub async fn build(
        params: StartNodeParams<C>,
        rx: flume::Receiver<Announcement>,
        state: Arc<Mutex<State<C>>>,
    ) -> Self {
        println!("Building the node...");
        let endpoint = Endpoint::builder()
            .secret_key(params.iroh_secret_key.clone())
            .discovery_n0()
            .discovery_local_network()
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, params.bind_port))
            .bind()
            .await
            .unwrap();
        // build gossip protocol
        let gossip = Gossip::builder().spawn(endpoint.clone()).await.unwrap();
        // build the blobs protocol (just in mem for now, not persistent)
        let blobs = Blobs::memory().build(&endpoint.clone());
        // build the docs protocol (just in mem for now, not persistent)
        let docs = Docs::memory().spawn(&blobs, &gossip).await.unwrap();
        // setup router
        let router = Router::builder(endpoint.clone())
            .accept(GOSSIP_ALPN, gossip.clone())
            .accept(BLOBS_ALPN, blobs.clone())
            .accept(DOCS_ALPN, docs.clone())
            .spawn()
            .await
            .unwrap();

        let addr = router.endpoint().node_addr().await;
        println!("> Generated node address: {:?}", addr);

        let arc_state_clone = Arc::clone(&state);

        n0_future::task::spawn(async move {
            while let Ok(announcement) = rx.recv_async().await {
                let mut state = arc_state_clone.lock().await;
                state.update(announcement);
            }
        });

        Node {
            endpoint,
            router,
            blobs: blobs.client().clone(),
            docs: docs.client().clone(),
            gossip: gossip.client().clone(),
            state,
        }
    }

    /// join the gossip topic by connecting to known peers, if any
    pub async fn try_connect_peers(&mut self, peers: Option<Vec<NodeAddr>>) -> Result<()> {
        match peers {
            Some(bootstrap) => {
                println!("> trying to connect to {} peer(s)", bootstrap.len());
                // add the peer addrs to our endpoint's addressbook so that they can be dialed
                for peer in bootstrap.into_iter() {
                    self.endpoint.add_node_addr(peer)?;
                }
            }
            None => {
                // do nothing
            }
        };

        println!("> Connection established.");
        Ok(())
    }

    /// Get the node public key (if it exists)
    pub async fn get_pk(&self) -> Option<PublicKey<C>> {
        let state = &self.state.lock().await;
        if let (Some(cfg), sk) = (state.config.clone(), state.sk.clone()) {
            return Some(sk.get_pk(&cfg.crs));
        }

        None
    }
}
