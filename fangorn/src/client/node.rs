use anyhow::Result;
use ark_serialize::CanonicalDeserialize;
use iroh::{
    discovery::{mdns::MdnsDiscovery, Discovery},
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr,
};
// use iroh_blobs::{net_protocol::Blobs, ALPN as BLOBS_ALPN};
use iroh_blobs::{store::mem::MemStore, BlobsProtocol, ALPN as BLOBS_ALPN};
use iroh_docs::{protocol::Docs, ALPN as DOCS_ALPN};
use iroh_gossip::{net::Gossip, ALPN as GOSSIP_ALPN};
use n0_error::{Result as N0Result, StdResultExt};

use crate::{pool::pool::PartialDecryptionMessage, types::*};
use ark_ec::pairing::Pairing;
use codec::Decode;
use silent_threshold_encryption::setup::PublicKey;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};
use tokio::sync::Mutex;

use quic_rpc::transport::flume::FlumeConnector;
use silent_threshold_encryption::setup::PartialDecryption;
use std::{fs::OpenOptions, io::Write};

/// A node...
#[derive(Clone)]
pub struct Node<C: Pairing> {
    /// the iroh endpoint
    endpoint: Endpoint,
    /// the iroh router
    pub router: Router,
    /// blobs client
    blobs: BlobsProtocol,
    /// docs client
    docs: Docs,
    /// the node state
    state: Arc<Mutex<State<C>>>,
    /// partial decryption receiver
    pd_rx: flume::Receiver<PartialDecryption<C>>,
}

impl<C: Pairing> Node<C> {
    pub fn blobs(&self) -> BlobsProtocol {
        self.blobs.clone()
    }

    pub fn docs(&self) -> Docs {
        self.docs.clone()
    }

    pub fn endpoint(&self) -> Endpoint {
        self.router.endpoint().clone()
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
            // TODO: keystore integration
            .discovery(
                MdnsDiscovery::builder()
                    .build(params.iroh_secret_key.public())
                    .unwrap(),
            )
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, params.bind_port))
            .bind()
            .await
            .unwrap();
        // build gossip protocol
        let gossip = Gossip::builder().spawn(endpoint.clone());
        // build the store (memstore for now)
        let store = MemStore::new();
        let blobs = BlobsProtocol::new(&store, None);
        // build the docs protocol (just in mem for now, not persistent)
        let docs = Docs::memory()
            .spawn(endpoint.clone(), store.clone().into(), gossip.clone())
            .await
            .unwrap();

        let (pd_tx, pd_rx) = flume::unbounded();
        let pd_handler = PartialDecryptionHandler { tx: pd_tx };

        // setup router
        let router = Router::builder(endpoint.clone())
            .accept(PD_ALPN, pd_handler)
            .accept(GOSSIP_ALPN, gossip.clone())
            .accept(BLOBS_ALPN, blobs.clone())
            .accept(DOCS_ALPN, docs.clone())
            .spawn();

        let addr = router.endpoint().addr();
        println!("> Generated node address: {:?}", addr);
        let pubkey = addr.id.to_string();
        // TODO: once we impl a proper keystore we can remove this
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open("pubkey.txt")
            .unwrap();
        writeln!(&mut file, "{}", pubkey).expect("Unable to write pubkey to file.");
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
            blobs,
            docs,
            state,
            pd_rx,
        }
    }

    /// join the gossip topic by connecting to known peers, if any
    // also peers does not need to be an option here!
    pub async fn try_connect_peers(&mut self, peers: Option<Vec<EndpointAddr>>) -> Result<()> {
        match peers {
            Some(bootstrap) => {
                println!("> trying to connect to {} peer(s)", bootstrap.len());
                // add the peer addrs to our endpoint's addressbook so that they can be dialed
                for peer in bootstrap.into_iter() {
                    self.connect_to_peer_for_multiple_protocols(peer).await;
                }
            }
            None => {
                // do nothing
            }
        };

        println!("> Connection established.");
        Ok(())
    }

    async fn connect_to_peer_for_multiple_protocols(&self, peer_addr: EndpointAddr) {
        let _blobs_conn = self
            .endpoint
            .connect(peer_addr.clone(), BLOBS_ALPN)
            .await
            .unwrap();
        let _docs_conn = self
            .endpoint
            .connect(peer_addr.clone(), DOCS_ALPN)
            .await
            .unwrap();
        let _gossip_conn = self
            .endpoint
            .connect(peer_addr.clone(), GOSSIP_ALPN)
            .await
            .unwrap();
        // should probably be optional or even external?
        // let _pd_conn = self.endpoint.connect(peer_addr, PD_ALPN).await.unwrap();
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

pub const PD_ALPN: &[u8] = b"fangorn/partial-decryption/0";

#[derive(Clone, Debug)]
pub struct PartialDecryptionHandler<C: Pairing> {
    tx: flume::Sender<PartialDecryption<C>>,
}

impl<C: Pairing> ProtocolHandler for PartialDecryptionHandler<C> {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        let endpoint_id = connection.remote_id();
        println!("accepted connection from {endpoint_id}");

        let (mut send, mut recv) = connection.accept_bi().await.unwrap();

        let bytes = recv.read_to_end(1024 * 1024).await.unwrap();
        println!("Received bytes - attempting to decode");
        let msg = PartialDecryptionMessage::decode(&mut &bytes[..]).unwrap();
        println!("Decoded the message successfully");
        // now deserialize the pd
        let partial_decryption =
            PartialDecryption::<C>::deserialize_compressed(&msg.partial_decryption_bytes[..])
                .unwrap();

        let _ = self.tx.send_async(partial_decryption.clone()).await;
        // TODO: if the partial decryption is invalid, then do not echo back
        send.write_all(&bytes).await.unwrap();
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}
