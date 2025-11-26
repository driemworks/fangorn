use anyhow::Result;
use ark_serialize::CanonicalDeserialize;
use iroh::{
    discovery::mdns::MdnsDiscovery,
    endpoint::Connection,
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointAddr,
};
// use iroh_blobs::{net_protocol::Blobs, ALPN as BLOBS_ALPN};
use iroh_blobs::{store::mem::MemStore, BlobsProtocol, ALPN as BLOBS_ALPN};
use iroh_docs::{protocol::Docs, ALPN as DOCS_ALPN};
use iroh_gossip::{net::Gossip, ALPN as GOSSIP_ALPN};
use rust_vault::Vault;
use secrecy::SecretString;

use crate::{crypto::keyvault::{IrohKeyVault, KeyVault, KeyVaultError, Sr25519KeyVault, SteKeyVault}, pool::pool::RawPartialDecryptionMessage};
use crate::{pool::pool::PartialDecryptionMessage, types::*};
use ark_ec::pairing::Pairing;
use codec::Decode;
use silent_threshold_encryption::setup::PublicKey;
use std::{
    net::{Ipv4Addr, SocketAddrV4},
    sync::Arc,
};
use tokio::sync::Mutex;
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
    /// the node state TODO (can we make this non-public?)
    pub state: Arc<Mutex<State<C>>>,
    /// partial decryption receiver
    pd_rx: flume::Receiver<RawPartialDecryptionMessage<C>>,
    /// key vault for Iroh keys
    pub iroh_vault: IrohKeyVault,
    /// key vault for STE keys
    pub ste_vault: SteKeyVault<C>,
    
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

    pub fn pd_rx(&self) -> flume::Receiver<RawPartialDecryptionMessage<C>> {
        self.pd_rx.clone()
    }
}

impl<C: Pairing> Node<C> {
    /// start the node
    pub async fn build(
        bind_port: u16,
        index: usize,
        rx: flume::Receiver<Announcement>,
        state: Arc<Mutex<State<C>>>,
        vault_config: VaultConfig
    ) -> Self {
        println!("Building the node...");
        let (iroh_vault, ste_vault) = create_vaults::<C>(vault_config, index).unwrap();

        // TODO: currently key_name is not used and is managed by the vault instance itself. However, this may change in the future.
        let key_name = String::from("");
        // TODO: file_password should never be hard coded within an application. Currently, we always pass this in via the command line.
        // therefore this field is not actually used. See IrohKeyVault::generate_key or SteKeyVault::generate_key
        let mut file_password = SecretString::new(String::from("").into_boxed_str());

        iroh_vault.generate_key(key_name.clone(), &mut file_password).unwrap();
        ste_vault.generate_key(index).unwrap();
        let endpoint = Endpoint::builder()
            .secret_key(iroh_vault.get_secret_key(key_name.clone(), &mut file_password).unwrap())
            .discovery(
                MdnsDiscovery::builder()
                    .build(iroh_vault.get_public_key(key_name, &mut file_password).unwrap())
                    .unwrap(),
            )
            .bind_addr_v4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, bind_port))
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
        let pd_handler: PartialDecryptionHandler<C> = PartialDecryptionHandler { tx: pd_tx };

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

        // receive and apply state updates
        n0_future::task::spawn(async move {
            while let Ok(announcement) = rx.recv_async().await {
                let mut state = arc_state_clone.lock().await;
                state.update(announcement);
            }
        });

        // n0_future::task::spawn(async move {
        //     while let Ok(partial_decryption_message) = pd_rx.recv_async().await {
        //         println!("handling partial decryptions in the handler in the node");
        //         // get filename
        //         // use it to get the cid
        //         // use the cid to get the data
        //         // decrypt the data with partial decryptions if you have enough (assume threshold = 1 for now)
        //         // save to file with pt_store
        //     }
        // });

        Node {
            endpoint,
            router,
            blobs,
            docs,
            state,
            pd_rx,
            ste_vault,
            iroh_vault,
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
    }

    /// Get the node public key (if it exists)
    pub async fn get_pk(&self) -> Option<PublicKey<C>> {
        let state = &self.state.lock().await;
        if let Some(cfg) = state.config.clone() {
            return Some(self.ste_vault.get_pk(&cfg.crs).unwrap());
        }

        None
    }
}

/// Create vaults. If arguments have not been passed in via the comand line, we will still create the vaults, but they will not have
/// password information stored in them.
pub fn create_vaults<C: Pairing>(vault_config: VaultConfig, index: usize) -> Result<(IrohKeyVault, SteKeyVault<C>), KeyVaultError> {
    let (iroh_vault, ste_vault) = if let (Some(vault_password), Some(iroh_password), Some(ste_password)) = (vault_config.vault_pswd, vault_config.iroh_key_pswd, vault_config.ste_key_pswd) {
        let deref_vault_pass = vault_password.to_owned();
        let vault = Vault::open_or_create(vault_config.vault_dir, &mut deref_vault_pass.clone()).unwrap();
        let iroh_vault = IrohKeyVault::new_store_info(vault.clone(),deref_vault_pass.clone(), iroh_password, index);
        let ste_vault = SteKeyVault::<C>::new_store_info(vault,deref_vault_pass, ste_password, index);
        // let sr25519_vault = Sr25519KeyVault::new(vault);
        (iroh_vault, ste_vault)
    } else {
        let mut master_password = SecretString::new(String::from("vault_password").into_boxed_str());
        let vault = Vault::open_or_create("tmp/keystore", &mut master_password).unwrap();
        let iroh_vault = IrohKeyVault::new(vault.clone(), index);
        let ste_vault = SteKeyVault::<C>::new(vault, index);
        (iroh_vault, ste_vault)
    };
    Ok((iroh_vault, ste_vault))
}

pub const PD_ALPN: &[u8] = b"fangorn/partial-decryption/0";

#[derive(Clone, Debug)]
pub struct PartialDecryptionHandler<C: Pairing> {
    tx: flume::Sender<RawPartialDecryptionMessage<C>>,
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

        let raw: RawPartialDecryptionMessage<C> = RawPartialDecryptionMessage {
            filename: msg.filename,
            index: msg.index,
            partial_decryption,
        };

        let _ = self.tx.send_async(raw.clone()).await;
        // TODO: if the partial decryption is invalid, then do not echo back
        // I think it could be interesting to do something where the decryption requests contains some hidden material
        // and here, we provide a piece of it to anyone who provides a verified partial decryption
        send.write_all(&bytes).await.unwrap();
        send.finish()?;
        connection.closed().await;
        Ok(())
    }
}
