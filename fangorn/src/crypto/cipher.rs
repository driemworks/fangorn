use crate::rpc::{resolver::IrohRpcResolver, server::*};
use crate::storage::{
    contract_store::ContractIntentStore,
    iroh_docstore::IrohDocStore,
    local_store::{LocalDocStore, LocalPlaintextStore},
    AppStore,
};
use crate::types::*;
use crate::Node;
use crate::{
    backend::{iroh::IrohBackend, SubstrateBackend},
    crypto::{decrypt::DecryptionClient, encrypt::EncryptionClient},
    gadget::{GadgetRegistry, PasswordGadget, Psp22Gadget, Sr25519Gadget},
    pool::pool::IrohPool,
    storage::PlaintextStore,
    utils::load_mnemonic,
};
use anyhow::Result;
use ark_ec::pairing::Pairing;
use ark_serialize::CanonicalDeserialize;
use codec::Decode;
use iroh_docs::{
    store::{FlatQuery, QueryBuilder},
    DocTicket,
};
use n0_future::StreamExt;
use silent_threshold_encryption::aggregate::SystemPublicKeys;
use std::str::FromStr;
use std::sync::Arc;
use subxt::config::polkadot::AccountId32;
use tokio::sync::Mutex;


/// encrypt the message located at message_path
pub async fn handle_encrypt(
    message_path: &String,
    filename: &String,
    config_path: &String,
    keystore_path: &String,
    intent_str: &String,
    contract_addr: &String,
    node: Node<E>,
    ticket: &String,
    sys_keys: SystemPublicKeys<E>,
) {
    let seed = load_mnemonic(keystore_path);
    let (gadget_registry, app_store) =
        iroh_testnet_setup(contract_addr, Some(&seed), node.clone(), ticket.clone()).await;

    let message = app_store
        .pt_store
        .read_plaintext(message_path)
        .await
        .expect("Something went wrong while reading PT");

    let client = EncryptionClient::new(config_path, sys_keys, app_store, gadget_registry);
    client
        .encrypt(&message, filename.as_bytes(), &intent_str)
        .await
        .unwrap();
}

pub async fn handle_decrypt(
    config_path: &String,
    filename: &String,
    witness_string: &String,
    pt_filename: &String,
    contract_addr: &String,
    node: Node<E>,
    ticket: &String,
    sys_keys: SystemPublicKeys<E>,
) {
    // we could split this up now with a public witness:
    // that's pretty pointless to put on chain or make public though...
    // we 100% need to do a zk approach here!!! z
    let (gadget_registry, app_store) =
        iroh_testnet_setup(contract_addr, None, node.clone(), ticket.clone()).await;

    // Parse witnesses
    let witnesses: Vec<&str> = witness_string.trim().split(',').map(|s| s.trim()).collect();

    let doc_ticket = DocTicket::from_str(&ticket).unwrap();
    let doc_stream = node.docs().import(doc_ticket).await.unwrap();

    // initialize iroh backend for the decryption client
    let iroh_backend = Arc::new(IrohBackend::new(node.clone()));
    let request_pool = Arc::new(Mutex::new(
        IrohPool::new(iroh_backend, ticket).await.unwrap(),
    ));

    // Decrypt
    let client =
        DecryptionClient::new(config_path, sys_keys, app_store, request_pool, node.clone())
            .unwrap();
    client
        .request_decrypt(filename, &witnesses, pt_filename)
        .await
        .unwrap();
}

/// an app store that uses the iroh nodes for storage
/// against a smart contract deployed on the configured substrate backend
type TestnetAppStore = AppStore<IrohDocStore<E>, ContractIntentStore, LocalPlaintextStore>;

/// an app store configured for all nodes running on the same machine,
/// against a smart contract deployed on the configured substrate backend
type LocalTestnetAppStore = AppStore<LocalDocStore, ContractIntentStore, LocalPlaintextStore>;

async fn local_testnet_setup(
    contract_addr: &String,
    seed: Option<&str>,
) -> (GadgetRegistry, LocalTestnetAppStore) {
    // let sys_keys = get_system_keys().await;

    // build the backend
    let backend = Arc::new(
        SubstrateBackend::new(crate::WS_URL.to_string(), seed)
            .await
            .unwrap(),
    );
    // configure the registry
    let mut gadget_registry = GadgetRegistry::new();
    gadget_registry.register(PasswordGadget {});
    gadget_registry.register(Psp22Gadget::new(backend.clone()));
    gadget_registry.register(Sr25519Gadget::new(backend.clone()));

    let app_store = AppStore::new(
        LocalDocStore::new("tmp/docs/"),
        ContractIntentStore::new(contract_addr.to_string(), backend),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    (gadget_registry, app_store)
}

async fn iroh_testnet_setup(
    contract_addr: &String,
    seed: Option<&str>,
    node: Node<E>,
    ticket: String,
) -> (GadgetRegistry, TestnetAppStore) {
    // build the backend
    let backend = Arc::new(
        SubstrateBackend::new(crate::WS_URL.to_string(), seed)
            .await
            .unwrap(),
    );
    // initialize iroh backend
    let iroh_backend = Arc::new(IrohBackend::new(node.clone()));

    // configure the registry
    let mut gadget_registry = GadgetRegistry::new();
    gadget_registry.register(PasswordGadget {});
    gadget_registry.register(Psp22Gadget::new(backend.clone()));
    gadget_registry.register(Sr25519Gadget::new(backend.clone()));

    let app_store = AppStore::new(
        IrohDocStore::new(node, &ticket, iroh_backend).await,
        ContractIntentStore::new(contract_addr.to_string(), backend),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    (gadget_registry, app_store)
}

// async fn load_system_keys_from_doc<C: Pairing>(
//     node: &Node<C>,
//     ticket: &str,
// ) -> Result<SystemPublicKeys<C>> {
//     let doc_ticket = DocTicket::from_str(ticket)?;
//     let doc = node.docs().import(doc_ticket).await?;

//     // Query for system keys
//     let query = QueryBuilder::<FlatQuery>::default()
//         .key_exact(SYSTEM_KEYS_KEY)
//         .limit(1);

//     let entries = doc.get_many(query.build()).await?;
//     let entry_vec = entries.collect::<Vec<_>>().await;

//     println!("GOT ENTRIES {:?}", entry_vec);

//     let entry = entry_vec
//         .first()
//         .ok_or_else(|| anyhow::anyhow!("System keys not found in doc"))?
//         .as_ref()
//         .map_err(|e| anyhow::anyhow!("Failed to get entry: {:?}", e))?;

//     // Fetch content
//     let hash = entry.content_hash();
//     let content = node.blobs().get_bytes(hash).await?;
//     let announcement = Announcement::decode(&mut &content[..])?;

//     // Deserialize system keys
//     let sys_keys = SystemPublicKeys::<C>::deserialize_compressed(&announcement.data[..])?;

//     println!("Loaded system keys from network");
//     Ok(sys_keys)
// }
