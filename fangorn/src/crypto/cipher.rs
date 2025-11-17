use crate::node::Node;
use crate::rpc::server::*;
use crate::storage::{
    contract_store::ContractIntentStore,
    iroh_docstore::IrohDocStore,
    local_store::{LocalDocStore, LocalPlaintextStore},
    AppStore,
};
use crate::types::*;
use crate::{
    backend::SubstrateBackend,
    crypto::{decrypt::DecryptionClient, encrypt::EncryptionClient},
    gadget::{GadgetRegistry, PasswordGadget, Psp22Gadget, Sr25519Gadget},
    storage::PlaintextStore,
    utils::load_mnemonic,
};
use ark_serialize::CanonicalDeserialize;
use silent_threshold_encryption::aggregate::SystemPublicKeys;
use std::str::FromStr;
use std::sync::Arc;

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
) {
    let seed = load_mnemonic(keystore_path);
    let (sys_keys, gadget_registry, app_store) =
        iroh_testnet_setup(contract_addr, Some(&seed), node, ticket.clone()).await;

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
) {
    // let (sys_keys, _registry, app_store) = local_testnet_setup(contract_addr, None).await;
    let (sys_keys, gadget_registry, app_store) =
        iroh_testnet_setup(contract_addr, None, node, ticket.clone()).await;
    // Parse witnesses
    let witnesses: Vec<&str> = witness_string.trim().split(',').map(|s| s.trim()).collect();

    // Decrypt
    let client = DecryptionClient::new(config_path, sys_keys, app_store).unwrap();
    client
        .decrypt(filename, &witnesses, pt_filename)
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
) -> (SystemPublicKeys<E>, GadgetRegistry, LocalTestnetAppStore) {
    let sys_keys = get_system_keys().await;

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

    (sys_keys, gadget_registry, app_store)
}

async fn iroh_testnet_setup(
    contract_addr: &String,
    seed: Option<&str>,
    node: Node<E>,
    ticket: String,
) -> (SystemPublicKeys<E>, GadgetRegistry, TestnetAppStore) {
    let sys_keys = get_system_keys().await;

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
        IrohDocStore::new(node, ticket).await,
        ContractIntentStore::new(contract_addr.to_string(), backend),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    (sys_keys, gadget_registry, app_store)
}

async fn get_system_keys() -> SystemPublicKeys<E> {
    let mut client = RpcClient::connect("http://127.0.0.1:30332").await.unwrap();
    let response = client.preprocess(PreprocessRequest {}).await.unwrap();
    let hex = response.into_inner().hex_serialized_sys_key;
    let bytes = hex::decode(&hex).unwrap();
    SystemPublicKeys::<E>::deserialize_compressed(&bytes[..]).unwrap()
}
