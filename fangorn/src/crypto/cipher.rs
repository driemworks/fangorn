use crate::rpc::server::*;
use crate::storage::{
    contract_store::ContractIntentStore,
    local_store::{LocalDocStore, LocalPlaintextStore},
    AppStore, DocStore, IntentStore, SharedStore,
};
use crate::types::*;
use crate::{
    backend::{BlockchainBackend, SubstrateBackend},
    crypto::keystore::{Keystore, Sr25519Keystore},
    gadget::{GadgetRegistry, PasswordGadget, Psp22Gadget, Sr25519Gadget},
    storage::PlaintextStore,
    utils::load_mnemonic,
};
use ark_bls12_381::G2Affine as G2;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use codec::Encode;
use multihash_codetable::{Code, MultihashDigest};
use silent_threshold_encryption::{
    aggregate::SystemPublicKeys, decryption::agg_dec, encryption::encrypt,
    setup::PartialDecryption, types::Ciphertext,
};
use sp_application_crypto::Ss58Codec;
use std::fs;
use std::str::FromStr;
use std::sync::Arc;

const MAX_COMMITTEE_SIZE: usize = 2;

/// encrypt the message located at message_path
pub async fn handle_encrypt(
    message_path: &String,
    filename: &String,
    config_path: &String,
    keystore_path: &String,
    intent_str: &String,
    contract_addr: &String,
) {
    let config_hex =
        fs::read_to_string(config_path).expect("you must provide a valid config file.");
    let config_bytes = hex::decode(&config_hex).unwrap();
    let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();

    // TODO: make this a parameter instead
    // we don't need to make the rpc request here
    // get the sys key
    let sys_key_request = tonic::Request::new(PreprocessRequest {});
    // from first node
    let mut client = RpcClient::connect("http://127.0.0.1:30332").await.unwrap();
    let response = client.preprocess(sys_key_request).await.unwrap();
    let hex = response.into_inner().hex_serialized_sys_key;
    let bytes = hex::decode(&hex[..]).unwrap();
    let sys_keys = SystemPublicKeys::<E>::deserialize_compressed(&bytes[..]).unwrap();
    let subset = vec![0, 1];
    // we could just read `ek` from the request
    let (_ak, ek) = sys_keys.get_aggregate_key(&subset, &config.crs, &config.lag_polys);
    // t = 1 , n = MAX, k = 1*
    let t = 1;
    let gamma_g2 = G2::rand(&mut OsRng);

    let seed = load_mnemonic(keystore_path);

    // build the backend
    let backend = Arc::new(
        SubstrateBackend::new(crate::WS_URL.to_string(), Some(&seed))
            .await
            .unwrap(),
    );
    // configure the registry
    let mut gadget_registry = GadgetRegistry::new();
    gadget_registry.register(PasswordGadget {});
    gadget_registry.register(Psp22Gadget::new(contract_addr.to_string(), backend.clone()));
    gadget_registry.register(Sr25519Gadget::new(backend.clone()));

    let app_store = AppStore::new(
        LocalDocStore::new("tmp/docs/"),
        ContractIntentStore::new(contract_addr.to_string(), backend),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    // build the ciphertext
    let message = app_store
        .pt_store
        .read_plaintext(message_path)
        .await
        .expect("Something went wrong while reading PT");

    let ct = encrypt::<E>(&ek, t, &config.crs, gamma_g2.into(), &message).unwrap();
    let mut ciphertext_bytes = Vec::new();
    ct.serialize_compressed(&mut ciphertext_bytes).unwrap();

    // write the ciphertext
    let cid = app_store.doc_store.add(&ciphertext_bytes).await.unwrap();
    // parse the intent
    let intents = gadget_registry.parse_intents(intent_str).await.unwrap();
    // .map_err(|e| EncryptionError::IntentError(e))?;
    // format filename
    let filename_bytes = filename.clone().into_bytes();
    // register intents
    let _ = app_store
        .intent_store
        .register_intent(&filename_bytes, &cid, intents)
        .await
        .expect("An error occurred when registering intent in shared store");

    println!("> Saved ciphertext to /tmp/{}", &cid.to_string());
}

// // todo: create generic encrypt and decrypt function here
// async fn encrypt(
//     ek:
// gadget_registry
// app_store,
// plaintext,
// config,
// ) [

// ]

pub async fn handle_decrypt(
    config_path: &String,
    filename: &String,
    witness_string: &String,
    pt_filename: &String,
    contract_addr: &String,
) {
    // read the config
    let config_hex =
        fs::read_to_string(config_path).expect("you must provide a valid config file.");
    let config_bytes = hex::decode(&config_hex).unwrap();
    let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();
    // get the ciphertext
    // build the backend
    let backend = Arc::new(
        SubstrateBackend::new(crate::WS_URL.to_string(), None)
            .await
            .unwrap(),
    );
    // configure the registry
    let mut gadget_registry = GadgetRegistry::new();
    gadget_registry.register(PasswordGadget {});
    gadget_registry.register(Psp22Gadget::new(contract_addr.to_string(), backend.clone()));
    gadget_registry.register(Sr25519Gadget::new(backend.clone()));

    let app_store = AppStore::new(
        LocalDocStore::new("tmp/docs/"),
        ContractIntentStore::new(contract_addr.to_string(), backend),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    // TODO: fetch the cid and intent from filename
    let (cid, _intents) = app_store
        .intent_store
        .get_intent(&filename.clone().into_bytes())
        .await
        .unwrap()
        .unwrap();

    // living dangerously...
    let ciphertext_bytes = app_store.doc_store.fetch(&cid).await.unwrap().unwrap();
    let ciphertext = Ciphertext::<E>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();
    //  get the sys key (TODO: send this as a cli param instead?)
    let sys_key_request = tonic::Request::new(PreprocessRequest {});

    // encode witnesses
    // split by comma
    // w1, w2, ..., wk
    let witness_parts: Vec<_> = witness_string.trim().split(",").collect();
    // [w1_bytes, w2_bytes, ..., wk_bytes]
    let witness_bytes: Vec<Vec<u8>> = witness_parts.iter().map(|w| w.as_bytes().to_vec()).collect();
    let witness_vec = witness_bytes.encode();
    let witness_hex = hex::encode(witness_vec);

    // from first node
    let mut client = RpcClient::connect("http://127.0.0.1:30332").await.unwrap();
    let response = client.preprocess(sys_key_request).await.unwrap();
    let hex = response.into_inner().hex_serialized_sys_key;
    let bytes = hex::decode(&hex[..]).unwrap();
    let sys_keys = SystemPublicKeys::<E>::deserialize_compressed(&bytes[..]).unwrap();

    let subset = vec![0, 1];
    let (ak, _ek) = sys_keys.get_aggregate_key(&subset, &config.crs, &config.lag_polys);

    // a map to hold partial decs
    let mut partial_decryptions = vec![PartialDecryption::zero(); ak.lag_pks.len()];

    for i in 0..1 {
        let node_id = ak.lag_pks[i].id;
        let rpc_port = match node_id {
            0 => 30332,
            1 => 30334,
            _ => panic!("Unknown node"),
        };

        println!("Sending query against rpc port: {:?}", rpc_port);
        let mut client = RpcClient::connect(format!("http://127.0.0.1:{}", rpc_port))
            .await
            .unwrap();

        let request = tonic::Request::new(PartDecRequest {
            filename: filename.clone(),
            witness_hex: witness_hex.clone(),
        });

        let response = client
            .partdec(request)
            .await
            .expect("Something went wrong with the partial decryption request");
        let part_dec_hex = response.into_inner().hex_serialized_decryption;
        let part_dec_bytes =
            hex::decode(&part_dec_hex).expect("Couldn't decode partial decryption hex");
        partial_decryptions[i] = PartialDecryption::deserialize_compressed(&part_dec_bytes[..])
            .expect("Couldn't deserialize the partial decryption bytes");
    }

    println!("> Collected partial decryptions, attempting to decrypt the ciphertext");

    let mut selector = vec![false; MAX_COMMITTEE_SIZE];
    selector[0] = true;
    // if k = 2 => selector[1] =  true; too

    let mut pds = Vec::new();
    partial_decryptions.iter().for_each(|pd| {
        let mut test = Vec::new();
        pd.serialize_compressed(&mut test).unwrap();
        pds.push(test);
    });

    let mut ct_bytes = Vec::new();
    ciphertext.serialize_compressed(&mut ct_bytes).unwrap();

    let plaintext = agg_dec(
        &partial_decryptions,
        &ciphertext,
        &selector,
        &ak,
        &config.crs,
    )
    .unwrap();

    app_store
        .pt_store
        .write_to_pt_store(pt_filename, &plaintext)
        .await
        .expect("Something went wrong with PT file persistence");
}
