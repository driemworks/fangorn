use crate::rpc::server::*;
use crate::storage::{
    contract_store::ContractIntentStore,
    local_store::{LocalDocStore, LocalPlaintextStore},
    AppStore, DocStore, IntentStore, SharedStore,
};
use crate::types::*;
use crate::{
    crypto::keystore::{Keystore, Sr25519Keystore},
    entish::{
        challenges::PasswordChallenge,
        intents::Intent,
        solutions::{PasswordSolution, Solution},
    },
    storage::PlaintextStore,
    utils::decode_contract_addr,
};
use ark_bls12_381::G2Affine as G2;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use multihash_codetable::{Code, MultihashDigest};
use silent_threshold_encryption::{
    aggregate::SystemPublicKeys, decryption::agg_dec, encryption::encrypt,
    setup::PartialDecryption, types::Ciphertext,
};
use sp_application_crypto::Ss58Codec;
use std::fs;
use std::str::FromStr;

const MAX_COMMITTEE_SIZE: usize = 2;

/// encrypt the message located at message_path
pub async fn handle_encrypt(
    message_path: &String,
    filename: &String,
    config_path: &String,
    keystore_path: &String,
    intent_str: &String,
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
    let mut client = RpcClient::connect("http://127.0.0.1:30333").await.unwrap();
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

    let contract_addr_bytes =
        decode_contract_addr(crate::CONTRACT_ADDR);
    let app_store = AppStore::new(
        LocalDocStore::new("tmp/docs/"),
        ContractIntentStore::new(
            "ws://localhost:9933".to_string(),
            contract_addr_bytes,
            Some(&seed),
        )
        .await
        .unwrap(),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    // build the ciphertext
    let message = app_store
        .pt_store
        .read_plaintext(message_path)
        .await
        .expect("Something went wrong while reading PT");
    let ct = encrypt::<E>(&ek, t, &config.crs, gamma_g2.into(), message.as_bytes()).unwrap();
    let mut ciphertext_bytes = Vec::new();
    ct.serialize_compressed(&mut ciphertext_bytes).unwrap();

    // write the ciphertext
    let cid = app_store.doc_store.add(&ciphertext_bytes).await.unwrap();
    // parse the intent
    let intent = Intent::try_from_string(intent_str).unwrap();
    // format filename
    let filename_bytes = filename.clone().into_bytes();
    // register it
    let _ = app_store
        .intent_store
        .register_intent(&filename_bytes, &cid, &intent)
        .await
        .expect("An error occurred when registering intent in shared store");

    println!("> Saved ciphertext to /tmp/{}", &cid.to_string());
}

/// try to load the mnemomic from the file
/// not secure
fn load_mnemonic(keystore_path: &String) -> String {
    // going dumb and simple for now: just read the first file in the dir
    let mut files: Vec<_> = fs::read_dir(keystore_path)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_file())
        .collect();

    let seed = fs::read_to_string(files[0].path()).expect("Issue reading keystore");
    let formatted = seed.trim().trim_matches('"');
    formatted.to_string()
}

/// decryption!

pub async fn handle_decrypt(
    config_path: &String,
    filename: &String,
    witness_string: &String,
    pt_filename: &String,
) {
    // read the config
    let config_hex =
        fs::read_to_string(config_path).expect("you must provide a valid config file.");
    let config_bytes = hex::decode(&config_hex).unwrap();
    let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();
    // get the ciphertext
    let contract_addr_bytes =
        decode_contract_addr(crate::CONTRACT_ADDR);
    let app_store = AppStore::new(
        LocalDocStore::new("tmp/docs/"),
        ContractIntentStore::new("ws://localhost:9933".to_string(), contract_addr_bytes, None)
            .await
            .unwrap(),
        LocalPlaintextStore::new("tmp/plaintexts/"),
    );

    // TODO: fetch the cid and intent from filename
    let (cid, _intent)  = app_store
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

    // encode witness
    let password_vec = witness_string.as_bytes().to_vec();
    let witness = PasswordSolution::prepare_witness(password_vec);
    let witness_hex = hex::encode(witness.0);

    // from first node
    let mut client = RpcClient::connect("http://127.0.0.1:30333").await.unwrap();
    let response = client.preprocess(sys_key_request).await.unwrap();
    let hex = response.into_inner().hex_serialized_sys_key;
    let bytes = hex::decode(&hex[..]).unwrap();
    let sys_keys = SystemPublicKeys::<E>::deserialize_compressed(&bytes[..]).unwrap();

    let subset = vec![0, 1];
    let (ak, _ek) = sys_keys.get_aggregate_key(&subset, &config.crs, &config.lag_polys);

    let mut partial_decryptions = vec![PartialDecryption::zero(); ak.lag_pks.len()];

    for i in 0..1 {
        let node_id = ak.lag_pks[i].id;
        let rpc_port = match node_id {
            0 => 30333,
            1 => 30334,
            _ => panic!("Unknown node"),
        };

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
