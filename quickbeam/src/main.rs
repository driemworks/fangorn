use anyhow::Result;
use ark_bls12_381::G2Affine as G2;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::rngs::OsRng, UniformRand};
use clap::{Parser, Subcommand};
use fangorn::rpc::server::*;
use fangorn::storage::{local_store::LocalDocStore, IntentStore, SharedStore};
use fangorn::types::*;
use fangorn::verification::{intents::{Intent, IntentType}, challenges::PasswordChallenge, solutions::{PasswordSolution, Solution}};
use multihash_codetable::{Code, MultihashDigest};
use silent_threshold_encryption::{
    aggregate::SystemPublicKeys, decryption::agg_dec, encryption::encrypt,
    setup::PartialDecryption, types::Ciphertext,
};
use std::fs;
use std::str::FromStr;

const MAX_COMMITTEE_SIZE: usize = 2;

#[derive(Parser, Debug)]
#[command(name = "quickbeam", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    /// encrypt a message under a 'policy' and then 'register' it
    Encrypt {
        /// the directory of the plaintext
        #[arg(long)]
        message_dir: String,
        // /// the directory of the file defining the policy
        // #[arg(long)]
        // policy: String,
        /// the directory of the kzg params (fangorn config)
        #[arg(long)]
        config_dir: String,
    },
    /// request to decrypt a message
    /// prepare a witness + send to t-of-n node RPCs
    /// wait for response, then aggr and decrypt
    Decrypt {
        /// the directory of the kzg params
        #[arg(long)]
        config_dir: String,
        /// the content identifier
        #[arg(long)]
        cid: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Encrypt {
            message_dir,
            config_dir,
        }) => {
            handle_encrypt(config_dir, message_dir).await;
        }
        Some(Commands::Decrypt { config_dir, cid }) => {
            handle_decrypt(config_dir, cid).await;
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}

async fn handle_encrypt(config_dir: &String, message_dir: &String) {
    let config_hex = fs::read_to_string(config_dir).expect("you must provide a valid config file.");
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
    // t = 1 , n = MAX, k = 1
    let t = 1;
    let gamma_g2 = G2::rand(&mut OsRng);

    let message =
        fs::read_to_string(message_dir).expect("you must provide a path to a plaintext file.");

    let ct = encrypt::<E>(&ek, t, &config.crs, gamma_g2.into(), message.as_bytes()).unwrap();

    let mut ciphertext_bytes = Vec::new();
    ct.serialize_compressed(&mut ciphertext_bytes).unwrap();

    // create docstore (same dir as in service.rs)
    let shared_store = LocalDocStore::new("tmp/docs/", "tmp/intents/");
    // write the ciphertext
    let cid = shared_store.add(&ciphertext_bytes).await.unwrap();

    let password_vec: Vec<u8> = "ideallabs".as_bytes().to_vec();
    let password_hash = Code::Sha2_256.digest(&password_vec).to_bytes();

    let intent_type = IntentType::Challenge;
    let intent =
        Intent::create_intent::<PasswordChallenge>(&password_hash, &password_vec, intent_type);

    let _ = shared_store
        .register_intent(&cid, &intent)
        .await
        .expect("An error occurred when registering intent in shared store");

    println!("> Saved ciphertext to /tmp/{}.dat", &cid.to_string());
    println!("> Saved intent to /tmp/intents/{}.ents", &cid.to_string());
}

async fn handle_decrypt(config_dir: &String, cid_string: &String) {
    // read the config
    let config_hex = fs::read_to_string(config_dir).expect("you must provide a valid config file.");
    let config_bytes = hex::decode(&config_hex).unwrap();
    let config = Config::<E>::deserialize_compressed(&config_bytes[..]).unwrap();
    // get the ciphertext
    let doc_store = LocalDocStore::new("tmp/docs/", "tmp/intents/");
    let cid = cid::Cid::from_str(cid_string).unwrap();

    // living dangerously...
    let ciphertext_bytes = doc_store.fetch(&cid).await.unwrap().unwrap();
    let ciphertext = Ciphertext::<E>::deserialize_compressed(&ciphertext_bytes[..]).unwrap();
    //  get the sys key (TODO: send this as a cli param instead?)
    let sys_key_request = tonic::Request::new(PreprocessRequest {});

    // TODO: generate the witness here

    let password_vec = "ideallabs".as_bytes().to_vec();
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
            cid: cid.to_string(),
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
