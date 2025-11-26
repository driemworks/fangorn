use std::{io::Read, time::SystemTime};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fangorn::{
    backend::substrate::runtime::{runtime_apis::core::types::version, sudo::storage::types::key},
    crypto::{
        cipher::{handle_decrypt, handle_encrypt},
        keystore::{Keystore, Sr25519Keystore},
        keyvault::{IrohKeyVault, KeyVault, Sr25519KeyVault},
        FANGORN,
    },
};
use rust_vault::Vault;
use secrecy::{ExposeSecretMut, SecretString};
use sp_core::{
    bytes::{from_hex, to_hex},
    crypto::Zeroize,
    hexdisplay::AsBytesRef,
    sr25519::Signature as SrSignature,
    ByteArray,
};
// use sp_core::crypto::{ExposeSecret, SecretString};
use ark_serialize::CanonicalDeserialize;
use fangorn::{types::*, Node};
use iroh::{EndpointAddr, PublicKey as IrohPublicKey};
use silent_threshold_encryption::aggregate::SystemPublicKeys;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::{sync::Mutex, task};

#[derive(Parser, Debug)]
#[command(name = "quickbeam", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Clone, Debug, ValueEnum)]
enum StoreType {
    Polkadot,
    Fangorn,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    Keygen {
        // the keystore directory
        #[arg(long)]
        keystore_dir: String,
    },
    KeygenPswd {
        #[arg(long)]
        keystore_dir: String,

        #[arg(long)]
        password: SecretString,

        #[arg(value_enum)]
        store_type: StoreType,
    },
    InspectPswd {
        #[arg(long)]
        keystore_dir: String,

        #[arg(long)]
        password: SecretString,

        #[arg(value_enum)]
        store_type: StoreType,
    },
    SignPswd {
        #[arg(long)]
        keystore_dir: String,

        #[arg(long)]
        password: SecretString,

        #[arg(value_enum)]
        store_type: StoreType,

        #[arg(long)]
        nonce: u32,
    },
    VerifyPswd {
        #[arg(long)]
        keystore_dir: String,

        #[arg(long)]
        password: SecretString,

        #[arg(value_enum)]
        store_type: StoreType,

        #[arg(long)]
        signature_hex: String,

        #[arg(long)]
        nonce: u32,
    },
    Inspect {
        // the keystore directory
        #[arg(long)]
        keystore_dir: String,
    },
    Sign {
        #[arg(long)]
        keystore_dir: String,
        #[arg(long)]
        nonce: u32,
    },
    /// encrypt a message under a 'policy' and then 'register' it
    Encrypt {
        /// the path to the plaintext
        #[arg(long)]
        message_path: String,
        /// the filename to assign to the document
        #[arg(long)]
        filename: String,
        /// the path to the file containing the kzg params (fangorn config)
        #[arg(long)]
        config_path: String,
        /// the keystore directory
        #[arg(long)]
        keystore_dir: String,
        /// the intent for encrypting the message
        #[arg(long)]
        intent: String,
        /// the contract address
        #[arg(long)]
        contract_addr: String,
        /// the ticket for reading/writing to fangorn's docstream
        /// note: this is only needed when we are using the iroh docstore
        /// maybe we should make this more generic somehow
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        system_keys_dir: String,
        #[arg(long)]
        bootstrap_url: String,
        #[arg(long)]
        bootstrap_pubkey: String,
    },
    /// request to decrypt a message
    /// prepare a witness + send to t-of-n node RPCs
    /// wait for response, then aggr and decrypt
    Decrypt {
        /// the directory of the kzg params
        #[arg(long)]
        config_path: String,
        /// the filename
        #[arg(long)]
        filename: String,
        /// A witness that satisfies the intent associated with the CID
        #[arg(long)]
        witness: String,
        /// The name of the file to which you would like to write
        /// the decrypted text to
        #[arg(long)]
        pt_filename: String,
        #[arg(long)]
        keystore_dir: String,
        /// the contract address
        #[arg(long)]
        contract_addr: String,
        /// the request pool contract
        #[arg(long)]
        request_pool_contract_addr: String,
        /// the ticket for reading/writing to fangorn's docstream
        #[arg(long)]
        ticket: String,
        #[arg(long)]
        system_keys_dir: String,
        #[arg(long)]
        bootstrap_url: String,
        #[arg(long)]
        bootstrap_pubkey: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Keygen { keystore_dir }) => {
            let keystore = Sr25519Keystore::new(keystore_dir.into(), FANGORN).unwrap();
            keystore.generate_key().unwrap();
            let keys = keystore.list_keys()?;
            println!(
                "Keys in keystore: {:?}",
                keys.iter().map(|k| keystore.to_ss58(k)).collect::<Vec<_>>()
            );
        }
        Some(Commands::Inspect { keystore_dir }) => {
            let keystore = Sr25519Keystore::new(keystore_dir.into(), FANGORN).unwrap();
            let keys = keystore.list_keys()?;
            println!(
                "Keys in keystore: {:?}",
                keys.iter().map(|k| keystore.to_ss58(k)).collect::<Vec<_>>()
            );
        }
        Some(Commands::KeygenPswd {
            keystore_dir,
            password,
            store_type,
        }) => {
            let mut deref_pass = password.to_owned();
            let mut vault_password =
                SecretString::new(String::from("vault_password").into_boxed_str());
            let vault = Vault::open_or_create(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    // create sr25519 identity
                    let keyvault = Sr25519KeyVault::new(vault);
                    let public_key = keyvault
                        .generate_key(String::from("sr25519"), &mut deref_pass)
                        .unwrap();
                    println!("generated new keypair. PubKey: {:?}", public_key);
                }
                StoreType::Fangorn => {
                    // create ed25519 identity
                    let keyvault = IrohKeyVault::new(vault);
                    let public_key = keyvault
                        .generate_key(String::from("ed25519"), &mut deref_pass)
                        .unwrap();
                    println!("generated new keypair. Pubkey: {:?}", public_key)
                }
            }
            deref_pass.expose_secret_mut().zeroize();
            deref_pass.zeroize();
        }
        Some(Commands::InspectPswd {
            keystore_dir,
            password,
            store_type,
        }) => {
            let mut deref_pass = password.to_owned();
            let mut vault_password =
                SecretString::new(String::from("vault_password").into_boxed_str());
            let vault = Vault::open(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new(vault);
                    let public_key = keyvault
                        .get_public_key(String::from("sr25519"), &mut deref_pass)
                        .unwrap();
                    println!("read keypair. Pubkey: {:?}", public_key)
                }
                StoreType::Fangorn => {
                    let keyvault = IrohKeyVault::new(vault);
                    let public_key = keyvault
                        .get_public_key(String::from("ed25519"), &mut deref_pass)
                        .unwrap();
                    println!("read keypair. Pubkey: {:?}", public_key)
                }
            }
            deref_pass.expose_secret_mut().zeroize();
            deref_pass.zeroize();
        }
        Some(Commands::SignPswd {
            keystore_dir,
            password,
            store_type,
            nonce,
        }) => {
            let mut deref_pass = password.to_owned();
            let mut vault_password =
                SecretString::new(String::from("vault_password").into_boxed_str());
            let vault = Vault::open(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new(vault);
                    let message_bytes = nonce.to_le_bytes();
                    let signature = keyvault
                        .sign(String::from("sr25519"), &message_bytes, &mut deref_pass)
                        .unwrap();
                    let sig_hex = to_hex(&signature.as_bytes_ref(), false);
                    println!(
                        "Produced a signature on the nonce {:?}: {:?}",
                        nonce, sig_hex
                    );
                }
                StoreType::Fangorn => {
                    let keyvault = IrohKeyVault::new(vault);
                    let message_bytes = nonce.to_le_bytes();
                    let signature = keyvault
                        .sign(String::from("ed25519"), &message_bytes, &mut deref_pass)
                        .unwrap();
                    let sig_hex = to_hex(&signature.to_bytes(), false);
                    println!(
                        "Produced a signature on the nonce {:?}: {:?}",
                        nonce, sig_hex
                    );
                }
            }
            deref_pass.expose_secret_mut().zeroize();
            deref_pass.zeroize();
        }
        Some(Commands::VerifyPswd {
            keystore_dir,
            password,
            store_type,
            signature_hex,
            nonce,
        }) => {
            let mut deref_pass = password.to_owned();
            let mut vault_password =
                SecretString::new(String::from("vault_password").into_boxed_str());
            let vault = Vault::open(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new(vault);
                    let public_key = keyvault
                        .get_public_key(String::from("sr25519"), &mut deref_pass)
                        .unwrap();
                    let message_bytes = nonce.to_le_bytes();
                    let sig_vec = from_hex(&signature_hex).unwrap();
                    let sig = SrSignature::from_slice(sig_vec.as_slice()).unwrap();
                    let result = Sr25519KeyVault::verify(&public_key, &message_bytes, &sig);
                    println!("Was sig verified: {:?}", result);
                }
                StoreType::Fangorn => {
                    let keyvault = IrohKeyVault::new(vault);
                    let public_key = keyvault
                        .get_public_key(String::from("ed25519"), &mut deref_pass)
                        .unwrap();
                    let message_bytes = nonce.to_le_bytes();
                    let sig_vec = from_hex(&signature_hex).unwrap();
                    let sig_bytes: [u8; 64] = sig_vec.try_into().unwrap();
                    let sig = iroh::Signature::from_bytes(&sig_bytes);
                    let result = IrohKeyVault::verify(&public_key, &message_bytes, &sig);
                    println!("Was sig verified: {:?}", result);
                }
            }
            deref_pass.expose_secret_mut().zeroize();
            deref_pass.zeroize();
        }
        Some(Commands::Sign {
            keystore_dir,
            nonce,
        }) => {
            let keystore = Sr25519Keystore::new(keystore_dir.into(), FANGORN).unwrap();
            let key = keystore.list_keys()?[0];
            let message_bytes = nonce.to_le_bytes();
            let signature = keystore.sign(&key, &message_bytes);
            println!(
                "Produced a signature on the nonce {:?}: {:?}",
                nonce, signature
            );
        }
        Some(Commands::Encrypt {
            message_path,
            filename,
            config_path,
            keystore_dir,
            intent,
            contract_addr,
            ticket,
            system_keys_dir,
            bootstrap_url,
            bootstrap_pubkey,
        }) => {
            // todo: should probably read the config file in this context
            // read the system keys
            // TODO: realistically this should be done by reading from a contract or similar
            // and probably is input as a param directly? not sure yet
            let sys_keys_bytes =
                std::fs::read(system_keys_dir).expect("Failed to read syskeys file");
            let sys_keys =
                SystemPublicKeys::<E>::deserialize_compressed(&sys_keys_bytes[..]).unwrap();

            // setup node
            let mut node = build_node().await;
            // connect to bootstrap
            let pubkey = IrohPublicKey::from_str(&bootstrap_pubkey).ok().unwrap();
            let socket: SocketAddr = bootstrap_url.parse().ok().unwrap();
            let boot = EndpointAddr::new(pubkey).with_ip_addr(socket);
            node.try_connect_peers(Some(vec![boot])).await?;
            // wait for initial sync
            thread::sleep(Duration::from_secs(3));
            // sync, read all keys, compute latest encryption key
            // in practice, this should be read from a contract or something.

            handle_encrypt(
                message_path,
                filename,
                config_path,
                keystore_dir,
                intent,
                contract_addr,
                node,
                ticket,
                sys_keys,
            )
            .await;
        }
        Some(Commands::Decrypt {
            config_path,
            filename,
            witness,
            pt_filename,
            keystore_dir,
            contract_addr,
            request_pool_contract_addr,
            ticket,
            system_keys_dir,
            bootstrap_url,
            bootstrap_pubkey,
        }) => {
            let sys_keys_bytes =
                std::fs::read(system_keys_dir).expect("Failed to read syskeys file");
            let sys_keys =
                SystemPublicKeys::<E>::deserialize_compressed(&sys_keys_bytes[..]).unwrap();

            // setup node
            let mut node = build_node().await;
            // connect to bootstrap
            let pubkey = IrohPublicKey::from_str(&bootstrap_pubkey).ok().unwrap();
            let socket: SocketAddr = bootstrap_url.parse().ok().unwrap();
            let boot = EndpointAddr::new(pubkey).with_ip_addr(socket);
            node.try_connect_peers(Some(vec![boot])).await?;
            // wait for the node to be online
            node.endpoint().online().await;
            println!("🟢 RECEIVER is ONLINE");

            // // setup the decryption handler
            // let node_clone = node.clone();
            // n0_future::task::spawn(async move {
            //     while let Ok(partial_decryption_message) = node_clone.pd_rx().recv_async().await {
            //         println!("handling partial decryptions in the handler in the node");
            //         // get filename
            //         // use it to get the cid
            //         // use the cid to get the data
            //         // decrypt the data with partial decryptions if you have enough (assume threshold = 1 for now)
            //         // save to file with pt_store
            //     }
            // });

            handle_decrypt(
                config_path,
                filename,
                witness,
                pt_filename,
                keystore_dir,
                contract_addr,
                request_pool_contract_addr,
                node,
                ticket,
                sys_keys,
            )
            .await;
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}

async fn build_node() -> Node<E> {
    // setup channels for state synchronization
    let (_tx, rx) = flume::unbounded();
    // initialize node parameters and state
    // start on port 4000
    // todo: can we remove the index field? sk unused here
    let params = StartNodeParams::<E>::rand(4000, 0);
    let state = State::<E>::empty(params.secret_key.clone());
    let arc_state = Arc::new(Mutex::new(state));

    Node::build(params, rx, arc_state).await
}
