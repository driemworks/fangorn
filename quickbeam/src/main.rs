use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fangorn::{
    crypto::{
        cipher::{handle_decrypt, handle_encrypt},
        keyvault::{IrohKeyVault, KeyVault, Sr25519KeyVault},
    },
};
use rust_vault::Vault;
use secrecy::SecretString;
use sp_core::{
    ByteArray,
    bytes::{from_hex, to_hex},
    hexdisplay::AsBytesRef,
    sr25519::Signature as SrSignature,
};
// use sp_core::crypto::{ExposeSecret, SecretString};
use ark_serialize::CanonicalDeserialize;
use fangorn::{Node, types::*};
use iroh::{EndpointAddr, PublicKey as IrohPublicKey};
use silent_threshold_encryption::aggregate::SystemPublicKeys;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use tokio::sync::Mutex;

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
        /// the keystore directory
        #[arg(long)]
        keystore_dir: String,

        #[arg(long)]
        key_name: String,

        #[arg(long, default_value = "vault_password")]
        vault_pswd: String,

        /// the password to encrypt the key with
        #[arg(long)]
        key_password: SecretString,

        /// the associated key type: polkadot(sr25519), fangorn(ed25519)
        #[arg(value_enum)]
        store_type: StoreType,

        /// Index used for key naming in STE and Fangorn vaults
        #[arg(long, default_value=None)]
        index: Option<usize>,

        /// whether to print the mnemonic to the terminal when generating
        /// an sr25519 key
        #[arg(short, long, default_value_t = false)]
        print_mnemonic: bool,
    },
    Inspect {
        /// the keystore directory
        #[arg(long)]
        keystore_dir: String,

        #[arg(long, default_value = "vault_password")]
        vault_pswd: String,

        #[arg(long)]
        key_name: String,

        /// the password to access the associated file
        #[arg(long)]
        key_password: SecretString,
        /// the associated key type: polkadot(sr25519), fangorn(ed25519)
        #[arg(value_enum)]
        store_type: StoreType,
        /// Index used for key naming in STE and Fangorn vaults
        #[arg(long, default_value=None)]
        index: Option<usize>,
    },
    Sign {
        /// the keystore directory
        #[arg(long)]
        keystore_dir: String,

        #[arg(long, default_value = "vault_password")]
        vault_pswd: String,

        #[arg(long)]
        key_name: String,

        #[arg(long)]
        key_password: SecretString,
        /// the associated key type: polkadot(sr25519), fangorn(ed25519)
        #[arg(value_enum)]
        store_type: StoreType,
        /// a nonce to sign
        #[arg(long)]
        nonce: u32,
        /// Index used for key naming in STE and Fangorn vaults
        #[arg(long, default_value=None)]
        index: Option<usize>,
    },
    Verify {
        /// the keystore directory
        #[arg(long)]
        keystore_dir: String,
        #[arg(long, default_value = "vault_password")]
        vault_pswd: String,

        #[arg(long)]
        key_name: String,

        /// the password to access the associated file
        #[arg(long)]
        key_password: SecretString,
        /// the associated key type: polkadot(sr25519), fangorn(ed25519)
        #[arg(value_enum)]
        store_type: StoreType,
        /// the hex printed when using sign-pswd
        #[arg(long)]
        signature_hex: String,
        /// the nonce that was signed when using sign-pswd
        #[arg(long)]
        nonce: u32,
        /// Index used for key naming in STE and Fangorn vaults
        #[arg(long, default_value=None)]
        index: Option<usize>,
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
        #[arg(long, default_value = "tmp/keystore")]
        vault_dir: String,
        #[arg(long,  default_value=None)]
        vault_pswd: Option<SecretString>,
        #[arg(long,  default_value=None)]
        iroh_key_pswd: Option<SecretString>,
        #[arg(long,  default_value=None)]
        ste_key_pswd: Option<SecretString>,
        #[arg(long, default_value = "sr25519")]
        substrate_name: String,
        #[arg(long, default_value=None)]
        substrate_pswd: Option<SecretString>,
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
        #[arg(long, default_value = "tmp/keystore")]
        vault_dir: String,
        #[arg(long,  default_value=None)]
        vault_pswd: Option<SecretString>,
        #[arg(long,  default_value=None)]
        iroh_key_pswd: Option<SecretString>,
        #[arg(long,  default_value=None)]
        ste_key_pswd: Option<SecretString>,
        #[arg(long, default_value = "sr25519")]
        substrate_name: String,
        #[arg(long, default_value=None)]
        substrate_pswd: Option<SecretString>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Keygen {
            keystore_dir,
            key_name,
            vault_pswd,
            key_password,
            store_type,
            index,
            print_mnemonic,
        }) => {
            let mut vault_password = SecretString::new(vault_pswd.to_owned().into_boxed_str());
            let vault = Vault::open_or_create(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new_store_info(vault, vault_password, key_name.clone(), key_password.clone());
                    // create sr25519 identity
                    if *print_mnemonic {
                        let public_key = keyvault
                            .generate_key_print_mnemonic()
                            .unwrap();
                        println!(
                            "Printned mnemonic and generated new keypair. PubKey: {:?}",
                            public_key
                        );
                    } else {
                        let public_key = keyvault
                            .generate_key()
                            .unwrap();
                        println!("generated new keypair. PubKey: {:?}", public_key);
                    }
                }
                StoreType::Fangorn => {
                    // create ed25519 identity
                    let keyvault = IrohKeyVault::new_store_info(vault, vault_password, key_password.clone(), index.unwrap_or(0));
                    let public_key = keyvault
                        .generate_key()
                        .unwrap();
                    println!("generated new keypair. Pubkey: {:?}", public_key)
                }
            }
        }
        Some(Commands::Inspect {
            keystore_dir,
            vault_pswd,
            key_name,
            key_password,
            store_type,
            index,
        }) => {
            let mut vault_password = SecretString::new(vault_pswd.to_owned().into_boxed_str());
            let vault = Vault::open(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new_store_info(vault, vault_password, key_name.clone(), key_password.clone());
                    let public_key = keyvault
                        .get_public_key()
                        .unwrap();
                    println!("read keypair. Pubkey: {:?}", public_key)
                }
                StoreType::Fangorn => {
                    let keyvault = IrohKeyVault::new_store_info(vault, vault_password, key_password.clone(), index.unwrap_or(0));
                    let public_key = keyvault
                        .get_public_key()
                        .unwrap();
                    println!("read keypair. Pubkey: {:?}", public_key)
                }
            }
        }
        Some(Commands::Sign {
            keystore_dir,
            vault_pswd,
            key_name,
            key_password,
            store_type,
            index,
            nonce,
        }) => {
            let mut vault_password = SecretString::new(vault_pswd.to_owned().into_boxed_str());
            let vault = Vault::open(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new_store_info(vault, vault_password, key_name.clone(), key_password.clone());
                    let message_bytes = nonce.to_le_bytes();
                    let signature = keyvault
                        .sign(&message_bytes)
                        .unwrap();
                    let sig_hex = to_hex(&signature.as_bytes_ref(), false);
                    println!(
                        "Produced a signature on the nonce {:?}: {:?}",
                        nonce, sig_hex
                    );
                }
                StoreType::Fangorn => {
                    let keyvault = IrohKeyVault::new_store_info(vault, vault_password, key_password.clone(), index.unwrap_or(0));
                    let message_bytes = nonce.to_le_bytes();
                    let signature = keyvault
                        .sign(&message_bytes)
                        .unwrap();
                    let sig_hex = to_hex(&signature.to_bytes(), false);
                    println!(
                        "Produced a signature on the nonce {:?}: {:?}",
                        nonce, sig_hex
                    );
                }
            }
        }
        Some(Commands::Verify {
            keystore_dir,
            vault_pswd,
            key_name,
            key_password,
            store_type,
            signature_hex,
            index,
            nonce,
        }) => {
            let mut vault_password = SecretString::new(vault_pswd.to_owned().into_boxed_str());
            let vault = Vault::open(keystore_dir, &mut vault_password).unwrap();
            match store_type {
                StoreType::Polkadot => {
                    let keyvault = Sr25519KeyVault::new_store_info(vault, vault_password, key_name.clone(), key_password.clone());
                    let public_key = keyvault
                        .get_public_key()
                        .unwrap();
                    let message_bytes = nonce.to_le_bytes();
                    let sig_vec = from_hex(&signature_hex).unwrap();
                    let sig = SrSignature::from_slice(sig_vec.as_slice()).unwrap();
                    let result = Sr25519KeyVault::verify(&public_key, &message_bytes, &sig);
                    println!("Was sig verified: {:?}", result);
                }
                StoreType::Fangorn => {
                    let keyvault = IrohKeyVault::new_store_info(vault, vault_password, key_password.clone(), index.unwrap_or(0));
                    let public_key = keyvault
                        .get_public_key()
                        .unwrap();
                    let message_bytes = nonce.to_le_bytes();
                    let sig_vec = from_hex(&signature_hex).unwrap();
                    let sig_bytes: [u8; 64] = sig_vec.try_into().unwrap();
                    let sig = iroh::Signature::from_bytes(&sig_bytes);
                    let result = IrohKeyVault::verify(&public_key, &message_bytes, &sig);
                    println!("Was sig verified: {:?}", result);
                }
            }
        }
        Some(Commands::Encrypt {
            message_path,
            filename,
            config_path,
            intent,
            contract_addr,
            ticket,
            system_keys_dir,
            bootstrap_url,
            bootstrap_pubkey,
            vault_dir,
            vault_pswd,
            iroh_key_pswd,
            ste_key_pswd,
            substrate_name,
            substrate_pswd,
        }) => {
            // todo: should probably read the config file in this context
            // read the system keys
            // TODO: realistically this should be done by reading from a contract or similar
            // and probably is input as a param directly? not sure yet
            let sys_keys_bytes =
                std::fs::read(system_keys_dir).expect("Failed to read syskeys file");
            let sys_keys =
                SystemPublicKeys::<E>::deserialize_compressed(&sys_keys_bytes[..]).unwrap();
            let vault_config = VaultConfig {
                vault_dir: vault_dir.clone(),
                substrate_name: substrate_name.clone(),
                vault_pswd: vault_pswd.clone(),
                iroh_key_pswd: iroh_key_pswd.clone(),
                ste_key_pswd: ste_key_pswd.clone(),
                substrate_pswd: substrate_pswd.clone(),
            };

            // setup node
            let mut node = build_node(vault_config, 2).await;
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
            contract_addr,
            request_pool_contract_addr,
            ticket,
            system_keys_dir,
            bootstrap_url,
            bootstrap_pubkey,
            vault_dir,
            vault_pswd,
            iroh_key_pswd,
            ste_key_pswd,
            substrate_name,
            substrate_pswd,
        }) => {
            let sys_keys_bytes =
                std::fs::read(system_keys_dir).expect("Failed to read syskeys file");
            let sys_keys =
                SystemPublicKeys::<E>::deserialize_compressed(&sys_keys_bytes[..]).unwrap();
            let vault_config = VaultConfig {
                vault_dir: vault_dir.clone(),
                substrate_name: substrate_name.clone(),
                vault_pswd: vault_pswd.clone(),
                iroh_key_pswd: iroh_key_pswd.clone(),
                ste_key_pswd: ste_key_pswd.clone(),
                substrate_pswd: substrate_pswd.clone(),
            };

            // setup node
            let mut node = build_node(vault_config, 3).await;
            // connect to bootstrap
            let pubkey = IrohPublicKey::from_str(&bootstrap_pubkey).ok().unwrap();
            let socket: SocketAddr = bootstrap_url.parse().ok().unwrap();
            let boot = EndpointAddr::new(pubkey).with_ip_addr(socket);
            node.try_connect_peers(Some(vec![boot])).await?;
            // wait for the node to be online
            node.endpoint().online().await;
            println!("🟢 Node is online");

            handle_decrypt(
                config_path,
                filename,
                witness,
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

async fn build_node(vault_config: VaultConfig, index: usize) -> Node<E> {
    // setup channels for state synchronization
    let (_tx, rx) = flume::unbounded();
    // initialize node parameters and state
    // start on port 4000
    // todo: can we remove the index field? sk unused here
    // let params = StartNodeParams::<E>::rand(4000, 0);
    let bind_port = 4000;
    let state = State::<E>::empty();
    let arc_state = Arc::new(Mutex::new(state));

    Node::build(bind_port, index, rx, arc_state, vault_config).await
}
