use std::{io::Read, time::SystemTime};

use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fangorn::{backend::substrate::runtime::runtime_apis::core::types::version, crypto::{
        FANGORN,
        cipher::{handle_decrypt, handle_encrypt},
        keystore::{IrohKeystore, Keystore, Sr25519Keystore}, keyvault::{IrohKeyVault, KeyVault, Sr25519KeyVault},
    }};
use rust_vault::Vault;
use secrecy::{ExposeSecret, ExposeSecretMut, SecretBox, SecretString, zeroize::Zeroizing};
use sp_core::crypto::Zeroize;
use ark_std::rand::rngs::OsRng;
// use sp_core::crypto::{ExposeSecret, SecretString};

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
        #[arg(long)]
        contract_addr: String,
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
        contract_addr: String,
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
        Some(Commands::KeygenPswd { keystore_dir, password , store_type}) => {
            let mut deref_pass = password.to_owned();
            match store_type {
                StoreType::Polkadot => {
                    // create sr25519 identity
                    let vault = Vault::create(keystore_dir, &mut deref_pass, "fangorn").unwrap();
                    let keyvault = Sr25519KeyVault::new(vault);
                    let public_key = keyvault.generate_key(String::from("sr25519")).unwrap();
                    println!("generated new keypair. PubKey: {:?}", public_key);

                }
                StoreType::Fangorn => {
                    // create ed25519 identity
                    let vault = Vault::create(keystore_dir, &mut deref_pass, "fangorn").unwrap();
                    let keyvault = IrohKeyVault::new(vault);
                    let public_key = keyvault.generate_key(String::from("ed25519")).unwrap();
                    println!("generated new keypair. Pubkey: {:?}", public_key)

                }
            }
            deref_pass.expose_secret_mut().zeroize();
            deref_pass.zeroize();
        }
        Some(Commands::InspectPswd{keystore_dir, password, store_type}) => {
            let mut deref_pass = password.to_owned();
            match store_type {
                StoreType::Polkadot => {
                    let vault = Vault::open(keystore_dir, &mut deref_pass, "fangorn").unwrap();
                    let keyvault = Sr25519KeyVault::new(vault);
                    let public_key = keyvault.get_public_key(String::from("sr25519")).unwrap();
                    println!("read keypair. Pubkey: {:?}", public_key)
                }
                StoreType::Fangorn => {
                    let vault = Vault::open(keystore_dir, &mut deref_pass, "fangorn").unwrap();
                    let keyvault = IrohKeyVault::new(vault);
                    let public_key = keyvault.get_public_key(String::from("ed25519")).unwrap();
                    println!("read keypair. Pubkey: {:?}", public_key)                    
                }
            }

            deref_pass.expose_secret_mut().zeroize();
            deref_pass.zeroize();

        } 
        Some(Commands::Sign { keystore_dir, nonce }) => {
            let keystore = Sr25519Keystore::new(keystore_dir.into(), FANGORN).unwrap();
            let key = keystore.list_keys()?[0];
            let message_bytes = nonce.to_le_bytes();
            let signature = keystore.sign(&key, &message_bytes); 
            println!("Produced a signature on the nonce {:?}: {:?}", nonce, signature);
        }
        Some(Commands::Encrypt {
            message_path,
            filename,
            config_path,
            keystore_dir,
            intent,
            contract_addr,
        }) => {
            handle_encrypt(
                message_path,
                filename,
                config_path,
                keystore_dir,
                intent,
                contract_addr,
            )
            .await;
        }
        Some(Commands::Decrypt {
            config_path,
            filename,
            witness,
            pt_filename,
            contract_addr,
        }) => {
            handle_decrypt(config_path, filename, witness, pt_filename, contract_addr).await;
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}
