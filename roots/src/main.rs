use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fangorn::{
    crypto::{
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

#[derive(Parser, Debug)]
#[command(name = "roots", version = "1.0")]
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
        None => {
            // do nothing
        }
    }

    Ok(())
}

