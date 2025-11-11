use anyhow::Result;
use clap::{Parser, Subcommand};
use fangorn::{
    crypto::{
        FANGORN,
        cipher::{handle_decrypt, handle_encrypt},
        keystore::{Keystore, Sr25519Keystore},
    },
    gadget::{GadgetRegistry, password::PasswordGadget},
};

#[derive(Parser, Debug)]
#[command(name = "quickbeam", version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
    Keygen {
        // the keystore directory
        #[arg(long)]
        keystore_dir: String,
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
            // let backend = Arc::new(SubstrateBackend::new(crate::WS_URL.to_string(), None).await?);

            // let mut registry = GadgetRegistry::new();
            // registry.register(PasswordGadget {});



            handle_encrypt(
                message_path,
                filename,
                config_path,
                keystore_dir,
                intent,
                contract_addr,
                // &registry,
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
