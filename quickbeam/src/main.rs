use anyhow::Result;
use clap::{Parser, Subcommand};
use fangorn::{
    crypto::{
        cipher::{handle_decrypt, handle_encrypt},
        keystore::{Keystore, Sr25519Keystore},
        FANGORN,
    },
    node::Node,
    types::*,
};
use std::sync::Arc;
use tokio::sync::Mutex;

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
        /// the contract address
        #[arg(long)]
        contract_addr: String,
        /// the ticket for reading/writing to fangorn's docstream
        #[arg(long)]
        ticket: String,
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
        /// the contract address
        #[arg(long)]
        contract_addr: String,
        /// the ticket for reading/writing to fangorn's docstream
        #[arg(long)]
        ticket: String,
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
        }) => {
            // setup node
            let node = build_node().await;

            handle_encrypt(
                message_path,
                filename,
                config_path,
                keystore_dir,
                intent,
                contract_addr,
                node,
                ticket,
            )
            .await;
        }
        Some(Commands::Decrypt {
            config_path,
            filename,
            witness,
            pt_filename,
            contract_addr,
            ticket,
        }) => {
            // setup node
            let node = build_node().await;
            handle_decrypt(
                config_path,
                filename,
                witness,
                pt_filename,
                contract_addr,
                node,
                ticket,
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
    let (tx, rx) = flume::unbounded();
    // initialize node parameters and state
    // start on port 4000
    // todo: can we remove the index field? sk unused here
    let params = StartNodeParams::<E>::rand(4000, 0);
    let state = State::<E>::empty(params.secret_key.clone());
    let arc_state = Arc::new(Mutex::new(state));
    let arc_state_clone = Arc::clone(&arc_state);

    Node::build(params, rx, arc_state).await
}
