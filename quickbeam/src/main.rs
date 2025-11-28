use anyhow::Result;
use clap::{Parser, Subcommand};
use fangorn::{
    crypto::{
        cipher::{handle_decrypt, handle_encrypt},
    },
};
use secrecy::SecretString;
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

/// Define available subcommands
#[derive(Subcommand, Debug)]
enum Commands {
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
