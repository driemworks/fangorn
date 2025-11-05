use anyhow::Result;
use clap::{Parser, Subcommand};
use fangorn::crypto::cipher::{handle_encrypt, handle_decrypt};

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
        /// the directory of the kzg params (fangorn config)
        #[arg(long)]
        config_dir: String,
        /// the intent for encrypting the message
        #[arg(long)]
        intent: String,
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
        /// A witness that satisfies the intent associated with the CID
        #[arg(long)]
        witness: String,
        /// The name of the file to which you would like to write
        /// the decrypted text to
        #[arg(long)]
        pt_filename: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    match &args.command {
        Some(Commands::Encrypt {
            message_dir,
            config_dir,
            intent,
        }) => {
            handle_encrypt(config_dir, message_dir, intent).await;
        }
        Some(Commands::Decrypt {
            config_dir,
            cid,
            witness,
            pt_filename,
        }) => {
            handle_decrypt(config_dir, cid, witness, pt_filename).await;
        }
        None => {
            // do nothing
        }
    }

    Ok(())
}
