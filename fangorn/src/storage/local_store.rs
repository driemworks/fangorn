use super::*;
use crate::gadget::Intent;
use async_trait::async_trait;
use cid::Cid;
use multihash_codetable::{Code, MultihashDigest};
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::PathBuf;
use tokio::fs;

/// The codec for generating CIDs
const RAW: u64 = 0x55;

pub struct LocalDocStore {
    pub docs_dir: String,
}

impl LocalDocStore {
    pub fn new(docs_dir: &str) -> Self {
        Self {
            docs_dir: docs_dir.to_string(),
        }
    }

    /// Ensure the docs directory exists
    async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.docs_dir).await?;
        Ok(())
    }

    /// Convert CID to filename for documents
    fn cid_to_filename(&self, cid: &str) -> PathBuf {
        PathBuf::from(&self.docs_dir).join(format!("{}", cid))
    }

    /// Write data to disk as hex-encoded
    fn write_to_disk(&self, data: &Data, filepath: PathBuf) {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(filepath)
            .unwrap();

        let hex_enc = hex::encode(data);
        write!(&mut file, "{}", hex_enc).unwrap();
    }

    /// Generate a CID for the given data
    fn build_cid(&self, data: &Data) -> Cid {
        let hash = Code::Sha2_256.digest(data);
        Cid::new_v1(RAW, hash)
    }
}

#[async_trait]
impl SharedStore<Cid, Data> for LocalDocStore {
    async fn add(&self, data: &Data) -> Result<Cid> {
        self.ensure_dir().await?;
        // build the cid
        let cid = self.build_cid(data);
        // write to file
        let filepath = self.cid_to_filename(&cid.to_string());
        self.write_to_disk(data, filepath);
        Ok(cid)
    }

    async fn fetch(&self, cid: &Cid) -> Result<Option<Data>> {
        let filepath = self.cid_to_filename(&cid.to_string());

        // Check if file exists
        if !filepath.exists() {
            return Ok(None);
        }

        // Read file
        let ciphertext_hex = fs::read_to_string(filepath)
            .await
            .expect("you must provide a ciphertext.");
        let ciphertext_bytes = hex::decode(ciphertext_hex.clone()).unwrap();

        Ok(Some(ciphertext_bytes))
    }

    async fn remove(&self, cid: &Cid) -> Result<()> {
        let filepath = self.cid_to_filename(&cid.to_string());

        // Check if file exists
        if filepath.exists() {
            fs::remove_file(&filepath).await?;
            println!("Removed data for CID: {}", &cid.to_string());
        } else {
            println!("No data found for CID: {}", &cid.to_string());
        }

        Ok(())
    }
}

impl DocStore for LocalDocStore {}

// local intent store impl

// pub struct LocalIntentStore {
//     pub intents_dir: String,
// }

// impl LocalIntentStore {
//     pub fn new(intents_dir: &str) -> Self {
//         Self { intents_dir: intents_dir.to_string() }
//     }

//     /// Ensure the intents directory exists
//     async fn ensure_dir(&self) -> Result<()> {
//         fs::create_dir_all(&self.intents_dir).await?;
//         Ok(())
//     }

//     /// Convert CID to filename for intents
//     fn cid_to_filename(&self, cid: &str) -> PathBuf {
//         PathBuf::from(&self.intents_dir).join(format!("{}", cid))
//     }

//     /// Write data to disk as hex-encoded
//     fn write_to_disk(&self, data: &Data, filepath: PathBuf) {
//         let mut file = OpenOptions::new()
//             .create(true)
//             .write(true)
//             .truncate(true)
//             .open(filepath)
//             .unwrap();

//         let hex_enc = hex::encode(data);
//         write!(&mut file, "{}", hex_enc).unwrap();
//     }
// }

// #[async_trait]
// impl IntentStore for LocalIntentStore {
//     async fn register_intent(&self, cid: &Cid, intent: &Intent) -> Result<()> {
//         self.ensure_dir().await?;
//         // write to file
//         let filepath = self.cid_to_filename(&cid.to_string());
//         self.write_to_disk(&intent.to_bytes(), filepath);
//         Ok(())
//     }

//     async fn get_intent(&self, cid: &Cid) -> Result<Option<Intent>> {
//         let filepath = self.cid_to_filename(&cid.to_string());

//         // Check if file exists
//         if !filepath.exists() {
//             return Ok(None);
//         }

//         // Read file
//         let raw = fs::read_to_string(filepath)
//             .await
//             .expect("Issue reading intent to string");
//         let bytes = hex::decode(raw.clone()).unwrap();

//         let intent: Intent = bytes.into();

//         Ok(Some(intent))
//     }

//     async fn remove_intent(&self, cid: &Cid) -> Result<()> {
//         let filepath = self.cid_to_filename(&cid.to_string());

//         // Check if file exists
//         if filepath.exists() {
//             fs::remove_file(&filepath).await?;
//             println!("Removed intent for CID: {}", &cid.to_string());
//         } else {
//             println!("No intent found for CID: {}", &cid.to_string());
//         }

//         Ok(())
//     }
// }

// local pt store impl

pub struct LocalPlaintextStore {
    pub pt_dir: String,
}

impl LocalPlaintextStore {
    pub fn new(pt_dir: &str) -> Self {
        Self {
            pt_dir: pt_dir.to_string(),
        }
    }

    /// Ensure the plaintext directory exists
    async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.pt_dir).await?;
        Ok(())
    }

    /// Write plaintext to disk (not hex-encoded)
    fn write_pt_to_disk(&self, data: &Data, filepath: PathBuf) {
        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(filepath)
            .unwrap();

        let pt = String::from_utf8(data.clone())
            .expect("Couldn't translate Vec to String for PT persistence");

        write!(&mut file, "{}", pt).unwrap();
    }
}

#[async_trait]
impl PlaintextStore for LocalPlaintextStore {
    async fn read_plaintext(&self, message_path: &String) -> Result<String> {
        let plaintext = fs::read_to_string(message_path)
            .await
            .expect("you must provide a path to a plaintext file.");

        Ok(plaintext)
    }

    async fn write_to_pt_store(&self, filename: &String, data: &Vec<u8>) -> Result<()> {
        self.ensure_dir().await?;

        let filepath = format!("{}{}.txt", self.pt_dir, filename);
        let pathbuf = PathBuf::from(filepath);

        self.write_pt_to_disk(data, pathbuf);

        Ok(())
    }
}
