use super::*;
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
    /// the root directory to store data
    pub docs_dir: String,
    pub intents_dir: String,
}

impl LocalDocStore {
    pub fn new(docs_dir: impl Into<String>, intents_dir: impl Into<String>) -> Self {
        Self {
            docs_dir: docs_dir.into(),
            intents_dir: intents_dir.into(),
        }
    }

    /// a helper function to check if a directory exists
    async fn ensure_docs_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.docs_dir).await?;
        Ok(())
    }

    /// a helper function to check if a directory exists
    async fn ensure_intents_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.intents_dir).await?;
        Ok(())
    }


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

    /// convert CID to filename
    fn cid_to_filename(&self, cid: &str) -> PathBuf {
        PathBuf::from(&self.docs_dir).join(format!("{}.dat", cid))
    }

    /// convert CID to filename
    fn cid_to_filename_for_intents(&self, cid: &str) -> PathBuf {
        PathBuf::from(&self.intents_dir).join(format!("{}.ents", cid))
    }

    /// generate a cid
    fn build_cid(&self, data: &Data) -> Cid {
        let hash = Code::Sha2_256.digest(data);
        Cid::new_v1(RAW, hash)
    }
}

#[async_trait]
impl SharedStore<Cid, Data> for LocalDocStore {
    async fn add(&self, data: &Data) -> Result<Cid> {
        self.ensure_docs_dir().await?;
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

#[async_trait]
impl IntentStore for LocalDocStore {
    async fn register_intent(&self, cid: &Cid, intent: &Intent) -> Result<()> {
        // // should check that the cid is unique but don't care at this point
        self.ensure_intents_dir().await?;
        // write to file
        let filepath = self.cid_to_filename_for_intents(&cid.to_string());
        self.write_to_disk(&intent.to_bytes(), filepath);
        Ok(())
    }

    async fn get_intent(&self, cid: &Cid) -> Result<Option<Intent>> {
        let filepath = self.cid_to_filename_for_intents(&cid.to_string());

        // // Check if file exists
        if !filepath.exists() {
            return Ok(None);
        }

        // // Read file
        let raw = fs::read_to_string(filepath)
            .await
            .expect("Issue reading intent to string");
        let bytes = hex::decode(raw.clone()).unwrap();

        let intent: Intent = bytes.into();

        Ok(Some(intent))
    }

    async fn remove_intent(&self, _cid: &Cid) -> Result<()> {
        Ok(())
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_local_policy_store() {
//         let temp_dir = "/tmp/test_policies";
//         let store = LocalPolicyStore::new(temp_dir);

//         // Create a test policy
//         let cid = CID(b"test_content_123".to_vec());
//         let policy = Policy::challenge("What is 2+2?", "4");

//         // Register
//         store.register_policy(cid.clone(), policy.clone()).await.unwrap();

//         // Retrieve
//         let retrieved = store.get_policy(&cid).await.unwrap();
//         assert!(retrieved.is_some());

//         // Kill
//         store.kill_policy(&cid).await.unwrap();

//         // Verify deleted
//         let after_kill = store.get_policy(&cid).await.unwrap();
//         assert!(after_kill.is_none());

//         // Cleanup
//         let _ = std::fs::remove_dir_all(temp_dir);
//     }
// }
