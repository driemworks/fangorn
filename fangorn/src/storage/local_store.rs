use super::*;
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use multihash_codetable::{Code, MultihashDigest};
use cid::Cid;

/// The codec for generating CIDs
const RAW: u64 = 0x55;

/// the raw data type for storage
type Data = Vec<u8>;

pub struct LocalDocStore {
    /// the root directory to store data
    pub dir: String,
}

impl LocalDocStore {
    pub fn new(dir: impl Into<String>) -> Self {
        Self { dir: dir.into() }
    }
    
    /// a helper function to check if a directory exists
    async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.dir).await?;
        Ok(())
    }
    
    /// convert CID to filename
    fn cid_to_filename(&self, cid_bytes: &[u8]) -> PathBuf {
        let cid_hex = hex::encode(cid_bytes);
        PathBuf::from(&self.dir).join(format!("{}.dat", cid_hex))
    }
}

#[async_trait]
impl SharedStore<cid::Cid, Data> for LocalDocStore {
    
    async fn add(&self, data: &Data) -> Result<Cid> {
        // Ensure directory exists
        self.ensure_dir().await?;

        // generate a cid
        let hash = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(RAW, hash);
        let key = cid.to_bytes();
        
        // Write to file
        let filepath = self.cid_to_filename(&key);
        let mut file = fs::File::create(&filepath).await?;
        file.write_all(&data).await?;
        file.flush().await?;
        
        println!("Registered policy for CID: {} at {:?}", hex::encode(&key), filepath);
        
        Ok(cid)
    }
    
    async fn fetch(&self, cid: &Cid) -> Result<Option<Data>> {
        let filepath = self.cid_to_filename(&cid.to_bytes());
        
        // Check if file exists
        if !filepath.exists() {
            return Ok(None);
        }
        
        // Read file
        let mut file = fs::File::open(&filepath).await?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await?;
        
        Ok(Some(contents))
    }
    
    async fn remove(&self, cid: &Cid) -> Result<()> {
        let filepath = self.cid_to_filename(&cid.to_bytes());
        
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