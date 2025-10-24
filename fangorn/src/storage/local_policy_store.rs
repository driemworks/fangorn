use super::*;
use async_trait::async_trait;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct LocalPolicyStore {
    /// the root directory to store policy data
    pub dir: String,
}

impl LocalPolicyStore {
    pub fn new(dir: impl Into<String>) -> Self {
        Self { dir: dir.into() }
    }
    
    /// a helper function to check if a directory exists
    async fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.dir).await?;
        Ok(())
    }
    
    /// convert CID to filename
    fn cid_to_filename(&self, cid: &CID) -> PathBuf {
        let cid_hex = hex::encode(&cid.0);
        PathBuf::from(&self.dir).join(format!("{}.policy", cid_hex))
    }
    
    /// serialize policy to bytes
    fn serialize_policy(&self, policy: &Policy) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(policy)?)
    }
    
    /// deserialize policy from bytes
    fn deserialize_policy(&self, bytes: &[u8]) -> Result<Policy> {
        Ok(serde_json::from_slice(bytes)?)
    }
}

#[async_trait]
impl PolicyStore for LocalPolicyStore {
    async fn get_policy(&self, cid: &CID) -> Result<Option<Policy>> {
        let filepath = self.cid_to_filename(cid);
        
        // Check if file exists
        if !filepath.exists() {
            return Ok(None);
        }
        
        // Read file
        let mut file = fs::File::open(&filepath).await?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).await?;
        
        // Deserialize
        let policy = self.deserialize_policy(&contents)?;
        
        Ok(Some(policy))
    }
    
    async fn register_policy(&self, cid: CID, policy: Policy) -> Result<()> {
        // Ensure directory exists
        self.ensure_dir().await?;
        
        // Serialize policy
        let bytes = self.serialize_policy(&policy)?;
        
        // Write to file
        let filepath = self.cid_to_filename(&cid);
        let mut file = fs::File::create(&filepath).await?;
        file.write_all(&bytes).await?;
        file.flush().await?;
        
        println!("Registered policy for CID: {} at {:?}", hex::encode(&cid.0), filepath);
        
        Ok(())
    }
    
    async fn kill_policy(&self, cid: &CID) -> Result<()> {
        let filepath = self.cid_to_filename(cid);
        
        // Check if file exists
        if filepath.exists() {
            fs::remove_file(&filepath).await?;
            println!("Killed policy for CID: {}", hex::encode(&cid.0));
        } else {
            println!("No policy found for CID: {}", hex::encode(&cid.0));
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