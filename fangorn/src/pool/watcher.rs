use super::*;
use crate::pool::pool::*;
use anyhow::Result;
use codec::{Decode, Encode};
use iroh::EndpointAddr;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::RwLock;

/// Generic pool watcher
#[async_trait::async_trait]
pub trait PoolWatcher: Send + Sync {
    type Item;

    /// Start watching, send new items to channel
    async fn watch(&self, tx: mpsc::Sender<Self::Item>) -> Result<()>;

    /// Stop watching
    fn stop(&self);
}

// Polling-based watcher for any RequestPool
pub struct PollingWatcher<P: RequestPool> {
    pool: Arc<RwLock<P>>,
    poll_interval: Duration,
    running: Arc<AtomicBool>,
    // Track seen request IDs
    seen: Arc<RwLock<HashSet<Vec<u8>>>>,
}

impl<P: RequestPool + Send + Sync + 'static> PollingWatcher<P> {
    pub fn new(pool: Arc<RwLock<P>>, poll_interval: Duration) -> Self {
        Self {
            pool,
            poll_interval,
            running: Arc::new(AtomicBool::new(false)),
            seen: Arc::new(RwLock::new(HashSet::new())),
        }
    }
}

#[async_trait::async_trait]
impl<P: RequestPool + Send + Sync + 'static> PoolWatcher for PollingWatcher<P> {
    type Item = DecryptionRequest;

    async fn watch(&self, tx: mpsc::Sender<Self::Item>) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        while self.running.load(Ordering::SeqCst) {
            let pool = self.pool.read().await;
            let requests = pool.read_all().await?;
            drop(pool);

            let mut seen = self.seen.write().await;
            for req in requests {
                if seen.insert(req.id().as_bytes().to_vec()) {
                    // new request
                    tx.send(req).await?;
                }
            }
            drop(seen);

            tokio::time::sleep(self.poll_interval).await;
        }

        Ok(())
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}
