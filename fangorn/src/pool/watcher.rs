use crate::pool::pool::*;
use anyhow::Result;
use flume::Sender;
use std::collections::HashSet;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;
use tokio::sync::RwLock;

/// Generic pool watcher
#[async_trait::async_trait]
pub trait PoolWatcher: Send + Sync {
    type Item;

    /// Start watching, send new items to channel
    async fn watch(&self, tx: Sender<Self::Item>) -> Result<()>;

    /// Stop watching
    fn stop(&self);
}

// Polling-based watcher for any RequestPool
pub struct PollingWatcher<P: RequestPool> {
    /// THe request pool
    pool: Arc<RwLock<P>>,
    /// The polling interval (in ms)
    poll_interval: Duration,
    /// Indicate if the watcher is running or idle
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

    async fn watch(&self, tx: Sender<Self::Item>) -> Result<()> {
        self.running.store(true, Ordering::SeqCst);

        while self.running.load(Ordering::SeqCst) {
            let pool = self.pool.read().await;
            let requests = pool.read_all().await?;
            drop(pool);
            let mut seen = self.seen.write().await;
            // ignore anything we have already seen
            for req in requests {
                if seen.insert(req.id()) {
                    tx.send(req)?;
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
