use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Limits the bytes of uploaded files held in memory (all clients together).
/// Counted in KB so a semaphore can hold it; a file larger than the whole budget
/// takes all of it and runs alone.
pub struct ByteBudget {
    sem: Arc<Semaphore>,
    total_kb: u32,
}

impl ByteBudget {
    pub fn new(max_bytes: i64) -> Arc<Self> {
        let total_kb = (max_bytes / 1024).clamp(1024, u32::MAX as i64 / 2) as u32;
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(total_kb as usize)),
            total_kb,
        })
    }

    pub async fn acquire(&self, bytes: i64) -> OwnedSemaphorePermit {
        let kb = ((bytes.max(0) / 1024) + 1).min(self.total_kb as i64) as u32;
        Arc::clone(&self.sem)
            .acquire_many_owned(kb)
            .await
            .expect("budget semaphore closed")
    }

    pub fn in_use_bytes(&self) -> i64 {
        (self.total_kb as i64 - self.sem.available_permits() as i64) * 1024
    }
}
