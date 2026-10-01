use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Limits the bytes of uploaded files held in memory (all clients together).
/// Counted in KB so a semaphore can hold it; a file larger than the whole budget
/// takes all of it and runs alone.
pub struct ByteBudget {
    sem: Arc<Semaphore>,
    total_kb: AtomicU32,
}

fn to_kb(max_bytes: i64) -> u32 {
    (max_bytes / 1024).clamp(1024, u32::MAX as i64 / 2) as u32
}

impl ByteBudget {
    pub fn new(max_bytes: i64) -> Arc<Self> {
        let total_kb = to_kb(max_bytes);
        Arc::new(Self {
            sem: Arc::new(Semaphore::new(total_kb as usize)),
            total_kb: AtomicU32::new(total_kb),
        })
    }

    pub async fn acquire(&self, bytes: i64) -> OwnedSemaphorePermit {
        let total = self.total_kb.load(Ordering::Relaxed) as i64;
        let kb = ((bytes.max(0) / 1024) + 1).min(total.max(1)) as u32;
        Arc::clone(&self.sem)
            .acquire_many_owned(kb)
            .await
            .expect("budget semaphore closed")
    }

    /// Changes the budget at runtime. Shrinking takes effect as uploads in memory finish.
    pub fn resize(&self, max_bytes: i64) {
        let new_kb = to_kb(max_bytes);
        let old_kb = self.total_kb.swap(new_kb, Ordering::Relaxed);
        if new_kb > old_kb {
            self.sem.add_permits((new_kb - old_kb) as usize);
        } else if new_kb < old_kb {
            let sem = Arc::clone(&self.sem);
            let diff = old_kb - new_kb;
            tokio::spawn(async move {
                // Waits for the permits to come back, then drops them for good.
                if let Ok(p) = sem.acquire_many_owned(diff).await {
                    p.forget();
                }
            });
        }
    }

    pub fn in_use_bytes(&self) -> i64 {
        let total = self.total_kb.load(Ordering::Relaxed) as i64;
        (total - self.sem.available_permits() as i64).max(0) * 1024
    }
}
