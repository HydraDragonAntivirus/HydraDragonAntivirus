use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

pub struct ByteBudget {
    used: Mutex<i64>,
    max: i64,
    notify: Notify,
}

impl ByteBudget {
    pub fn new(max: i64) -> Arc<Self> {
        Arc::new(Self {
            used: Mutex::new(0),
            max,
            notify: Notify::new(),
        })
    }

    pub async fn acquire(&self, n: i64) {
        loop {
            let mut used = self.used.lock().await;
            if *used > 0 && *used + n > self.max {
                drop(used);
                self.notify.notified().await;
            } else {
                *used += n;
                break;
            }
        }
    }

    pub async fn release(&self, n: i64) {
        let mut used = self.used.lock().await;
        *used -= n;
        if *used < 0 {
            *used = 0;
        }
        drop(used);
        self.notify.notify_waiters();
    }

    pub async fn in_use(&self) -> i64 {
        *self.used.lock().await
    }
}
