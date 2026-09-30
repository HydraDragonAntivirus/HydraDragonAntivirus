use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tokio::sync::{Mutex, Notify};

pub type Job = Box<dyn FnOnce() + Send + 'static>;

pub struct FairScheduler {
    inner: Mutex<SchedulerInner>,
    notify: Notify,
}

struct SchedulerInner {
    queues: HashMap<i64, VecDeque<Job>>,
    order: VecDeque<i64>,
}

impl FairScheduler {
    pub fn new(workers: usize) -> Arc<Self> {
        let sched = Arc::new(Self {
            inner: Mutex::new(SchedulerInner {
                queues: HashMap::new(),
                order: VecDeque::new(),
            }),
            notify: Notify::new(),
        });

        sched.start_workers(workers);
        sched
    }

    fn start_workers(self: &Arc<Self>, workers: usize) {
        for _ in 0..workers {
            let sched = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    let job = sched.next_job().await;
                    // Run the scan job on a dedicated blocking OS thread with full native stack
                    let _ = tokio::task::spawn_blocking(move || {
                        job();
                    })
                    .await;
                }
            });
        }
    }

    pub async fn submit(&self, session_id: i64, job: Job) {
        let mut guard = self.inner.lock().await;
        let is_first = {
            let q = guard.queues.entry(session_id).or_default();
            q.push_back(job);
            q.len() == 1
        };
        if is_first {
            guard.order.push_back(session_id);
        }
        drop(guard);
        self.notify.notify_one();
    }

    async fn next_job(&self) -> Job {
        loop {
            let mut guard = self.inner.lock().await;
            if let Some(session_id) = guard.order.pop_front() {
                if let Some(q) = guard.queues.get_mut(&session_id) {
                    if let Some(job) = q.pop_front() {
                        if !q.is_empty() {
                            guard.order.push_back(session_id);
                        } else {
                            guard.queues.remove(&session_id);
                        }
                        return job;
                    }
                }
            }
            drop(guard);
            self.notify.notified().await;
        }
    }

    pub async fn queued(&self) -> usize {
        let guard = self.inner.lock().await;
        guard.queues.values().map(|q| q.len()).sum()
    }
}
