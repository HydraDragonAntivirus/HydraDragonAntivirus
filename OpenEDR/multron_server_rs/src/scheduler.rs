use std::collections::{HashMap, VecDeque};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};

pub type Job = Box<dyn FnOnce() + Send + 'static>;

/// Engine thread pool. Scans are CPU-bound and synchronous, so they run on their own
/// OS threads (not tokio's blocking pool): the network side never waits for a thread,
/// the stack is big enough for deep archive recursion, and a panic only fails one file.
///
/// Jobs are queued per client and taken round-robin, so one client sending 100k files
/// does not make everybody else wait behind it.
pub struct FairScheduler {
    inner: Mutex<SchedulerInner>,
    cv: Condvar,
    busy: AtomicUsize,
}

#[derive(Default)]
struct SchedulerInner {
    queues: HashMap<i64, VecDeque<Job>>,
    order: VecDeque<i64>,
    queued: usize,
}

impl FairScheduler {
    pub fn new(workers: usize, stack_mb: usize) -> Arc<Self> {
        let workers = workers.max(1);
        let sched = Arc::new(Self {
            inner: Mutex::new(SchedulerInner::default()),
            cv: Condvar::new(),
            busy: AtomicUsize::new(0),
        });

        for n in 0..workers {
            let s = Arc::clone(&sched);
            std::thread::Builder::new()
                .name(format!("engine-{n}"))
                .stack_size(stack_mb.max(8) * 1024 * 1024)
                .spawn(move || s.worker_loop())
                .expect("cannot start engine thread");
        }
        sched
    }

    fn worker_loop(&self) {
        loop {
            let job = self.next_job();
            self.busy.fetch_add(1, Ordering::Relaxed);
            // A panicking scan drops its result sender; the waiting side reports it as an error.
            let _ = catch_unwind(AssertUnwindSafe(job));
            self.busy.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn submit(&self, session_id: i64, job: Job) {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        let q = inner.queues.entry(session_id).or_default();
        q.push_back(job);
        if q.len() == 1 {
            inner.order.push_back(session_id);
        }
        inner.queued += 1;
        drop(g);
        self.cv.notify_one();
    }

    fn next_job(&self) -> Job {
        let mut g = self.inner.lock().unwrap();
        loop {
            {
                let inner = &mut *g;
                while let Some(sid) = inner.order.pop_front() {
                    let Some(q) = inner.queues.get_mut(&sid) else { continue };
                    let job = q.pop_front();
                    let empty = q.is_empty();
                    if empty {
                        inner.queues.remove(&sid);
                    } else {
                        inner.order.push_back(sid);
                    }
                    if let Some(job) = job {
                        inner.queued -= 1;
                        return job;
                    }
                }
            }
            g = self.cv.wait(g).unwrap();
        }
    }

    pub fn queued(&self) -> usize {
        self.inner.lock().unwrap().queued
    }

    pub fn busy(&self) -> usize {
        self.busy.load(Ordering::Relaxed)
    }
}
