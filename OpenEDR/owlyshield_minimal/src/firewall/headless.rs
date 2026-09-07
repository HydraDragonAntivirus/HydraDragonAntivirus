use super::engine::FirewallEngine;
use std::sync::{Arc, Mutex, OnceLock};

/// Global registry of the single in-process `FirewallEngine` instance.
///
/// The engine is created and registered by `HydraDragonFirewall_Start` and
/// stopped/unregistered by `HydraDragonFirewall_Stop`. Holding a strong `Arc`
/// here keeps the engine alive for the lifetime of the loaded DLL.
static GLOBAL_ENGINE: OnceLock<Mutex<Option<Arc<FirewallEngine>>>> = OnceLock::new();

/// Dedicated multi-threaded tokio runtime used for the embedded proxy and the
/// named-pipe telemetry readers. Kept alive for the lifetime of the DLL.
static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

fn engine_slot() -> &'static Mutex<Option<Arc<FirewallEngine>>> {
    GLOBAL_ENGINE.get_or_init(|| Mutex::new(None))
}

pub(crate) fn register(engine: Arc<FirewallEngine>) -> bool {
    let mut slot = engine_slot().lock().unwrap();
    if slot.is_some() {
        return false;
    }
    *slot = Some(engine);
    true
}

/// Stops and unregisters the running engine. Safe to call repeatedly.
pub(crate) fn unregister_and_stop() {
    let engine = engine_slot().lock().unwrap().take();
    if let Some(engine) = engine {
        engine.stop();
    }
}

pub(crate) fn engine() -> Option<Arc<FirewallEngine>> {
    engine_slot().lock().unwrap().clone()
}

pub(crate) fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("failed to create HydraDragonFirewall tokio runtime")
    })
}

pub(crate) fn spawn<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    runtime().spawn(future);
}
