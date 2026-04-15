// src/invoke.rs
// Thin wrapper around window.__TAURI__.core.invoke so that Yew
// components can call backend commands with typed args and results.

use js_sys::{Function, Promise, Reflect};
use serde::{de::DeserializeOwned, Serialize};
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

/// Call a Tauri command by name.
///
/// `args` is serialised to a JS object via `serde-wasm-bindgen`.
/// The returned Promise value is deserialised back into `R`.
///
/// On error (compile-time or runtime), returns `Err(String)`.
pub async fn invoke<A: Serialize, R: DeserializeOwned>(
    cmd: &str,
    args: &A,
) -> Result<R, String> {
    // Resolve window.__TAURI__.core.invoke
    let window = web_sys::window().ok_or("No global window")?;
    let tauri = Reflect::get(&window, &JsValue::from_str("__TAURI__"))
        .map_err(|_| "__TAURI__ not found — is this running inside Tauri?")?;
    let core = Reflect::get(&tauri, &JsValue::from_str("core"))
        .map_err(|_| "__TAURI__.core not found")?;
    let invoke_fn: Function = Reflect::get(&core, &JsValue::from_str("invoke"))
        .map_err(|_| "__TAURI__.core.invoke not found")?
        .dyn_into()
        .map_err(|_| "invoke is not a Function")?;

    // Serialise args to JsValue
    let js_args = serde_wasm_bindgen::to_value(args)
        .map_err(|e| format!("Arg serialise error: {e}"))?;

    // Call invoke(cmd, args) → Promise
    let promise_val = invoke_fn
        .call2(&JsValue::NULL, &JsValue::from_str(cmd), &js_args)
        .map_err(|e| format!("invoke call failed: {e:?}"))?;

    let promise: Promise = promise_val
        .dyn_into()
        .map_err(|_| "invoke did not return a Promise")?;

    // Await the Promise
    let js_result = JsFuture::from(promise)
        .await
        .map_err(|e| {
            // Tauri sends Err strings as rejected promise values.
            e.as_string().unwrap_or_else(|| format!("{e:?}"))
        })?;

    // Deserialise result
    serde_wasm_bindgen::from_value(js_result)
        .map_err(|e| format!("Result deserialise error: {e}"))
}
