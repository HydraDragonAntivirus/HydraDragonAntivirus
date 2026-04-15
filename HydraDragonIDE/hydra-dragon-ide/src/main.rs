// src/main.rs
// HydraDragonIDE — Yew/WASM frontend entry point.

mod app;
mod invoke;
mod types;

fn main() {
    wasm_logger::init(wasm_logger::Config::default());
    yew::Renderer::<app::App>::new().render();
}
