// HydraDragonIDE — Tauri Backend Entry Point
// Delegates to lib.rs for the actual app runner.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    hydra_dragon_ide::run();
}
