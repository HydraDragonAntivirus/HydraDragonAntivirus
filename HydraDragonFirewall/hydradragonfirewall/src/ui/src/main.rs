#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;

use eframe::egui;

fn main() -> eframe::Result<()> {
    env_logger::init(); // Log to stderr
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1200.0, 800.0])
            .with_title("HydraDragon EDR Command Center"),
        ..Default::default()
    };
    
    eframe::run_native(
        "HydraDragon Tactical UI",
        options,
        Box::new(|cc| {
            // Future configuration: Load custom fonts for "Tactical/Cyberpunk" theme here
            Box::new(app::FirewallApp::new(cc))
        }),
    )
}
