use eframe::egui::{self, Color32, RichText, Visuals};
use std::collections::VecDeque;
use chrono::Local;

// Ring buffer max capacity
const MAX_LOG_LINES: usize = 1000;

#[derive(Clone)]
pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub protocol: String,
    pub action: String,
    pub details: String,
}

pub struct FirewallApp {
    logs: VecDeque<LogEntry>,
}

impl FirewallApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        // Tactical Tech-Noir theme
        let mut visuals = Visuals::dark();
        // Pitch black / Dark metallic background
        visuals.window_fill = Color32::from_rgb(10, 10, 12); 
        visuals.panel_fill = Color32::from_rgb(10, 10, 12);
        cc.egui_ctx.set_visuals(visuals);

        let mut app = Self {
            logs: VecDeque::with_capacity(MAX_LOG_LINES),
        };

        // Dummy data for rendering preview
        app.add_log(LogEntry {
            timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
            level: "INFO".to_string(),
            source_ip: "127.0.0.1".to_string(),
            dest_ip: "127.0.0.1".to_string(),
            protocol: "TCP".to_string(),
            action: "SYSTEM".to_string(),
            details: "Command Center Initialized. Listening on UNIX Socket/gRPC...".to_string(),
        });
        app.add_log(LogEntry {
            timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
            level: "WARN".to_string(),
            source_ip: "192.168.1.102".to_string(),
            dest_ip: "8.8.8.8".to_string(),
            protocol: "UDP".to_string(),
            action: "ALLOW".to_string(),
            details: "External DNS Query Detected".to_string(),
        });
        app.add_log(LogEntry {
            timestamp: Local::now().format("%H:%M:%S%.3f").to_string(),
            level: "CRITICAL".to_string(),
            source_ip: "103.45.67.89".to_string(),
            dest_ip: "192.168.1.50".to_string(),
            protocol: "TCP".to_string(),
            action: "BLOCK".to_string(),
            details: "Syn Flood Pattern / Port Scan Attempt".to_string(),
        });

        app
    }

    pub fn add_log(&mut self, log: LogEntry) {
        // Ring buffer logic: Drop oldest if at capacity
        if self.logs.len() >= MAX_LOG_LINES {
            self.logs.pop_front();
        }
        self.logs.push_back(log);
    }
}

impl eframe::App for FirewallApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::TopBottomPanel::top("header_panel").show(ctx, |ui| {
            ui.add_space(10.0);
            ui.horizontal(|ui| {
                ui.heading(
                    RichText::new("HYDRADRAGON FIREWALL COMMAND CENTER")
                        .color(Color32::from_rgb(0, 255, 150)) // Tech-Noir Neon Green
                        .size(24.0)
                        .strong(),
                );
                
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("ROOT AUTHORITY VERIFIED")
                            .color(Color32::from_rgb(255, 60, 60)) // Tactical Red
                            .size(16.0)
                            .strong(),
                    );
                });
            });
            ui.add_space(5.0);
            ui.separator();
        });

        // Bottom panel for connection status
        egui::TopBottomPanel::bottom("footer_panel").show(ctx, |ui| {
            ui.add_space(4.0);
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("● Engine Connection: WAITING_IPC")
                        .color(Color32::from_rgb(200, 200, 50))
                );
                ui.separator();
                ui.label(format!("Live Logs in RAM: {} / {}", self.logs.len(), MAX_LOG_LINES));
            });
            ui.add_space(4.0);
        });

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(5.0);
            
            // Render the live log table using egui_extras
            use egui_extras::{TableBuilder, Column};

            let table = TableBuilder::new(ui)
                .striped(true) // Alternating row colors
                .resizable(true)
                .vscroll(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .column(Column::initial(100.0).at_least(80.0)) // Timestamp
                .column(Column::initial(80.0).at_least(50.0))  // Level
                .column(Column::initial(120.0).at_least(100.0)) // Source IP
                .column(Column::initial(120.0).at_least(100.0)) // Dest IP
                .column(Column::initial(60.0).at_least(40.0))  // Protocol
                .column(Column::initial(80.0).at_least(60.0))  // Action
                .column(Column::remainder().at_least(200.0))    // Details
                .min_scrolled_height(0.0);

            table.header(24.0, |mut header| {
                header.col(|ui| { ui.strong("TIME"); });
                header.col(|ui| { ui.strong("LEVEL"); });
                header.col(|ui| { ui.strong("SRC IP"); });
                header.col(|ui| { ui.strong("DST IP"); });
                header.col(|ui| { ui.strong("PROTO"); });
                header.col(|ui| { ui.strong("ACTION"); });
                header.col(|ui| { ui.strong("DETAILS"); });
            })
            .body(|mut body| {
                for log in &self.logs {
                    body.row(20.0, |mut row| {
                        row.col(|ui| { 
                            ui.label(RichText::new(&log.timestamp).color(Color32::LIGHT_GRAY)); 
                        });
                        row.col(|ui| { 
                            let color = match log.level.as_str() {
                                "CRITICAL" => Color32::from_rgb(255, 50, 50),
                                "WARN" => Color32::from_rgb(255, 200, 50),
                                _ => Color32::from_rgb(0, 200, 255),
                            };
                            ui.label(RichText::new(&log.level).color(color).strong());
                        });
                        row.col(|ui| { ui.label(&log.source_ip); });
                        row.col(|ui| { ui.label(&log.dest_ip); });
                        row.col(|ui| { ui.label(&log.protocol); });
                        row.col(|ui| { 
                            let color = match log.action.as_str() {
                                "BLOCK" => Color32::from_rgb(255, 60, 60),
                                "ALLOW" => Color32::from_rgb(50, 255, 100),
                                _ => Color32::WHITE,
                            };
                            ui.label(RichText::new(&log.action).color(color).strong()); 
                        });
                        row.col(|ui| { 
                            ui.label(RichText::new(&log.details).color(Color32::from_rgb(200, 200, 200))); 
                        });
                    });
                }
            });
        });
    }
}
