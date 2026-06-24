//! hydradragonegui — a safe egui/eframe GUI for the HydraDragon portable antivirus.
//!
//! Replaces the raw Win32/GDI `hydradragonwingui` (full of `unsafe extern` FFI and
//! manual GDI painting) with pure, safe Rust: egui for the UI, `rfd` for native
//! dialogs, and a background worker that owns the `hydradragonav` `Pipeline` and
//! streams scan results back over a channel. No `unsafe`, cross-platform.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use egui::{Color32, RichText};

use hydradragonav::pipeline::PipelineConfig;
use hydradragonav::verdict::Verdict;

mod worker;
use worker::{EnginePhase, ResultRow, ToUi, ToWorker};

// --------------------------------------------------------------------------- #
// Palette (named like the Win32 GUI's DARK theme, but plain egui Color32).
// --------------------------------------------------------------------------- #
const ACCENT: Color32 = Color32::from_rgb(0x4A, 0x90, 0xFF);
const DANGER: Color32 = Color32::from_rgb(0xF0, 0x4C, 0x62);
const WARN: Color32 = Color32::from_rgb(0xF0, 0xA8, 0x00);
const OK: Color32 = Color32::from_rgb(0x28, 0xD4, 0x6A);
const MUTED: Color32 = Color32::from_rgb(0x84, 0x8E, 0xA8);

/// Severity (0–100) → colour (matches the Win32 `sev_color`).
fn sev_color(sev: u8) -> Color32 {
    if sev >= 80 {
        DANGER
    } else if sev >= 55 {
        WARN
    } else if sev >= 30 {
        ACCENT
    } else {
        OK
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Scan,
    Results,
    Quarantine,
    Settings,
    About,
}

/// Editable engine paths / options (Settings). Portable-layout defaults (paths are
/// resolved relative to the executable directory, exactly like the Win32 GUI).
#[derive(Clone)]
struct Settings {
    base_dir: String,
    fast_scan: bool,
    clamav_heuristics: bool,
    ml_threshold: f32,
}

impl Default for Settings {
    fn default() -> Self {
        let base = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| PathBuf::from("."));
        Settings {
            base_dir: base.display().to_string(),
            fast_scan: true,
            clamav_heuristics: false,
            ml_threshold: 0.8,
        }
    }
}

impl Settings {
    fn to_pipeline_config(&self) -> PipelineConfig {
        let base = PathBuf::from(&self.base_dir);
        let dir = |sub: &str| {
            let p = base.join(sub);
            p.exists().then_some(p)
        };
        PipelineConfig {
            clamav_db: dir("database"),
            yara_rules_dir: dir("yara-x"),
            hydradragonsig_rules_dir: dir("hydradragonsig_rules"),
            bloom_dir: dir("bloom_filter"),
            pe_ml_model_path: dir("ml/pe_model.mpk"),
            js_ml_model_path: dir("ml/js_model.mpk"),
            results_cache_dir: Some(base.clone()),
            fast_scan: self.fast_scan,
            clamav_heuristics: self.clamav_heuristics,
            ml_threshold: self.ml_threshold,
            ..PipelineConfig::default()
        }
    }
}

// --------------------------------------------------------------------------- #
struct App {
    page: Page,
    settings: Settings,
    to_worker: Option<Sender<ToWorker>>,
    from_worker: Receiver<ToUi>,
    to_ui: Sender<ToUi>,
    cancel: Arc<AtomicBool>,
    engine_phase: EnginePhase,
    load_status: String,
    scanning: bool,
    scanned: usize,
    detections: usize,
    current_file: String,
    results: Vec<ResultRow>,
    // Quarantine page.
    quar_rows: Vec<(String, String, String, u64)>, // id, original_path, detection, size
    quar_selected: Option<usize>,
    status: String,
    dark: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        let (to_ui, from_worker) = channel();
        let mut app = App {
            page: Page::Scan,
            settings: Settings::default(),
            to_worker: None,
            from_worker,
            to_ui,
            cancel: Arc::new(AtomicBool::new(false)),
            engine_phase: EnginePhase::Idle,
            load_status: String::new(),
            scanning: false,
            scanned: 0,
            detections: 0,
            current_file: String::new(),
            results: Vec::new(),
            quar_rows: Vec::new(),
            quar_selected: None,
            status: "Loading engines…".into(),
            dark: true,
        };
        app.spawn_worker();
        app
    }

    fn spawn_worker(&mut self) {
        let (to_worker_tx, to_worker_rx) = channel();
        self.to_worker = Some(to_worker_tx);
        self.engine_phase = EnginePhase::Loading;
        self.load_status = "Loading engines…".into();
        let to_ui = self.to_ui.clone();
        let cancel = Arc::clone(&self.cancel);
        let config = self.settings.to_pipeline_config();
        std::thread::spawn(move || worker::run(config, to_worker_rx, to_ui, cancel));
    }

    fn start_scan(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() || self.engine_phase != EnginePhase::Ready || self.scanning {
            return;
        }
        // Exclude our own executable directory from scanning (like the Win32 GUI).
        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf));
        let paths: Vec<PathBuf> = match exe_dir {
            Some(d) => paths.into_iter().filter(|p| !p.starts_with(&d)).collect(),
            None => paths,
        };
        self.scanning = true;
        self.scanned = 0;
        self.detections = 0;
        self.results.clear();
        self.page = Page::Results;
        self.status = "Scanning…".into();
        if let Some(tx) = &self.to_worker {
            let _ = tx.send(ToWorker::Scan(paths));
        }
    }

    fn stop_scan(&mut self) {
        self.cancel.store(true, Ordering::SeqCst);
        self.status = "Stopping…".into();
    }

    fn refresh_quarantine(&mut self) {
        let qdir = PathBuf::from(&self.settings.base_dir).join("quarantine");
        let q = hydradragonav::quarantine::Quarantine::new(&qdir);
        self.quar_rows = q
            .list()
            .into_iter()
            .map(|e| (e.id, e.original_path.display().to_string(), e.detection, e.size))
            .collect();
        self.status = format!("{} quarantined item(s).", self.quar_rows.len());
    }

    fn drain_worker(&mut self) {
        while let Ok(msg) = self.from_worker.try_recv() {
            match msg {
                ToUi::Loaded { signatures } => {
                    self.engine_phase = EnginePhase::Ready;
                    self.load_status = format!("Engines ready — {signatures} signatures.");
                    if !self.scanning {
                        self.status = self.load_status.clone();
                    }
                }
                ToUi::Progress { file } => {
                    self.scanned += 1;
                    self.current_file = file;
                }
                ToUi::Detection(row) => {
                    self.detections += 1;
                    self.results.push(*row);
                }
                ToUi::ScanDone => {
                    self.scanning = false;
                    self.current_file.clear();
                    self.cancel.store(false, Ordering::SeqCst);
                    self.status = format!(
                        "Scan complete — {} scanned, {} detections.",
                        self.scanned, self.detections
                    );
                }
                ToUi::Error(e) => self.status = format!("Error: {e}"),
            }
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.drain_worker();
        ctx.request_repaint_after(Duration::from_millis(if self.scanning { 100 } else { 1000 }));

        self.sidebar(ctx);
        self.status_bar(ctx);
        egui::CentralPanel::default().show(ctx, |ui| match self.page {
            Page::Scan => self.page_scan(ui),
            Page::Results => self.page_results(ui),
            Page::Quarantine => self.page_quarantine(ui),
            Page::Settings => self.page_settings(ui),
            Page::About => self.page_about(ui),
        });

        // Drag-and-drop files/folders → scan (mirrors the Win32 GUI).
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect()
        });
        if !dropped.is_empty() && self.engine_phase == EnginePhase::Ready && !self.scanning {
            let mut files = Vec::new();
            for p in dropped {
                if p.is_dir() {
                    files.extend(collect_files(&p));
                } else {
                    files.push(p);
                }
            }
            self.start_scan(files);
        }
    }
}

// --------------------------------------------------------------------------- #
impl App {
    fn sidebar(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("nav").resizable(false).exact_width(190.0).show(ctx, |ui| {
            ui.add_space(12.0);
            ui.heading(RichText::new("🐉 HydraDragon").color(ACCENT));
            ui.label(RichText::new("Antivirus").color(MUTED).small());
            ui.add_space(16.0);
            let mut nav = |ui: &mut egui::Ui, this: Page, label: &str| {
                if ui.selectable_label(self.page == this, RichText::new(label).size(15.0)).clicked() {
                    self.page = this;
                    if this == Page::Quarantine {
                        // refresh handled below to avoid borrow issues
                    }
                }
            };
            let before = self.page;
            nav(ui, Page::Scan, "🛡  Scan");
            nav(ui, Page::Results, "📋  Results");
            nav(ui, Page::Quarantine, "🔒  Quarantine");
            nav(ui, Page::Settings, "⚙  Settings");
            nav(ui, Page::About, "ℹ  About");
            if self.page == Page::Quarantine && before != Page::Quarantine {
                self.refresh_quarantine();
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(8.0);
                if ui.checkbox(&mut self.dark, "Dark theme").changed() {
                    ctx.set_visuals(if self.dark { egui::Visuals::dark() } else { egui::Visuals::light() });
                }
                match self.engine_phase {
                    EnginePhase::Loading => { ui.colored_label(WARN, "● loading engines…"); }
                    EnginePhase::Ready => { ui.colored_label(OK, "● engines ready"); }
                    EnginePhase::Stopped => { ui.colored_label(MUTED, "● engines stopped"); }
                    EnginePhase::Idle => {}
                }
            });
        });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let rss = hydradragonav::metrics::working_set_mb();
                    let peak = hydradragonav::metrics::peak_working_set_mb();
                    let cpu = hydradragonav::metrics::process_cpu_secs();
                    ui.label(RichText::new(format!("RAM {rss:.0} MB  (peak {peak:.0})   CPU {cpu:.0}s")).color(MUTED));
                });
            });
        });
    }

    fn page_scan(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Scan");
        ui.label(RichText::new("Pick a file or folder (or drag-and-drop) to scan with all engines: ClamAV, YARA-X, ML, static analysis.").color(MUTED));
        ui.add_space(16.0);

        let ready = self.engine_phase == EnginePhase::Ready && !self.scanning;
        ui.horizontal(|ui| {
            if ui.add_enabled(ready, egui::Button::new("📄  Scan File…")).clicked() {
                if let Some(file) = rfd::FileDialog::new().pick_file() {
                    self.start_scan(vec![file]);
                }
            }
            if ui.add_enabled(ready, egui::Button::new("📁  Scan Folder…")).clicked() {
                if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                    let files = collect_files(&dir);
                    self.start_scan(files);
                }
            }
            if self.scanning && ui.button("⏹  Stop").clicked() {
                self.stop_scan();
            }
        });

        ui.add_space(20.0);
        if self.scanning {
            ui.add(egui::ProgressBar::new(0.0).animate(true).desired_width(360.0));
            ui.label(format!("Scanning… {} scanned, {} detections", self.scanned, self.detections));
            ui.label(RichText::new(&self.current_file).color(MUTED).small());
        } else {
            ui.label(RichText::new(&self.load_status).color(MUTED));
        }
    }

    fn page_results(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("Results");
            ui.label(RichText::new(format!("{} detections / {} scanned", self.detections, self.scanned)).color(MUTED));
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button("Save report…").clicked() {
                    self.save_report();
                }
            });
        });
        ui.separator();
        use egui_extras::{Column, TableBuilder};
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::auto().at_least(110.0))
            .column(Column::remainder().at_least(220.0))
            .column(Column::auto().at_least(160.0))
            .column(Column::auto().at_least(56.0))
            .header(22.0, |mut h| {
                h.col(|ui| { ui.strong("Verdict"); });
                h.col(|ui| { ui.strong("File"); });
                h.col(|ui| { ui.strong("Threat"); });
                h.col(|ui| { ui.strong("ms"); });
            })
            .body(|mut body| {
                for r in &self.results {
                    body.row(20.0, |mut row| {
                        row.col(|ui| {
                            ui.colored_label(sev_color(r.sev), format!("{} ({})", r.verdict.label(), r.sev));
                        });
                        row.col(|ui| { ui.label(&r.path).on_hover_text(&r.detail); });
                        row.col(|ui| { ui.label(&r.threat); });
                        row.col(|ui| { ui.label(format!("{}", r.elapsed_ms)); });
                    });
                }
            });
        if self.results.is_empty() && !self.scanning {
            ui.add_space(20.0);
            ui.colored_label(OK, "No threats found.");
        }
    }

    fn page_quarantine(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("Quarantine");
            if ui.button("🔄 Refresh").clicked() {
                self.refresh_quarantine();
            }
        });
        ui.separator();
        let qdir = PathBuf::from(&self.settings.base_dir).join("quarantine");
        let mut action: Option<bool> = None; // Some(true)=restore, Some(false)=delete
        use egui_extras::{Column, TableBuilder};
        TableBuilder::new(ui)
            .striped(true)
            .sense(egui::Sense::click())
            .column(Column::auto().at_least(180.0))
            .column(Column::remainder().at_least(220.0))
            .column(Column::auto().at_least(120.0))
            .column(Column::auto().at_least(70.0))
            .header(22.0, |mut h| {
                h.col(|ui| { ui.strong("ID"); });
                h.col(|ui| { ui.strong("Original path"); });
                h.col(|ui| { ui.strong("Detection"); });
                h.col(|ui| { ui.strong("Size"); });
            })
            .body(|mut body| {
                for (i, (id, orig, det, size)) in self.quar_rows.iter().enumerate() {
                    let selected = self.quar_selected == Some(i);
                    body.row(20.0, |mut row| {
                        row.set_selected(selected);
                        row.col(|ui| { ui.label(id); });
                        row.col(|ui| { ui.label(orig); });
                        row.col(|ui| { ui.label(det); });
                        row.col(|ui| { ui.label(format!("{size}")); });
                        if row.response().clicked() {
                            self.quar_selected = Some(i);
                        }
                    });
                }
            });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let has = self.quar_selected.is_some();
            if ui.add_enabled(has, egui::Button::new("↩ Restore selected")).clicked() {
                action = Some(true);
            }
            if ui.add_enabled(has, egui::Button::new("🗑 Delete selected")).clicked() {
                action = Some(false);
            }
        });
        if let (Some(restore), Some(idx)) = (action, self.quar_selected) {
            if let Some(row) = self.quar_rows.get(idx) {
                let id = row.0.clone();
                let q = hydradragonav::quarantine::Quarantine::new(&qdir);
                let _ = if restore { q.restore(&id) } else { q.delete(&id) };
            }
            self.quar_selected = None;
            self.refresh_quarantine();
        }
        if self.quar_rows.is_empty() {
            ui.add_space(12.0);
            ui.label(RichText::new("No quarantined items.").color(MUTED));
        }
    }

    fn page_settings(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("Settings");
        ui.separator();
        egui::Grid::new("settings").num_columns(2).spacing([16.0, 10.0]).show(ui, |ui| {
            ui.label("Base directory");
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.settings.base_dir);
                if ui.button("Browse…").clicked() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        self.settings.base_dir = d.display().to_string();
                    }
                }
            });
            ui.end_row();
            ui.label("Fast scan");
            ui.checkbox(&mut self.settings.fast_scan, "");
            ui.end_row();
            ui.label("ClamAV heuristics");
            ui.checkbox(&mut self.settings.clamav_heuristics, "");
            ui.end_row();
            ui.label("ML threshold");
            ui.add(egui::Slider::new(&mut self.settings.ml_threshold, 0.0..=1.0));
            ui.end_row();
        });
        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Apply & reload engines").clicked() {
                let cfg = self.settings.to_pipeline_config();
                self.engine_phase = EnginePhase::Loading;
                self.status = "Reloading engines…".into();
                if let Some(tx) = &self.to_worker {
                    let _ = tx.send(ToWorker::Reload(cfg));
                }
            }
            if ui.button("Clear result cache").clicked() {
                if let Some(tx) = &self.to_worker {
                    let _ = tx.send(ToWorker::ClearCache);
                }
            }
        });
    }

    fn page_about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("HydraDragon Antivirus");
        ui.label("Safe egui GUI (hydradragonegui) — replaces the raw Win32 GUI.");
        ui.add_space(8.0);
        ui.label(RichText::new("Engines: ClamAV (pure-Rust), YARA-X, ML (PE/JS), static analysis.").color(MUTED));
        ui.label(RichText::new("No unsafe Win32 FFI — pure, safe Rust UI.").color(MUTED));
    }

    /// Write the results to a CSV report (mirrors the Win32 Save Results).
    fn save_report(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .add_filter("Text", &["txt"])
            .set_file_name("hydradragon_report.csv")
            .save_file()
        else {
            return;
        };
        let mut out = String::from("File,Verdict,Threat,Severity\n");
        for r in &self.results {
            out.push_str(&format!(
                "{},{},{},{}\n",
                r.path.replace(',', " "),
                r.verdict.label(),
                r.threat.replace(',', " "),
                r.sev
            ));
        }
        match std::fs::write(&path, out) {
            Ok(_) => self.status = format!("Report saved → {}", path.display()),
            Err(e) => self.status = format!("Save failed: {e}"),
        }
    }
}

/// Recursively collect regular files under `dir`.
fn collect_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        if let Ok(rd) = std::fs::read_dir(&d) {
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
    }
    out
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([720.0, 480.0])
            .with_title("HydraDragon Antivirus"),
        ..Default::default()
    };
    eframe::run_native(
        "HydraDragon Antivirus",
        options,
        Box::new(|cc| Ok(Box::new(App::new(cc)))),
    )
}
