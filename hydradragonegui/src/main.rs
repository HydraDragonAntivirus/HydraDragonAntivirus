//! hydradragonegui — a safe egui/eframe GUI for the HydraDragon portable antivirus.
//!
//! Replaces the raw Win32/GDI `hydradragonwingui` (full of `unsafe extern` FFI and
//! manual GDI painting) with pure, safe Rust: egui for the UI, `rfd` for native
//! dialogs, and a background worker that owns the `hydradragonav` `Pipeline` and
//! streams scan results back over a channel. No `unsafe`.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Duration;

use eframe::egui;
use egui::{Color32, RichText};

use hydradragonav::pipeline::PipelineConfig;

mod worker;
use worker::{
    EnginePhase, ResultRow, ToUi, ToWorker, CAT_BOOT, CAT_MEMORY, CAT_PUM, CAT_REGISTRY, CAT_SIGMA,
    CAT_STARTUP,
};

// --------------------------------------------------------------------------- #
// Palette (named like the Win32 GUI's DARK theme, but plain egui Color32).
// --------------------------------------------------------------------------- #
const ACCENT: Color32 = Color32::from_rgb(0x4A, 0x90, 0xFF);
const DANGER: Color32 = Color32::from_rgb(0xF0, 0x4C, 0x62);
const WARN: Color32 = Color32::from_rgb(0xF0, 0xA8, 0x00);
const OK: Color32 = Color32::from_rgb(0x28, 0xD4, 0x6A);
const MUTED: Color32 = Color32::from_rgb(0x84, 0x8E, 0xA8);

/// All seven scan categories with their bitmask + label (option panel order).
const CATEGORIES: &[(u8, &str)] = &[
    (CAT_REGISTRY, "Registry autoruns & PUA entries"),
    (CAT_MEMORY, "Process memory (behavioral)"),
    (CAT_SIGMA, "Event logs (Sigma / Hayabusa)"),
    (CAT_STARTUP, "Startup objects + their executables"),
    (CAT_BOOT, "Boot sectors"),
    (CAT_PUM, "PUM (potentially unwanted modifications)"),
];

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

/// Human label for a severity score (used in the TXT report).
fn sev_label(sev: u8) -> &'static str {
    if sev >= 80 {
        "CRITICAL"
    } else if sev >= 55 {
        "HIGH"
    } else if sev >= 30 {
        "MEDIUM"
    } else {
        "LOW"
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

/// Scan lifecycle, drives the button set (mirrors the Win32 `ScanState`).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScanState {
    Idle,
    Scanning,
    Paused,
    Done,
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
        Settings {
            base_dir: exe_dir().display().to_string(),
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
            hayabusa_dir: dir("hayabusa"),
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
    pause: Arc<AtomicBool>,
    abort: Arc<AtomicBool>,
    engine_phase: EnginePhase,
    load_status: String,
    signatures: usize,
    scan_state: ScanState,
    scanned: usize,
    detections: usize,
    current_file: String,
    results: Vec<ResultRow>,
    // Custom-scan option panel.
    opt_panel: bool,
    opt_cats: u8,
    opt_items: Vec<PathBuf>,
    // Quarantine page.
    quar_rows: Vec<(String, String, String, u64)>, // id, original_path, detection, size
    quar_selected: Option<usize>,
    status: String,
    dark: bool,
}

impl App {
    fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let settings = Settings::default();
        let dark = load_dark(&settings.base_dir);
        cc.egui_ctx
            .set_visuals(if dark { egui::Visuals::dark() } else { egui::Visuals::light() });
        let (to_ui, from_worker) = channel();
        let mut app = App {
            page: Page::Scan,
            settings,
            to_worker: None,
            from_worker,
            to_ui,
            pause: Arc::new(AtomicBool::new(false)),
            abort: Arc::new(AtomicBool::new(false)),
            engine_phase: EnginePhase::Idle,
            load_status: String::new(),
            signatures: 0,
            scan_state: ScanState::Idle,
            scanned: 0,
            detections: 0,
            current_file: String::new(),
            results: Vec::new(),
            opt_panel: false,
            opt_cats: 0,
            opt_items: Vec::new(),
            quar_rows: Vec::new(),
            quar_selected: None,
            status: "Loading engines…".into(),
            dark,
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
        let pause = Arc::clone(&self.pause);
        let abort = Arc::clone(&self.abort);
        let config = self.settings.to_pipeline_config();
        std::thread::spawn(move || worker::run(config, to_worker_rx, to_ui, pause, abort));
    }

    fn send(&self, msg: ToWorker) {
        if let Some(tx) = &self.to_worker {
            let _ = tx.send(msg);
        }
    }

    fn ready(&self) -> bool {
        self.engine_phase == EnginePhase::Ready
            && matches!(self.scan_state, ScanState::Idle | ScanState::Done)
    }

    /// Begin a scan over `paths`, running the selected category phases (`cats`).
    fn start_scan(&mut self, paths: Vec<PathBuf>, cats: u8) {
        if !self.ready() || (paths.is_empty() && cats == 0) {
            return;
        }
        // Exclude our own executable directory (like the Win32 GUI).
        let exe = exe_dir();
        let paths: Vec<PathBuf> = paths.into_iter().filter(|p| !p.starts_with(&exe)).collect();
        self.pause.store(false, Ordering::SeqCst);
        self.abort.store(false, Ordering::SeqCst);
        self.scan_state = ScanState::Scanning;
        self.scanned = 0;
        self.detections = 0;
        self.results.clear();
        self.opt_panel = false;
        self.page = Page::Results;
        self.status = "Scanning…".into();
        self.send(ToWorker::Scan { paths, cats });
    }

    fn pause_scan(&mut self) {
        self.pause.store(true, Ordering::SeqCst);
        self.status = "Pausing…".into();
    }

    fn resume_scan(&mut self) {
        self.scan_state = ScanState::Scanning;
        self.status = "Resuming…".into();
        self.send(ToWorker::Resume);
    }

    fn stop_scan(&mut self) {
        self.abort.store(true, Ordering::SeqCst);
        self.pause.store(false, Ordering::SeqCst);
        self.status = "Stopping…".into();
    }

    /// Paths of currently-checked, on-disk-file detections.
    fn checked_files(&self) -> Vec<PathBuf> {
        self.results
            .iter()
            .filter(|r| r.checked && r.cleanable)
            .map(|r| PathBuf::from(&r.path))
            .collect()
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
                ToUi::EngineLoading => {
                    self.engine_phase = EnginePhase::Loading;
                    self.load_status = "Loading engines…".into();
                    self.status = self.load_status.clone();
                }
                ToUi::Loaded { signatures } => {
                    self.engine_phase = EnginePhase::Ready;
                    self.signatures = signatures;
                    self.load_status = format!("Engines ready — {signatures} signatures.");
                    if self.scan_state == ScanState::Idle {
                        self.status = self.load_status.clone();
                    }
                }
                ToUi::EngineStopped => {
                    self.engine_phase = EnginePhase::Stopped;
                    self.status = "Engines stopped.".into();
                }
                ToUi::Progress { scanned, threats, current } => {
                    self.scanned = scanned;
                    self.detections = threats;
                    self.current_file = current;
                }
                ToUi::Detection(row) => {
                    self.detections += 1;
                    self.results.push(*row);
                }
                ToUi::Rescanned { path, row } => {
                    self.results.retain(|r| r.path != path);
                    if let Some(r) = row {
                        self.results.push(*r);
                    }
                    self.detections = self.results.len();
                }
                ToUi::Cleaned { path, outcome } => {
                    self.results.retain(|r| r.path != path);
                    self.detections = self.results.len();
                    self.status = format!("{path}: {outcome}");
                }
                ToUi::ScanDone { scanned, threats } => {
                    self.scan_state = ScanState::Done;
                    self.scanned = scanned;
                    self.detections = threats;
                    self.current_file.clear();
                    self.status = format!("Scan complete — {scanned} scanned, {threats} detections.");
                }
                ToUi::Paused { scanned, threats, remaining } => {
                    self.scan_state = ScanState::Paused;
                    self.scanned = scanned;
                    self.detections = threats;
                    self.status = format!("Paused — {scanned} scanned, {remaining} remaining.");
                }
                ToUi::Stopped => {
                    self.scan_state = ScanState::Idle;
                    self.current_file.clear();
                    self.status = "Scan stopped.".into();
                }
                ToUi::Status(s) => self.status = s,
                ToUi::Error(e) => self.status = format!("Error: {e}"),
            }
        }
    }
}

impl Drop for App {
    fn drop(&mut self) {
        // Tell the worker to stop any scan and exit cleanly on window close.
        self.abort.store(true, Ordering::SeqCst);
        self.send(ToWorker::Shutdown);
    }
}

impl eframe::App for App {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.drain_worker();
        let busy = matches!(self.scan_state, ScanState::Scanning);
        ctx.request_repaint_after(Duration::from_millis(if busy { 100 } else { 1000 }));

        self.sidebar(ui);
        self.status_bar(ui);
        egui::CentralPanel::default().show_inside(ui, |ui| match self.page {
            Page::Scan => self.page_scan(ui),
            Page::Results => self.page_results(ui),
            Page::Quarantine => self.page_quarantine(ui),
            Page::Settings => self.page_settings(ui),
            Page::About => self.page_about(ui),
        });

        // Drag-and-drop files/folders → quick scan (mirrors the Win32 GUI).
        let dropped: Vec<PathBuf> = ctx.input(|i| {
            i.raw.dropped_files.iter().filter_map(|f| f.path.clone()).collect()
        });
        if !dropped.is_empty() && self.ready() {
            let files = expand_paths(&dropped);
            self.start_scan(files, 0);
        }
    }
}

// --------------------------------------------------------------------------- #
impl App {
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        egui::Panel::left("nav").resizable(false).exact_size(190.0).show_inside(ui, |ui| {
            ui.add_space(12.0);
            ui.heading(RichText::new("🐉 HydraDragon").color(ACCENT));
            ui.label(RichText::new("Antivirus").color(MUTED).small());
            ui.add_space(16.0);
            let before = self.page;
            for (this, label) in [
                (Page::Scan, "🛡  Scan"),
                (Page::Results, "📋  Results"),
                (Page::Quarantine, "🔒  Quarantine"),
                (Page::Settings, "⚙  Settings"),
                (Page::About, "ℹ  About"),
            ] {
                if ui
                    .selectable_label(self.page == this, RichText::new(label).size(15.0))
                    .clicked()
                {
                    self.page = this;
                }
            }
            if self.page == Page::Quarantine && before != Page::Quarantine {
                self.refresh_quarantine();
            }

            ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
                ui.add_space(8.0);
                if ui.checkbox(&mut self.dark, "Dark theme").changed() {
                    ctx.set_visuals(if self.dark {
                        egui::Visuals::dark()
                    } else {
                        egui::Visuals::light()
                    });
                    save_dark(&self.settings.base_dir, self.dark);
                }
                match self.engine_phase {
                    EnginePhase::Loading => {
                        ui.horizontal(|ui| {
                            ui.add(egui::Spinner::new().size(14.0));
                            ui.colored_label(WARN, "loading engines…");
                        });
                    }
                    EnginePhase::Ready => {
                        ui.colored_label(OK, "● engines ready");
                    }
                    EnginePhase::Stopped => {
                        ui.colored_label(MUTED, "● engines stopped");
                    }
                    EnginePhase::Idle => {}
                }
            });
        });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(&self.status);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let rss = hydradragonav::metrics::working_set_mb();
                    let peak = hydradragonav::metrics::peak_working_set_mb();
                    let cpu = hydradragonav::metrics::process_cpu_secs();
                    ui.label(
                        RichText::new(format!("RAM {rss:.0} MB  (peak {peak:.0})   CPU {cpu:.0}s"))
                            .color(MUTED),
                    );
                });
            });
        });
    }

    fn page_scan(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        // Hero banner.
        self.hero(ui);
        ui.add_space(16.0);

        if self.opt_panel {
            self.custom_scan_panel(ui);
            return;
        }

        let ready = self.ready();
        ui.horizontal(|ui| match self.scan_state {
            ScanState::Scanning => {
                if ui.button("⏸  Pause").clicked() {
                    self.pause_scan();
                }
                if ui.button("⏹  Stop").clicked() {
                    self.stop_scan();
                }
            }
            ScanState::Paused => {
                if ui.button("▶  Resume").clicked() {
                    self.resume_scan();
                }
                if ui.button("⏹  Stop").clicked() {
                    self.stop_scan();
                }
            }
            _ => {
                if ui.add_enabled(ready, egui::Button::new("📄  Scan File…")).clicked() {
                    if let Some(file) = rfd::FileDialog::new().pick_file() {
                        self.start_scan(vec![file], 0);
                    }
                }
                if ui.add_enabled(ready, egui::Button::new("📁  Scan Folder…")).clicked() {
                    if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                        let files = collect_files(&dir);
                        self.start_scan(files, 0);
                    }
                }
                if ui.add_enabled(ready, egui::Button::new("⚙  Custom Scan…")).clicked() {
                    self.opt_panel = true;
                }
            }
        });
    }

    /// Big status badge + (when scanning) a progress bar.
    fn hero(&mut self, ui: &mut egui::Ui) {
        let (glyph, color, title, subtitle) = match self.scan_state {
            ScanState::Idle => (
                "🛡",
                ACCENT,
                "Ready to scan".to_string(),
                format!("{} signatures loaded", self.signatures),
            ),
            ScanState::Scanning => (
                "🔍",
                ACCENT,
                format!("Scanning…  {} threat(s)", self.detections),
                format!("{} scanned · {}", self.scanned, self.current_file),
            ),
            ScanState::Paused => (
                "⏸",
                WARN,
                "Scan paused".to_string(),
                format!("{} scanned · {} threats — Resume to continue", self.scanned, self.detections),
            ),
            ScanState::Done => {
                if self.detections == 0 {
                    (
                        "✔",
                        OK,
                        "No threats found".to_string(),
                        format!("{} files scanned — your system looks clean", self.scanned),
                    )
                } else {
                    (
                        "⚠",
                        DANGER,
                        format!("{} threat(s) found", self.detections),
                        "Review the detections, then Clean checked items".to_string(),
                    )
                }
            }
        };
        ui.horizontal(|ui| {
            ui.label(RichText::new(glyph).size(40.0).color(color));
            ui.vertical(|ui| {
                ui.label(RichText::new(title).size(22.0).strong().color(color));
                ui.label(RichText::new(subtitle).color(MUTED));
            });
        });
        if matches!(self.scan_state, ScanState::Scanning | ScanState::Paused) {
            ui.add_space(8.0);
            ui.add(egui::ProgressBar::new(0.0).animate(self.scan_state == ScanState::Scanning).desired_width(400.0));
        }
    }

    /// The custom-scan option card: category checkboxes + added objects.
    fn custom_scan_panel(&mut self, ui: &mut egui::Ui) {
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ui.heading("Custom scan");
            ui.label(RichText::new("Choose extra areas to scan beyond the files you add.").color(MUTED));
            ui.add_space(8.0);
            for (bit, label) in CATEGORIES {
                let mut on = self.opt_cats & bit != 0;
                if ui.checkbox(&mut on, *label).changed() {
                    self.opt_cats ^= bit; // toggle the bit
                }
            }
            if ui.link("Restore default (all categories)").clicked() {
                self.opt_cats = CATEGORIES.iter().fold(0, |acc, (b, _)| acc | b);
            }

            ui.add_space(10.0);
            ui.separator();
            ui.label(RichText::new("Objects to scan").strong());
            ui.horizontal(|ui| {
                if ui.button("➕ Add file…").clicked() {
                    if let Some(f) = rfd::FileDialog::new().pick_file() {
                        self.opt_items.push(f);
                    }
                }
                if ui.button("➕ Add folder…").clicked() {
                    if let Some(d) = rfd::FileDialog::new().pick_folder() {
                        self.opt_items.push(d);
                    }
                }
            });
            let mut remove: Option<usize> = None;
            for (i, p) in self.opt_items.iter().enumerate() {
                ui.horizontal(|ui| {
                    if ui.small_button("✖").clicked() {
                        remove = Some(i);
                    }
                    ui.label(p.display().to_string());
                });
            }
            if let Some(i) = remove {
                self.opt_items.remove(i);
            }

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                let can_start = !self.opt_items.is_empty() || self.opt_cats != 0;
                if ui.add_enabled(can_start, egui::Button::new("▶  Start scan")).clicked() {
                    let files = expand_paths(&self.opt_items);
                    let cats = self.opt_cats;
                    self.start_scan(files, cats);
                }
                if ui.button("Cancel").clicked() {
                    self.opt_panel = false;
                }
            });
        });
    }

    fn page_results(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.heading("Results");
            ui.label(
                RichText::new(format!("{} detections / {} scanned", self.detections, self.scanned))
                    .color(MUTED),
            );
        });

        // Action toolbar.
        ui.horizontal_wrapped(|ui| {
            let any_checked = self.results.iter().any(|r| r.checked);
            let any_clean = self.results.iter().any(|r| r.checked && r.cleanable);
            if ui.button("☑ Select all").clicked() {
                for r in &mut self.results {
                    r.checked = true;
                }
            }
            if ui.button("☐ Deselect all").clicked() {
                for r in &mut self.results {
                    r.checked = false;
                }
            }
            if ui.add_enabled(any_clean, egui::Button::new("🧹 Clean checked")).clicked() {
                let files = self.checked_files();
                if !files.is_empty() {
                    self.status = format!("Cleaning {} file(s)…", files.len());
                    self.send(ToWorker::Clean(files));
                }
            }
            if ui.add_enabled(any_clean, egui::Button::new("🔁 Rescan checked")).clicked() {
                let files = self.checked_files();
                if !files.is_empty() {
                    self.status = format!("Rescanning {} file(s)…", files.len());
                    self.send(ToWorker::Rescan(files));
                }
            }
            if ui.add_enabled(any_checked, egui::Button::new("📋 Copy")).clicked() {
                let text = self.copy_text();
                ui.ctx().copy_text(text);
                self.status = "Copied selected rows.".into();
            }
            if ui.button("💾 Save report…").clicked() {
                self.save_report();
            }
        });
        ui.separator();

        use egui_extras::{Column, TableBuilder};
        let mut toggle: Option<usize> = None;
        TableBuilder::new(ui)
            .striped(true)
            .column(Column::auto().at_least(28.0))
            .column(Column::auto().at_least(120.0))
            .column(Column::auto().at_least(70.0))
            .column(Column::remainder().at_least(220.0))
            .column(Column::auto().at_least(150.0))
            .column(Column::auto().at_least(50.0))
            .header(22.0, |mut h| {
                h.col(|_ui| {});
                h.col(|ui| { ui.strong("Verdict"); });
                h.col(|ui| { ui.strong("Kind"); });
                h.col(|ui| { ui.strong("Object"); });
                h.col(|ui| { ui.strong("Threat"); });
                h.col(|ui| { ui.strong("ms"); });
            })
            .body(|mut body| {
                for (i, r) in self.results.iter().enumerate() {
                    body.row(20.0, |mut row| {
                        row.col(|ui| {
                            let mut c = r.checked;
                            if ui.checkbox(&mut c, "").changed() {
                                toggle = Some(i);
                            }
                        });
                        row.col(|ui| {
                            ui.colored_label(sev_color(r.sev), format!("{} ({})", r.verdict.label(), r.sev));
                        });
                        row.col(|ui| { ui.label(r.category); });
                        row.col(|ui| { ui.label(&r.path).on_hover_text(&r.detail); });
                        row.col(|ui| { ui.label(&r.threat); });
                        row.col(|ui| { ui.label(format!("{}", r.elapsed_ms)); });
                    });
                }
            });
        if let Some(i) = toggle {
            if let Some(r) = self.results.get_mut(i) {
                r.checked = !r.checked;
            }
        }
        if self.results.is_empty() && self.scan_state == ScanState::Done {
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
                if restore {
                    let _ = q.restore(&id);
                } else {
                    let _ = q.delete(&id);
                }
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
        ui.label(RichText::new("Engine").strong());
        ui.horizontal(|ui| {
            if ui.button("Apply & reload engines").clicked() {
                let cfg = self.settings.to_pipeline_config();
                self.engine_phase = EnginePhase::Loading;
                self.status = "Reloading engines…".into();
                self.send(ToWorker::Reload(cfg));
            }
            if ui.add_enabled(self.engine_phase == EnginePhase::Stopped, egui::Button::new("Start engine")).clicked() {
                self.send(ToWorker::StartEngine);
            }
            if ui.add_enabled(self.engine_phase == EnginePhase::Ready, egui::Button::new("Stop engine")).clicked() {
                self.send(ToWorker::StopEngine);
            }
            if ui.button("Clear result cache").clicked() {
                self.send(ToWorker::ClearCache);
            }
        });

        ui.add_space(12.0);
        ui.label(RichText::new("Explorer context menu").strong());
        ui.label(RichText::new("Adds “Scan with HydraDragonAV” for files and folders (HKCU).").color(MUTED));
        ui.horizontal(|ui| {
            if ui.button("Install context menu").clicked() {
                self.status = match install_context_menu() {
                    Ok(_) => "Context menu installed.".into(),
                    Err(e) => format!("Install failed: {e}"),
                };
            }
            if ui.button("Uninstall context menu").clicked() {
                self.status = match uninstall_context_menu() {
                    Ok(_) => "Context menu removed.".into(),
                    Err(e) => format!("Uninstall failed: {e}"),
                };
            }
        });
    }

    fn page_about(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading("HydraDragon Antivirus");
        ui.label("Safe egui GUI (hydradragonegui) — replaces the raw Win32 GUI.");
        ui.add_space(8.0);
        ui.label(RichText::new("Engines: ClamAV (pure-Rust), YARA-X, ML (PE/JS), static analysis.").color(MUTED));
        ui.label(RichText::new("Extra scan areas: registry, process memory, Sigma event logs, startup, boot sectors, PUM.").color(MUTED));
        ui.label(RichText::new("No unsafe Win32 FFI — pure, safe Rust UI.").color(MUTED));
    }

    /// Tab-separated text of checked rows (for the clipboard).
    fn copy_text(&self) -> String {
        let mut out = String::new();
        for r in self.results.iter().filter(|r| r.checked) {
            out.push_str(&format!("{}\t{}\t{}\n", r.path, r.verdict.label(), r.threat));
        }
        out
    }

    /// Write the results to a CSV or TXT report (with MD5 + VirusTotal link).
    fn save_report(&mut self) {
        let Some(path) = rfd::FileDialog::new()
            .add_filter("CSV", &["csv"])
            .add_filter("Text", &["txt"])
            .set_file_name("hydradragon_report.csv")
            .save_file()
        else {
            return;
        };
        let as_txt = path.extension().is_some_and(|e| e.eq_ignore_ascii_case("txt"));
        let out = if as_txt { self.report_txt() } else { self.report_csv() };
        match std::fs::write(&path, out) {
            Ok(_) => self.status = format!("Report saved → {}", path.display()),
            Err(e) => self.status = format!("Save failed: {e}"),
        }
    }

    fn report_csv(&self) -> String {
        let mut out = String::from("Object,Kind,Verdict,Threat,Severity,MD5,VirusTotal\n");
        for r in &self.results {
            let (md5, vt) = md5_and_vt(r);
            out.push_str(&format!(
                "{},{},{},{},{},{},{}\n",
                csv_escape(&r.path),
                r.category,
                r.verdict.label(),
                csv_escape(&r.threat),
                r.sev,
                md5,
                vt
            ));
        }
        out
    }

    fn report_txt(&self) -> String {
        let mut out = format!(
            "HydraDragon scan report\n{} detection(s), {} scanned\n\n",
            self.detections, self.scanned
        );
        for r in &self.results {
            let (md5, vt) = md5_and_vt(r);
            out.push_str(&format!("[{}] {}\n", sev_label(r.sev), r.path));
            out.push_str(&format!("    kind:    {}\n", r.category));
            out.push_str(&format!("    verdict: {} ({})\n", r.verdict.label(), r.sev));
            out.push_str(&format!("    threat:  {}\n", r.threat));
            if !r.detail.is_empty() {
                out.push_str(&format!("    detail:  {}\n", r.detail));
            }
            if !md5.is_empty() {
                out.push_str(&format!("    md5:     {md5}  ({vt})\n"));
            }
            out.push('\n');
        }
        out
    }
}

/// MD5 + VirusTotal link for a file row (empty for non-file detections).
fn md5_and_vt(r: &ResultRow) -> (String, String) {
    if !r.cleanable {
        return (String::new(), String::new());
    }
    match hydradragonav::hash_scanner::compute_md5(Path::new(&r.path)) {
        Ok(md5) => {
            let vt = format!("https://www.virustotal.com/gui/file/{md5}");
            (md5, vt)
        }
        Err(_) => (String::new(), String::new()),
    }
}

/// RFC-4180 CSV escaping.
fn csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// Directory the executable lives in (portable layout root).
fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
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

/// Expand a mix of files and directories into a flat file list.
fn expand_paths(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        if p.is_dir() {
            out.extend(collect_files(p));
        } else if p.is_file() {
            out.push(p.clone());
        }
    }
    out
}

// --------------------------------------------------------------------------- #
// Theme persistence (`<base>/hydradragon_theme`, "dark" / "light").
// --------------------------------------------------------------------------- #
fn theme_file(base: &str) -> PathBuf {
    PathBuf::from(base).join("hydradragon_theme")
}

fn load_dark(base: &str) -> bool {
    match std::fs::read_to_string(theme_file(base)) {
        Ok(s) => s.trim() != "light",
        Err(_) => true,
    }
}

fn save_dark(base: &str, dark: bool) {
    let _ = std::fs::write(theme_file(base), if dark { "dark" } else { "light" });
}

// --------------------------------------------------------------------------- #
// Explorer context menu (HKCU\Software\Classes) via `reg.exe` — no extra deps,
// no unsafe. Mirrors the Win32 GUI's install/uninstall.
// --------------------------------------------------------------------------- #
fn install_context_menu() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe = exe.display().to_string();
    let cmd = format!("\"{exe}\" \"%1\"");
    for root in ["*", "Directory"] {
        let key = format!("HKCU\\Software\\Classes\\{root}\\shell\\HydraDragonAV");
        reg_add(&key, "", "Scan with HydraDragonAV")?;
        reg_add(&key, "Icon", &format!("\"{exe}\",0"))?;
        reg_add(&format!("{key}\\command"), "", &cmd)?;
    }
    Ok(())
}

fn uninstall_context_menu() -> Result<(), String> {
    for root in ["*", "Directory"] {
        let key = format!("HKCU\\Software\\Classes\\{root}\\shell\\HydraDragonAV");
        // Ignore "key not found" errors so uninstall is idempotent.
        let _ = std::process::Command::new("reg").args(["delete", &key, "/f"]).output();
    }
    Ok(())
}

fn reg_add(key: &str, value: &str, data: &str) -> Result<(), String> {
    let mut args = vec!["add", key];
    if value.is_empty() {
        args.extend(["/ve"]);
    } else {
        args.extend(["/v", value]);
    }
    args.extend(["/t", "REG_SZ", "/d", data, "/f"]);
    let out = std::process::Command::new("reg")
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([980.0, 660.0])
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
