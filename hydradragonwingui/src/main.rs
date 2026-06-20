#![cfg(windows)]
#![windows_subsystem = "windows"]
// Every function here is `unsafe fn` wrapping raw Win32/GDI/COM calls; the whole
// body is the unsafe surface, so we don't double-wrap each call (edition-2024).
#![allow(unsafe_op_in_unsafe_fn)]

//! Native Win32 GUI for the HydraDragon portable antivirus — a fully
//! custom-painted (owner-drawn, double-buffered GDI) interface: branded header,
//! sidebar navigation with hover/active states, flat rounded accent buttons, a
//! themed results ListView with severity-colored rows, and the native shell
//! file/folder picker. All chrome is painted and hit-tested by hand; the only
//! real child controls are the two ListViews. Scanning / disinfection /
//! trace-removal run on a background worker driving the `hydradragonav` engine.

use std::collections::VecDeque;
use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hydradragonav::disinfector::{self, DisinfectOutcome};
use hydradragonav::memory_scanner;
use hydradragonav::pipeline::{scan_hayabusa_once, Pipeline, PipelineConfig};
use hydradragonav::quarantine::Quarantine;
use hydradragonav::registry_scanner::RegistryScanner;
use hydradragonav::remediation;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{COLORREF, HANDLE, HINSTANCE, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, OpenClipboard, SetClipboardData,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, LVCF_SUBITEM, LVCF_TEXT,
    LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVITEMW, NMHDR, NMLVCUSTOMDRAW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    ReleaseCapture, SetCapture, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FileOpenDialog, FileSaveDialog, IFileOpenDialog, IFileSaveDialog, IShellItem,
    FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::*;

// ---------------------------------------------------------------------------
// IDs, messages, geometry
// ---------------------------------------------------------------------------

const ID_SCAN_LIST: usize = 1001;
const ID_QUAR_LIST: usize = 1002;

// Painted-button command ids.
const CMD_SCAN_FILE: usize = 1;
const CMD_SCAN_FOLDER: usize = 2;
const CMD_CLEAN: usize = 3;
const CMD_TRACES: usize = 4;
const CMD_QUAR_REFRESH: usize = 5;
const CMD_QUAR_RESTORE: usize = 6;
const CMD_QUAR_DELETE: usize = 7;
const CMD_CLEAR_CACHE: usize = 8;
const CMD_FULL_SCAN: usize = 9;
const CMD_SAVE_RESULTS: usize = 10;
// Context-menu-only command (right-click a detection row → re-scan it fresh).
const CMD_RESCAN: usize = 11;
const CMD_STOP: usize = 12;
const CMD_RESUME: usize = 13;
// Context-menu: copy the selected detection rows to the clipboard.
const CMD_COPY: usize = 14;

const WM_APP_RESULT: u32 = WM_APP + 1;
// Not surfaced by the WindowsAndMessaging glob in this build — define it raw, or
// its match arm silently becomes a catch-all binding.
const WM_MOUSELEAVE: u32 = 0x02A3;
// Defined locally for the same reason; shadows the glob if present.
const WM_CONTEXTMENU: u32 = 0x007B;

const HEADER_H: i32 = 68;
const SIDEBAR_W: i32 = 210;
const STATUS_H: i32 = 30;
const PAD: i32 = 16;
const BTN_W: i32 = 150;
const BTN_H: i32 = 38;
const GAP: i32 = 10;
const NAV_H: i32 = 46;
const HERO_H: i32 = 104; // status banner height (Scan page)

mod msg {
    pub const LVM_FIRST: u32 = 0x1000;
    pub const LVM_SETBKCOLOR: u32 = LVM_FIRST + 1;
    pub const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;
    pub const LVM_DELETEITEM: u32 = LVM_FIRST + 8;
    pub const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
    pub const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
    pub const LVM_SETTEXTCOLOR: u32 = LVM_FIRST + 36;
    pub const LVM_SETTEXTBKCOLOR: u32 = LVM_FIRST + 38;
    pub const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
    pub const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
    pub const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
    pub const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
}
mod sty {
    pub const CHILD: u32 = 0x4000_0000;
    pub const VISIBLE: u32 = 0x1000_0000;
    pub const CLIPCHILDREN: u32 = 0x0200_0000;
    pub const OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
    pub const LVS_REPORT: u32 = 0x0001;
    pub const LVS_EX_FULLROWSELECT: u32 = 0x0000_0020;
    pub const LVS_EX_DOUBLEBUFFER: u32 = 0x0001_0000;
    pub const LVNI_SELECTED: isize = 0x0002;
}
// Custom-draw notification + stages (raw NM/CDDS/CDRF values).
const NM_CUSTOMDRAW: u32 = 0xFFFF_FFF4; // -12
const CDDS_PREPAINT: u32 = 0x0000_0001;
const CDDS_ITEMPREPAINT: u32 = 0x0001_0001;
const CDRF_DODEFAULT: isize = 0x0000_0000;
const CDRF_NEWFONT: isize = 0x0000_0002;
const CDRF_NOTIFYITEMDRAW: isize = 0x0000_0020;

// ---------------------------------------------------------------------------
// Palette (light, modern). COLORREF is 0x00BBGGRR.
// ---------------------------------------------------------------------------

const fn rgb(r: u8, g: u8, b: u8) -> COLORREF {
    COLORREF((r as u32) | ((g as u32) << 8) | ((b as u32) << 16))
}

/// Pure white — for text/icons drawn ON the accent/danger fills and the dark
/// gradient header (constant across themes).
const WHITE: COLORREF = rgb(0xFF, 0xFF, 0xFF);

/// A full color theme. Two instances exist: [`LIGHT`] and [`DARK`]; the active
/// one is chosen by `AppState.dark` via `AppState::theme()`.
struct Theme {
    bg: COLORREF,
    header_top: COLORREF,
    header_bot: COLORREF,
    header_sub: COLORREF,
    sidebar: COLORREF,
    surface: COLORREF, // cards / list background / status bar
    border: COLORREF,
    text: COLORREF,
    text2: COLORREF,
    accent: COLORREF,
    accent_hot: COLORREF,
    accent_down: COLORREF,
    accent_soft: COLORREF,
    nav_hot: COLORREF,
    danger: COLORREF,
    danger_hot: COLORREF,
    danger_down: COLORREF,
    danger_soft: COLORREF,
    warn: COLORREF,
    shadow: COLORREF,
    stripe: COLORREF,
    ok: COLORREF,
    ok_soft: COLORREF,
}

const LIGHT: Theme = Theme {
    bg: rgb(0xF4, 0xF5, 0xF8),
    header_top: rgb(0x27, 0x36, 0x57),
    header_bot: rgb(0x12, 0x19, 0x2A),
    header_sub: rgb(0x9F, 0xB0, 0xCC),
    sidebar: rgb(0xFF, 0xFF, 0xFF),
    surface: rgb(0xFF, 0xFF, 0xFF),
    border: rgb(0xE3, 0xE6, 0xEC),
    text: rgb(0x14, 0x1A, 0x24),
    text2: rgb(0x6B, 0x72, 0x80),
    accent: rgb(0x2D, 0x6C, 0xF6),
    accent_hot: rgb(0x4B, 0x82, 0xF8),
    accent_down: rgb(0x1F, 0x57, 0xD6),
    accent_soft: rgb(0xEC, 0xF2, 0xFE),
    nav_hot: rgb(0xF1, 0xF3, 0xF7),
    danger: rgb(0xD8, 0x2C, 0x2C),
    danger_hot: rgb(0xE5, 0x48, 0x48),
    danger_down: rgb(0xB7, 0x20, 0x20),
    danger_soft: rgb(0xFD, 0xEC, 0xEC),
    warn: rgb(0xC2, 0x7A, 0x06),
    shadow: rgb(0xDD, 0xE1, 0xE9),
    stripe: rgb(0xF7, 0xF8, 0xFB),
    ok: rgb(0x15, 0x9A, 0x52),
    ok_soft: rgb(0xE7, 0xF6, 0xEC),
};

const DARK: Theme = Theme {
    bg: rgb(0x15, 0x16, 0x1B),
    header_top: rgb(0x23, 0x26, 0x32),
    header_bot: rgb(0x0E, 0x0F, 0x14),
    header_sub: rgb(0x8B, 0x93, 0xA6),
    sidebar: rgb(0x1B, 0x1D, 0x24),
    surface: rgb(0x22, 0x25, 0x2D),
    border: rgb(0x32, 0x35, 0x3F),
    text: rgb(0xE7, 0xE9, 0xEE),
    text2: rgb(0x97, 0x9E, 0xAC),
    accent: rgb(0x4C, 0x8D, 0xFF),
    accent_hot: rgb(0x6A, 0xA1, 0xFF),
    accent_down: rgb(0x2D, 0x6C, 0xF6),
    accent_soft: rgb(0x1C, 0x29, 0x42),
    nav_hot: rgb(0x2A, 0x2E, 0x39),
    danger: rgb(0xF0, 0x52, 0x52),
    danger_hot: rgb(0xF8, 0x71, 0x71),
    danger_down: rgb(0xDC, 0x26, 0x26),
    danger_soft: rgb(0x3A, 0x20, 0x24),
    warn: rgb(0xE0, 0xA1, 0x06),
    shadow: rgb(0x0A, 0x0B, 0x0E),
    stripe: rgb(0x1E, 0x21, 0x29),
    ok: rgb(0x34, 0xC7, 0x59),
    ok_soft: rgb(0x16, 0x30, 0x1F),
};

#[derive(Clone, Copy, PartialEq)]
enum Kind {
    Primary,
    Neutral,
    Danger,
}

struct UiButton {
    cmd: usize,
    label: &'static str,
    kind: Kind,
    rect: RECT,
}

struct NavItem {
    page: usize,
    label: &'static str,
    icon: &'static str, // Segoe MDL2 Assets glyph
    rect: RECT,
}

#[derive(Clone, Copy, PartialEq)]
enum ScanState {
    Idle,
    Scanning,
    Paused,
    Clean,
    Threats,
}

enum ScanMsg {
    Row {
        file: String,
        verdict: String,
        threat: String,
        sev: u8,
    },
    Status(String),
    Begin,
    /// Live progress. `discovered` grows while the tree is still being walked
    /// (`discovering` = true); `speed` is files/sec and `eta_secs` is the estimate
    /// for the currently-discovered backlog.
    Progress {
        scanned: usize,
        threats: usize,
        discovered: usize,
        speed: f64,
        eta_secs: f64,
        discovering: bool,
    },
    Done { scanned: usize, threats: usize },
    /// Scan was stopped mid-run; `remaining` files are queued for Resume.
    Paused { scanned: usize, threats: usize, remaining: usize },
    /// A paused scan has been picked back up.
    Resumed,
    /// Result of re-scanning one already-listed file (right-click → Rescan). The
    /// row is updated in place, or removed when it comes back clean.
    Rescanned {
        file: String,
        verdict: String,
        threat: String,
        sev: u8,
        threat_found: bool,
    },
}

enum WorkRequest {
    Scan(Vec<PathBuf>),
    /// Full mode: in-memory file scan of the path + registry + Windows event logs.
    FullScan(Vec<PathBuf>),
    /// Force a fresh (uncached) re-scan of specific files already in the list.
    Rescan(Vec<PathBuf>),
    /// Continue a scan that was stopped (the worker keeps the remaining file list).
    Resume,
    Clean(Vec<PathBuf>),
    RemoveTraces(Vec<PathBuf>),
    ClearCache,
}

struct Fonts {
    logo: HFONT,
    title: HFONT,
    sub: HFONT,
    nav: HFONT,
    button: HFONT,
    body: HFONT,
    status: HFONT,
    icon: HFONT,       // Segoe MDL2 Assets, nav glyph size
    icon_lg: HFONT,    // larger, header logo glyph
    hero: HFONT,       // hero headline
    hero_icon: HFONT,  // big MDL2 badge glyph
}

struct AppState {
    scan_list: HWND,
    quar_list: HWND,
    fonts: Fonts,
    page: usize, // 0 = Scan, 1 = Quarantine
    nav: Vec<NavItem>,
    buttons: Vec<UiButton>,
    hot_cmd: Option<usize>,
    down_cmd: Option<usize>,
    hot_nav: Option<usize>,
    hot_theme: bool,
    theme_btn: RECT,
    dark: bool,
    tracking: bool,
    status: String,
    scan_state: ScanState,
    scanned_count: usize,
    threat_count: usize,
    // Live throughput for the hero banner / status bar (streaming scan).
    scan_discovered: usize,
    scan_speed: f64,
    scan_eta_secs: f64,
    scan_discovering: bool,
    work_tx: Sender<WorkRequest>,
    result_rx: Receiver<ScanMsg>,
    /// Set from the UI thread (Stop) and polled by the worker's scan loop to
    /// abort between files. Shared with the worker thread.
    cancel: Arc<AtomicBool>,
    scan_rows: Vec<PathBuf>,
    scan_sev: Vec<u8>,
    // Parallel to scan_rows: the verdict/threat text shown per detection, kept so
    // the result list can be exported (Save Results) without reading it back
    // out of the ListView.
    scan_verdict: Vec<String>,
    scan_threat: Vec<String>,
    quar_ids: Vec<String>,
    quarantine_dir: PathBuf,
}

impl AppState {
    fn theme(&self) -> &'static Theme {
        if self.dark { &DARK } else { &LIGHT }
    }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn main() {
    unsafe {
        let _ = SetProcessDPIAware();
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);

        let hinst = GetModuleHandleW(None).expect("module");
        let class = w!("HydraDragonWinGuiClass");
        // Icon embedded by build.rs under resource id 1.
        let hicon = LoadIconW(Some(HINSTANCE::from(hinst)), PCWSTR(1 as *const u16)).unwrap_or_default();
        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wndproc),
            hInstance: hinst.into(),
            hIcon: hicon,
            hIconSm: hicon,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: HBRUSH(std::ptr::null_mut()),
            lpszClassName: class,
            ..Default::default()
        };
        if RegisterClassExW(&wc) == 0 {
            return;
        }

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            w!("HydraDragon Antivirus"),
            WINDOW_STYLE(sty::OVERLAPPEDWINDOW | sty::CLIPCHILDREN),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            900,
            600,
            None,
            None,
            Some(HINSTANCE::from(hinst).into()),
            None,
        )
        .expect("window");

        let _ = ShowWindow(hwnd, SW_SHOW);

        let mut m = MSG::default();
        while GetMessageW(&mut m, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&m);
            DispatchMessageW(&m);
        }
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                on_create(hwnd);
                LRESULT(0)
            }
            WM_ERASEBKGND => LRESULT(1),
            WM_SIZE => {
                layout(hwnd);
                let _ = InvalidateRect(Some(hwnd), None, false);
                LRESULT(0)
            }
            WM_GETMINMAXINFO => {
                let mmi = &mut *(lp.0 as *mut MINMAXINFO);
                mmi.ptMinTrackSize.x = 720;
                mmi.ptMinTrackSize.y = 480;
                LRESULT(0)
            }
            WM_PAINT => {
                paint(hwnd);
                LRESULT(0)
            }
            WM_MOUSEMOVE => {
                on_mouse_move(hwnd, lparam_xy(lp));
                LRESULT(0)
            }
            WM_MOUSELEAVE => {
                if let Some(s) = state(hwnd) {
                    s.tracking = false;
                    if s.hot_cmd.take().is_some() || s.hot_nav.take().is_some() {
                        let _ = InvalidateRect(Some(hwnd), None, false);
                    }
                }
                LRESULT(0)
            }
            WM_LBUTTONDOWN => {
                on_lbutton_down(hwnd, lparam_xy(lp));
                LRESULT(0)
            }
            WM_LBUTTONUP => {
                on_lbutton_up(hwnd, lparam_xy(lp));
                LRESULT(0)
            }
            x if x == WM_CONTEXTMENU => {
                // wParam = the control that was right-clicked; lParam = screen x/y
                // (both -1 when invoked from the keyboard).
                let src = HWND(wp.0 as *mut c_void);
                on_context_menu(hwnd, src, lparam_xy(lp));
                LRESULT(0)
            }
            WM_NOTIFY => {
                let nm = &*(lp.0 as *const NMHDR);
                if nm.code == NM_CUSTOMDRAW && nm.idFrom == ID_SCAN_LIST {
                    return LRESULT(on_list_customdraw(hwnd, lp.0 as *mut NMLVCUSTOMDRAW));
                }
                LRESULT(0)
            }
            x if x == WM_APP_RESULT => {
                drain_results(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
                if !ptr.is_null() {
                    let s = Box::from_raw(ptr);
                    delete_fonts(&s.fonts);
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wp, lp),
        }
    }
}

unsafe fn state(hwnd: HWND) -> Option<&'static mut AppState> {
    (GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState).as_mut()
}

fn lparam_xy(lp: LPARAM) -> (i32, i32) {
    ((lp.0 & 0xFFFF) as i16 as i32, ((lp.0 >> 16) & 0xFFFF) as i16 as i32)
}

fn pt_in(r: &RECT, x: i32, y: i32) -> bool {
    x >= r.left && x < r.right && y >= r.top && y < r.bottom
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

unsafe fn on_create(hwnd: HWND) {
    let hinst: HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();
    let fonts = Fonts {
        logo: make_font(-20, 700),
        title: make_font(-22, 600),
        sub: make_font(-13, 400),
        nav: make_font(-16, 600),
        button: make_font(-15, 600),
        body: make_font(-16, 400),
        status: make_font(-13, 400),
        icon: make_font_face(-17, 400, "Segoe MDL2 Assets"),
        icon_lg: make_font_face(-22, 400, "Segoe MDL2 Assets"),
        hero: make_font(-26, 600),
        hero_icon: make_font_face(-30, 400, "Segoe MDL2 Assets"),
    };

    let lv = sty::CHILD | sty::VISIBLE | sty::LVS_REPORT;
    let scan_list = make_list(hwnd, hinst, lv, ID_SCAN_LIST, fonts.body);
    lv_col(scan_list, 0, "File", 470);
    lv_col(scan_list, 1, "Verdict", 120);
    lv_col(scan_list, 2, "Threat", 240);

    let quar_list = make_list(hwnd, hinst, lv, ID_QUAR_LIST, fonts.body);
    lv_col(quar_list, 0, "ID", 250);
    lv_col(quar_list, 1, "Original path", 360);
    lv_col(quar_list, 2, "Detection", 140);
    lv_col(quar_list, 3, "Size", 90);

    // Restore the remembered theme.
    let dark = load_dark();
    if dark {
        apply_list_theme(scan_list, &DARK);
        apply_list_theme(quar_list, &DARK);
    }

    let (work_tx, work_rx) = channel::<WorkRequest>();
    let (result_tx, result_rx) = channel::<ScanMsg>();
    let quarantine_dir = exe_dir().join("quarantine");
    let qdir = quarantine_dir.clone();
    let raw = hwnd.0 as isize;
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    std::thread::spawn(move || worker(raw, work_rx, result_tx, qdir, worker_cancel));

    let s = Box::new(AppState {
        scan_list,
        quar_list,
        fonts,
        page: 0,
        nav: vec![
            NavItem { page: 0, label: "Scan", icon: "\u{E721}", rect: RECT::default() },
            NavItem { page: 1, label: "Quarantine", icon: "\u{E72E}", rect: RECT::default() },
            NavItem { page: 2, label: "Settings", icon: "\u{E713}", rect: RECT::default() },
        ],
        buttons: Vec::new(),
        hot_cmd: None,
        down_cmd: None,
        hot_nav: None,
        hot_theme: false,
        theme_btn: RECT::default(),
        dark,
        tracking: false,
        status: "Ready.".into(),
        scan_state: ScanState::Idle,
        scanned_count: 0,
        threat_count: 0,
        scan_discovered: 0,
        scan_speed: 0.0,
        scan_eta_secs: 0.0,
        scan_discovering: false,
        work_tx,
        result_rx,
        cancel,
        scan_rows: Vec::new(),
        scan_sev: Vec::new(),
        scan_verdict: Vec::new(),
        scan_threat: Vec::new(),
        quar_ids: Vec::new(),
        quarantine_dir,
    });
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(s) as isize);
    layout(hwnd);
    apply_page(hwnd);
}

unsafe fn make_font(height: i32, weight: i32) -> HFONT {
    make_font_face(height, weight, "Segoe UI")
}

unsafe fn make_font_face(height: i32, weight: i32, face: &str) -> HFONT {
    let mut lf = LOGFONTW {
        lfHeight: height,
        lfWeight: weight,
        lfQuality: CLEARTYPE_QUALITY,
        ..Default::default()
    };
    for (i, c) in face.encode_utf16().enumerate().take(31) {
        lf.lfFaceName[i] = c;
    }
    CreateFontIndirectW(&lf)
}

unsafe fn delete_fonts(f: &Fonts) {
    for h in [
        f.logo, f.title, f.sub, f.nav, f.button, f.body, f.status, f.icon, f.icon_lg,
        f.hero, f.hero_icon,
    ] {
        let _ = DeleteObject(h.into());
    }
}

unsafe fn make_list(parent: HWND, hinst: HINSTANCE, style: u32, id: usize, font: HFONT) -> HWND {
    let h = CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        w!("SysListView32"),
        w!(""),
        WINDOW_STYLE(style),
        0,
        0,
        0,
        0,
        Some(parent),
        Some(HMENU(id as *mut c_void)),
        Some(hinst.into()),
        None,
    )
    .unwrap_or_default();
    SendMessageW(
        h,
        msg::LVM_SETEXTENDEDLISTVIEWSTYLE,
        Some(WPARAM(0)),
        Some(LPARAM((sty::LVS_EX_FULLROWSELECT | sty::LVS_EX_DOUBLEBUFFER) as isize)),
    );
    apply_list_theme(h, &LIGHT);
    SendMessageW(h, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
    h
}

/// Re-applies the theme's surface/text colors to a ListView (called on toggle).
unsafe fn apply_list_theme(h: HWND, t: &Theme) {
    SendMessageW(h, msg::LVM_SETBKCOLOR, Some(WPARAM(0)), Some(LPARAM(t.surface.0 as isize)));
    SendMessageW(h, msg::LVM_SETTEXTBKCOLOR, Some(WPARAM(0)), Some(LPARAM(t.surface.0 as isize)));
    SendMessageW(h, msg::LVM_SETTEXTCOLOR, Some(WPARAM(0)), Some(LPARAM(t.text.0 as isize)));
}

fn buttons_for(page: usize, state: ScanState) -> Vec<(usize, &'static str, Kind)> {
    match page {
        // Scan page buttons depend on the scan state: a single Stop while a scan
        // runs, Resume (+ the normal actions) once it's paused.
        0 => match state {
            ScanState::Scanning => vec![(CMD_STOP, "Stop", Kind::Danger)],
            ScanState::Paused => vec![
                (CMD_RESUME, "Resume", Kind::Primary),
                (CMD_SCAN_FILE, "Scan File", Kind::Primary),
                (CMD_SCAN_FOLDER, "Scan Folder", Kind::Primary),
                (CMD_CLEAN, "Clean Selected", Kind::Primary),
                (CMD_SAVE_RESULTS, "Save Results", Kind::Neutral),
                (CMD_TRACES, "Remove Traces", Kind::Danger),
            ],
            _ => vec![
                (CMD_SCAN_FILE, "Scan File", Kind::Primary),
                (CMD_SCAN_FOLDER, "Scan Folder", Kind::Primary),
                (CMD_FULL_SCAN, "Full Scan", Kind::Primary),
                (CMD_CLEAN, "Clean Selected", Kind::Primary),
                (CMD_SAVE_RESULTS, "Save Results", Kind::Neutral),
                (CMD_TRACES, "Remove Traces", Kind::Danger),
            ],
        },
        1 => vec![
            (CMD_QUAR_REFRESH, "Refresh", Kind::Neutral),
            (CMD_QUAR_RESTORE, "Restore Selected", Kind::Primary),
            (CMD_QUAR_DELETE, "Delete Selected", Kind::Danger),
        ],
        _ => vec![(CMD_CLEAR_CACHE, "Clear Result Cache", Kind::Danger)],
    }
}

// ---------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------

unsafe fn layout(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let mut rc = RECT::default();
    if GetClientRect(hwnd, &mut rc).is_err() {
        return;
    }
    let w = rc.right;
    let h = rc.bottom;

    // Sidebar nav items.
    for (i, item) in s.nav.iter_mut().enumerate() {
        let top = HEADER_H + 14 + i as i32 * (NAV_H + 6);
        item.rect = RECT { left: 10, top, right: SIDEBAR_W - 10, bottom: top + NAV_H };
    }

    // Theme toggle in the header (top-right).
    let tb = 36;
    let ty = (HEADER_H - tb) / 2;
    s.theme_btn = RECT { left: w - PAD - tb, top: ty, right: w - PAD, bottom: ty + tb };

    // Content buttons (wrap into rows if narrow).
    let content_l = SIDEBAR_W + PAD;
    let content_r = w - PAD;
    let defs = buttons_for(s.page, s.scan_state);
    s.buttons.clear();
    let mut x = content_l;
    // Scan page reserves a status hero banner above the action buttons.
    let mut y = HEADER_H + PAD + if s.page == 0 { HERO_H + PAD } else { 0 };
    for (cmd, label, kind) in defs {
        if x + BTN_W > content_r && x > content_l {
            x = content_l;
            y += BTN_H + GAP;
        }
        s.buttons.push(UiButton {
            cmd,
            label,
            kind,
            rect: RECT { left: x, top: y, right: x + BTN_W, bottom: y + BTN_H },
        });
        x += BTN_W + GAP;
    }
    let list_top = y + BTN_H + PAD;

    let lr = RECT { left: content_l, top: list_top, right: content_r, bottom: h - STATUS_H - PAD };
    let list_w = (lr.right - lr.left).max(80);
    let list_h = (lr.bottom - lr.top).max(60);
    for hl in [s.scan_list, s.quar_list] {
        let _ = MoveWindow(hl, lr.left, lr.top, list_w, list_h, true);
    }
}

/// Show the active page's ListView, hide the others, refresh quarantine on enter.
unsafe fn apply_page(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let _ = ShowWindow(s.scan_list, if s.page == 0 { SW_SHOW } else { SW_HIDE });
    let _ = ShowWindow(s.quar_list, if s.page == 1 { SW_SHOW } else { SW_HIDE });
    layout(hwnd);
    if s.page == 1 {
        refresh_quarantine(s);
    }
    let _ = InvalidateRect(Some(hwnd), None, false);
}

// ---------------------------------------------------------------------------
// Painting
// ---------------------------------------------------------------------------

unsafe fn paint(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let t = s.theme();
    let mut ps = PAINTSTRUCT::default();
    let hdc = BeginPaint(hwnd, &mut ps);
    let mut rc = RECT::default();
    let _ = GetClientRect(hwnd, &mut rc);
    let w = rc.right.max(1);
    let h = rc.bottom.max(1);

    // Double buffer.
    let mem = CreateCompatibleDC(Some(hdc));
    let bmp = CreateCompatibleBitmap(hdc, w, h);
    let old = SelectObject(mem, bmp.into());

    fill(mem, &rc, t.bg);

    // --- Sidebar ---
    let side = RECT { left: 0, top: 0, right: SIDEBAR_W, bottom: h };
    fill(mem, &side, t.sidebar);
    fill(mem, &RECT { left: SIDEBAR_W - 1, top: 0, right: SIDEBAR_W, bottom: h }, t.border);
    for (i, item) in s.nav.iter().enumerate() {
        let active = s.page == item.page;
        let hot = s.hot_nav == Some(i);
        if active {
            fill_round(mem, item.rect, 10, t.accent); // full accent pill
        } else if hot {
            fill_round(mem, item.rect, 10, t.nav_hot);
        }
        let icon_col = if active { WHITE } else { t.accent };
        let txt_col = if active { WHITE } else { t.text };
        let icon_r = RECT { left: item.rect.left + 14, right: item.rect.left + 42, ..item.rect };
        text(mem, item.icon, &icon_r, icon_col, s.fonts.icon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        let tr = RECT { left: item.rect.left + 46, ..item.rect };
        text(mem, item.label, &tr, txt_col, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }

    // --- Header (vertical gradient + thin drop shadow) ---
    let head = RECT { left: 0, top: 0, right: w, bottom: HEADER_H };
    gradient_v(mem, &head, t.header_top, t.header_bot);
    fill(mem, &RECT { left: 0, top: HEADER_H, right: w, bottom: HEADER_H + 1 }, t.shadow);
    let logo = RECT { left: PAD, top: (HEADER_H - 40) / 2, right: PAD + 40, bottom: (HEADER_H - 40) / 2 + 40 };
    fill_round(mem, logo, 11, t.accent);
    text(mem, "\u{E83D}", &logo, WHITE, s.fonts.icon_lg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    let tx = logo.right + 14;
    text(
        mem,
        "HydraDragon Antivirus",
        &RECT { left: tx, top: 12, right: w - PAD, bottom: 38 },
        WHITE,
        s.fonts.title,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    text(
        mem,
        "Portable malware scanner",
        &RECT { left: tx, top: 38, right: w - PAD, bottom: 58 },
        t.header_sub,
        s.fonts.sub,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    // Theme toggle (sun when dark → switch to light; moon when light → dark).
    if s.hot_theme {
        fill_round(mem, s.theme_btn, 9, t.accent);
    }
    let toggle_glyph = if s.dark { "\u{E706}" } else { "\u{E708}" };
    text(mem, toggle_glyph, &s.theme_btn, WHITE, s.fonts.icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // --- Hero status banner (Scan page) ---
    if s.page == 0 {
        let content_l = SIDEBAR_W + PAD;
        let hero = RECT { left: content_l, top: HEADER_H + PAD, right: w - PAD, bottom: HEADER_H + PAD + HERO_H };
        draw_hero(mem, s, hero);
    }

    // --- Buttons ---
    for b in &s.buttons {
        let hot = s.hot_cmd == Some(b.cmd);
        let down = s.down_cmd == Some(b.cmd);
        draw_button(mem, b, hot, down, &s.fonts, t);
    }

    // --- Content card (flat border around the active ListView / settings text) ---
    let content_l = SIDEBAR_W + PAD;
    let list_top = s.buttons.iter().map(|b| b.rect.bottom).max().unwrap_or(HEADER_H + PAD) + PAD;
    let card = RECT { left: content_l - 1, top: list_top - 1, right: w - PAD + 1, bottom: h - STATUS_H - PAD + 1 };
    if s.page == 2 {
        // Settings page has no list — fill the card and explain the cache.
        fill_round(mem, card, 8, t.surface);
        let pad = 18;
        let inner = RECT { left: card.left + pad, top: card.top + pad, right: card.right - pad, bottom: card.bottom - pad };
        text(mem, "Result cache", &RECT { bottom: inner.top + 26, ..inner }, t.text, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        let body = RECT { top: inner.top + 34, ..inner };
        text(
            mem,
            "The scanner remembers the MD5 of every file it has already classified \
             (good_results.bloom and bad_results.bloom), so identical files are not \
             re-scanned — this makes repeat and bulk scans much faster, at almost no \
             memory cost.\r\n\r\n\
             “Clear Result Cache” wipes both blooms on disk and in memory. The scanner \
             will then re-scan everything from scratch and forget every learned good and \
             bad result. This is not recommended — only clear it if you suspect the cache \
             is stale or corrupted.",
            &body,
            t.text2,
            s.fonts.body,
            DT_LEFT | DT_WORDBREAK,
        );
    }
    frame_round(mem, card, 8, t.border);

    // --- Status bar ---
    let status = RECT { left: 0, top: h - STATUS_H, right: w, bottom: h };
    fill(mem, &status, t.surface);
    fill(mem, &RECT { left: 0, top: h - STATUS_H, right: w, bottom: h - STATUS_H + 1 }, t.shadow);
    text(
        mem,
        &s.status,
        &RECT { left: PAD, top: h - STATUS_H, right: w - PAD, bottom: h },
        t.text2,
        s.fonts.status,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    let _ = BitBlt(hdc, 0, 0, w, h, Some(mem), 0, 0, SRCCOPY);
    SelectObject(mem, old);
    let _ = DeleteObject(bmp.into());
    let _ = DeleteDC(mem);
    let _ = EndPaint(hwnd, &ps);
}

/// Kaspersky-style status hero: a colored banner with a big badge + headline.
unsafe fn draw_hero(hdc: HDC, s: &AppState, r: RECT) {
    let t = s.theme();
    let (bg, accent, glyph, head, sub) = match s.scan_state {
        ScanState::Idle => (
            t.accent_soft,
            t.accent,
            "\u{E83D}", // shield
            "Ready to scan".to_string(),
            "Run a scan to check your system for threats.".to_string(),
        ),
        ScanState::Scanning => (
            t.accent_soft,
            t.accent,
            "\u{E721}", // search
            "Scanning…".to_string(),
            {
                let eta = if s.scan_discovering {
                    "estimating…".to_string()
                } else {
                    format!("ETA {}", fmt_eta(s.scan_eta_secs))
                };
                format!(
                    "{}/{} scanned · {:.0} files/s · {} · {} threat(s)",
                    s.scanned_count, s.scan_discovered, s.scan_speed, eta, s.threat_count
                )
            },
        ),
        ScanState::Paused => (
            t.accent_soft,
            t.warn,
            "\u{E769}", // pause
            "Scan paused".to_string(),
            format!("{} scanned · {} threat(s) — Resume to continue.", s.scanned_count, s.threat_count),
        ),
        ScanState::Clean => (
            t.ok_soft,
            t.ok,
            "\u{E73E}", // checkmark
            "No threats found".to_string(),
            format!("{} files scanned — your system looks clean.", s.scanned_count),
        ),
        ScanState::Threats => (
            t.danger_soft,
            t.danger,
            "\u{E7BA}", // warning
            format!("{} threat(s) found", s.threat_count),
            "Review the detections below, then Clean Selected.".to_string(),
        ),
    };

    fill_round(hdc, r, 12, bg);
    frame_round(hdc, r, 12, t.border);

    let bsize = 64;
    let bx = r.left + 22;
    let by = r.top + (r.bottom - r.top - bsize) / 2;
    let badge = RECT { left: bx, top: by, right: bx + bsize, bottom: by + bsize };
    fill_round(hdc, badge, bsize / 2, accent); // filled circle
    text(hdc, glyph, &badge, WHITE, s.fonts.hero_icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    let tx = badge.right + 22;
    text(
        hdc,
        &head,
        &RECT { left: tx, top: r.top + 24, right: r.right - 20, bottom: r.top + 58 },
        t.text,
        s.fonts.hero,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );
    text(
        hdc,
        &sub,
        &RECT { left: tx, top: r.top + 60, right: r.right - 20, bottom: r.bottom - 22 },
        t.text2,
        s.fonts.body,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );
}

unsafe fn draw_button(hdc: HDC, b: &UiButton, hot: bool, down: bool, fonts: &Fonts, t: &Theme) {
    let (fillc, textc) = match b.kind {
        Kind::Primary => (
            if down { t.accent_down } else if hot { t.accent_hot } else { t.accent },
            WHITE,
        ),
        Kind::Danger => (
            if down { t.danger_down } else if hot { t.danger_hot } else { t.danger },
            WHITE,
        ),
        Kind::Neutral => (if down { t.nav_hot } else if hot { t.bg } else { t.surface }, t.text),
    };
    fill_round(hdc, b.rect, 9, fillc);
    if b.kind == Kind::Neutral {
        frame_round(hdc, b.rect, 9, t.border);
    }
    text(hdc, b.label, &b.rect, textc, fonts.button, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
}

// GDI helpers --------------------------------------------------------------

unsafe fn fill(hdc: HDC, r: &RECT, color: COLORREF) {
    let br = CreateSolidBrush(color);
    FillRect(hdc, r, br);
    let _ = DeleteObject(br.into());
}

/// Vertical (top→bottom) gradient fill — one GDI call, cheap.
unsafe fn gradient_v(hdc: HDC, r: &RECT, top: COLORREF, bottom: COLORREF) {
    let chan = |c: COLORREF| {
        (
            ((c.0 & 0xFF) as u16) << 8,
            (((c.0 >> 8) & 0xFF) as u16) << 8,
            (((c.0 >> 16) & 0xFF) as u16) << 8,
        )
    };
    let (tr, tg, tb) = chan(top);
    let (br, bg, bb) = chan(bottom);
    let verts = [
        TRIVERTEX { x: r.left, y: r.top, Red: tr, Green: tg, Blue: tb, Alpha: 0 },
        TRIVERTEX { x: r.right, y: r.bottom, Red: br, Green: bg, Blue: bb, Alpha: 0 },
    ];
    let mesh = GRADIENT_RECT { UpperLeft: 0, LowerRight: 1 };
    let _ = GradientFill(hdc, &verts, &mesh as *const _ as *const c_void, 1, GRADIENT_FILL_RECT_V);
}

unsafe fn fill_round(hdc: HDC, r: RECT, radius: i32, color: COLORREF) {
    let rgn = CreateRoundRectRgn(r.left, r.top, r.right, r.bottom, radius * 2, radius * 2);
    let br = CreateSolidBrush(color);
    let _ = FillRgn(hdc, rgn, br);
    let _ = DeleteObject(br.into());
    let _ = DeleteObject(rgn.into());
}

unsafe fn frame_round(hdc: HDC, r: RECT, radius: i32, color: COLORREF) {
    let rgn = CreateRoundRectRgn(r.left, r.top, r.right, r.bottom, radius * 2, radius * 2);
    let br = CreateSolidBrush(color);
    let _ = FrameRgn(hdc, rgn, br, 1, 1);
    let _ = DeleteObject(br.into());
    let _ = DeleteObject(rgn.into());
}

unsafe fn text(hdc: HDC, s: &str, r: &RECT, color: COLORREF, font: HFONT, flags: DRAW_TEXT_FORMAT) {
    if s.is_empty() {
        return;
    }
    let old = SelectObject(hdc, font.into());
    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, color);
    let mut chars: Vec<u16> = s.encode_utf16().collect();
    let mut rr = *r;
    DrawTextW(hdc, &mut chars, &mut rr, flags);
    SelectObject(hdc, old);
}

// ---------------------------------------------------------------------------
// Mouse interaction
// ---------------------------------------------------------------------------

unsafe fn on_mouse_move(hwnd: HWND, (x, y): (i32, i32)) {
    let Some(s) = state(hwnd) else { return };
    if !s.tracking {
        let mut tme = TRACKMOUSEEVENT {
            cbSize: std::mem::size_of::<TRACKMOUSEEVENT>() as u32,
            dwFlags: TME_LEAVE,
            hwndTrack: hwnd,
            dwHoverTime: 0,
        };
        let _ = TrackMouseEvent(&mut tme);
        s.tracking = true;
    }
    let hot_cmd = s.buttons.iter().find(|b| pt_in(&b.rect, x, y)).map(|b| b.cmd);
    let hot_nav = s.nav.iter().position(|n| pt_in(&n.rect, x, y));
    let hot_theme = pt_in(&s.theme_btn, x, y);
    if hot_cmd != s.hot_cmd || hot_nav != s.hot_nav || hot_theme != s.hot_theme {
        s.hot_cmd = hot_cmd;
        s.hot_nav = hot_nav;
        s.hot_theme = hot_theme;
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

unsafe fn on_lbutton_down(hwnd: HWND, (x, y): (i32, i32)) {
    let Some(s) = state(hwnd) else { return };
    // Theme toggle (header).
    if pt_in(&s.theme_btn, x, y) {
        s.dark = !s.dark;
        save_dark(s.dark); // remember across launches
        let t = s.theme();
        apply_list_theme(s.scan_list, t);
        apply_list_theme(s.quar_list, t);
        let _ = InvalidateRect(Some(hwnd), None, false);
        return;
    }
    // Nav switches immediately.
    if let Some(i) = s.nav.iter().position(|n| pt_in(&n.rect, x, y)) {
        let page = s.nav[i].page;
        if page != s.page {
            s.page = page;
            apply_page(hwnd);
        }
        return;
    }
    if let Some(b) = s.buttons.iter().find(|b| pt_in(&b.rect, x, y)) {
        s.down_cmd = Some(b.cmd);
        SetCapture(hwnd);
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

unsafe fn on_lbutton_up(hwnd: HWND, (x, y): (i32, i32)) {
    let Some(s) = state(hwnd) else { return };
    let Some(cmd) = s.down_cmd.take() else { return };
    let _ = ReleaseCapture();
    let _ = InvalidateRect(Some(hwnd), None, false);
    let hit = s.buttons.iter().any(|b| b.cmd == cmd && pt_in(&b.rect, x, y));
    if hit {
        dispatch(hwnd, cmd);
    }
}

unsafe fn dispatch(hwnd: HWND, cmd: usize) {
    let Some(s) = state(hwnd) else { return };
    match cmd {
        CMD_SCAN_FILE => pick_and_scan(s, false),
        CMD_SCAN_FOLDER => pick_and_scan(s, true),
        CMD_FULL_SCAN => pick_and_full_scan(s),
        CMD_CLEAN => act_on_selected(hwnd, s, true),
        CMD_SAVE_RESULTS => save_results(hwnd, s),
        CMD_RESCAN => rescan_selected(hwnd, s),
        CMD_COPY => copy_selected(hwnd, s),
        CMD_STOP => {
            // Signal the worker's scan loop to stop after the in-flight files.
            s.cancel.store(true, Ordering::Relaxed);
            set_status(hwnd, s, "Stopping…");
        }
        CMD_RESUME => {
            let _ = s.work_tx.send(WorkRequest::Resume);
        }
        CMD_TRACES => act_on_selected(hwnd, s, false),
        CMD_QUAR_REFRESH => {
            refresh_quarantine(s);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }
        CMD_QUAR_RESTORE => {
            quarantine_action(s, true);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }
        CMD_QUAR_DELETE => {
            quarantine_action(s, false);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }
        CMD_CLEAR_CACHE => {
            if confirm(
                hwnd,
                "Clear the result cache (good_results.bloom + bad_results.bloom)?\n\n\
                 This is NOT recommended: the scanner will re-scan everything from \
                 scratch and forget every learned good/bad result.",
            ) {
                let _ = s.work_tx.send(WorkRequest::ClearCache);
            }
        }
        _ => {}
    }
}

/// Right-click on the results list → popup menu. Acts on the current selection,
/// so the user left-clicks the row(s) first, then right-clicks them.
unsafe fn on_context_menu(hwnd: HWND, src: HWND, (mut x, mut y): (i32, i32)) {
    let Some(s) = state(hwnd) else { return };
    // Only the Scan page's results list has a context menu.
    if src != s.scan_list || s.page != 0 {
        return;
    }
    if lv_selected(s.scan_list).is_empty() {
        return;
    }
    // Keyboard-invoked (Shift+F10 / menu key) gives (-1,-1): use the cursor.
    if x == -1 && y == -1 {
        let mut p = POINT::default();
        let _ = GetCursorPos(&mut p);
        x = p.x;
        y = p.y;
    }

    let menu = CreatePopupMenu().unwrap_or_default();
    if menu.is_invalid() {
        return;
    }
    let _ = AppendMenuW(menu, MF_STRING, CMD_RESCAN, w!("Rescan Selected"));
    let _ = AppendMenuW(menu, MF_STRING, CMD_COPY, w!("Copy"));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, CMD_CLEAN, w!("Clean Selected"));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, CMD_SAVE_RESULTS, w!("Save Results\u{2026}"));

    // TPM_RETURNCMD makes TrackPopupMenu return the chosen id instead of posting it.
    let chosen = TrackPopupMenu(
        menu,
        TPM_RETURNCMD | TPM_LEFTALIGN | TPM_TOPALIGN | TPM_RIGHTBUTTON,
        x,
        y,
        Some(0),
        hwnd,
        None,
    );
    let _ = DestroyMenu(menu);
    let cmd = chosen.0 as usize;
    if cmd != 0 {
        dispatch(hwnd, cmd);
    }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

unsafe fn set_status(hwnd: HWND, s: &mut AppState, text: &str) {
    s.status = text.to_string();
    let _ = InvalidateRect(Some(hwnd), None, false);
}

unsafe fn pick_and_scan(s: &mut AppState, folder: bool) {
    if let Some(path) = pick_path(folder) {
        lv_clear(s.scan_list);
        clear_scan_results(s);
        s.status = format!("Scanning {}…", path.display());
        let _ = s.work_tx.send(WorkRequest::Scan(vec![path]));
    }
}

/// Full mode: pick a folder, then scan its files (in memory) + registry + logs.
unsafe fn pick_and_full_scan(s: &mut AppState) {
    if let Some(path) = pick_path(true) {
        lv_clear(s.scan_list);
        clear_scan_results(s);
        s.status = format!("Full scan: {} + registry + logs…", path.display());
        let _ = s.work_tx.send(WorkRequest::FullScan(vec![path]));
    }
}

/// Drop every cached scan-result row (kept in sync with `lv_clear(scan_list)`).
fn clear_scan_results(s: &mut AppState) {
    s.scan_rows.clear();
    s.scan_sev.clear();
    s.scan_verdict.clear();
    s.scan_threat.clear();
}

/// Human-readable ETA from seconds: "12s", "3m 05s", "1h 04m".
fn fmt_eta(secs: f64) -> String {
    if !secs.is_finite() || secs <= 0.0 {
        return "0s".to_string();
    }
    let s = secs.round() as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
    }
}

fn sev_label(sev: u8) -> &'static str {
    match sev {
        2 => "High",
        1 => "Medium",
        _ => "Info",
    }
}

/// Quote a CSV field only when it contains a delimiter/quote/newline, doubling
/// any embedded quotes (RFC 4180).
fn csv_escape(field: &str) -> String {
    if field.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Build the result report. CSV (machine-readable) unless `txt` is set, in which
/// case a human-readable plain-text layout is produced.
fn build_report(s: &AppState, txt: bool) -> String {
    let mut out = String::new();
    if txt {
        out.push_str("HydraDragon Antivirus — scan results\r\n");
        out.push_str(&format!(
            "{} file(s) scanned, {} threat(s) found\r\n\r\n",
            s.scanned_count, s.threat_count
        ));
        if s.scan_rows.is_empty() {
            out.push_str("No threats detected.\r\n");
            return out;
        }
        for i in 0..s.scan_rows.len() {
            out.push_str(&format!(
                "[{}] {}\r\n    verdict: {}\r\n    threat : {}\r\n",
                sev_label(s.scan_sev.get(i).copied().unwrap_or(0)),
                s.scan_rows[i].display(),
                s.scan_verdict.get(i).map(String::as_str).unwrap_or(""),
                s.scan_threat.get(i).map(String::as_str).unwrap_or(""),
            ));
            // MD5 only for real files (registry/log/memory rows aren't files), so
            // the user can look the hash up on VirusTotal. Report only — not in the GUI.
            if let Some(md5) = file_md5(&s.scan_rows[i]) {
                out.push_str(&format!(
                    "    md5    : {md5}  (search on VirusTotal: https://www.virustotal.com/gui/file/{md5})\r\n"
                ));
            }
            out.push_str("\r\n");
        }
    } else {
        out.push_str("# HydraDragon Antivirus scan results\r\n");
        out.push_str(&format!(
            "# {} file(s) scanned, {} threat(s) found\r\n",
            s.scanned_count, s.threat_count
        ));
        out.push_str("File,Verdict,Threat,Severity,MD5\r\n");
        for i in 0..s.scan_rows.len() {
            out.push_str(&format!(
                "{},{},{},{},{}\r\n",
                csv_escape(&s.scan_rows[i].display().to_string()),
                csv_escape(s.scan_verdict.get(i).map(String::as_str).unwrap_or("")),
                csv_escape(s.scan_threat.get(i).map(String::as_str).unwrap_or("")),
                sev_label(s.scan_sev.get(i).copied().unwrap_or(0)),
                file_md5(&s.scan_rows[i]).unwrap_or_default(),
            ));
        }
    }
    out
}

/// Stream a file's MD5 as lowercase hex, or None if it isn't a readable file
/// (registry/event-log/memory detections have no underlying file). Streamed in
/// chunks so a huge detected file doesn't have to be loaded into memory at once.
fn file_md5(path: &Path) -> Option<String> {
    use md5::{Digest, Md5};
    use std::io::Read;
    if !path.is_file() {
        return None;
    }
    let mut f = std::fs::File::open(path).ok()?;
    let mut hasher = Md5::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(32);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    Some(hex)
}

/// Export the current scan results to a CSV/TXT file chosen via the shell Save
/// dialog. The detection rows are taken from the cached `scan_*` vectors.
unsafe fn save_results(hwnd: HWND, s: &mut AppState) {
    if s.scan_state == ScanState::Idle {
        set_status(hwnd, s, "Run a scan first, then save the results.");
        return;
    }
    let Some(path) = pick_save_path("hydradragon_scan_results.csv") else {
        return; // user cancelled
    };
    let as_txt = path
        .extension()
        .map(|e| e.eq_ignore_ascii_case("txt"))
        .unwrap_or(false);
    let content = build_report(s, as_txt);
    let msg = match std::fs::write(&path, content) {
        Ok(_) => format!(
            "Saved {} detection(s) to {}",
            s.scan_rows.len(),
            path.display()
        ),
        Err(e) => format!("Save failed: {e}"),
    };
    set_status(hwnd, s, &msg);
}

/// Force a fresh, uncached re-scan of the selected detection rows. Used to
/// re-verify a hit (e.g. after the file changed, or to rule out a false positive)
/// without re-running the whole scan.
unsafe fn rescan_selected(hwnd: HWND, s: &mut AppState) {
    let paths: Vec<PathBuf> = lv_selected(s.scan_list)
        .into_iter()
        .filter_map(|i| s.scan_rows.get(i as usize).cloned())
        .collect();
    if paths.is_empty() {
        set_status(hwnd, s, "Select one or more rows to rescan.");
        return;
    }
    set_status(hwnd, s, &format!("Rescanning {} file(s)…", paths.len()));
    let _ = s.work_tx.send(WorkRequest::Rescan(paths));
}

/// Copy the selected detection rows to the clipboard as tab-separated
/// `file<TAB>verdict<TAB>threat` lines (CRLF between rows).
unsafe fn copy_selected(hwnd: HWND, s: &mut AppState) {
    let sel = lv_selected(s.scan_list);
    if sel.is_empty() {
        set_status(hwnd, s, "Select one or more rows to copy.");
        return;
    }
    let mut lines: Vec<String> = Vec::new();
    for i in sel {
        let i = i as usize;
        if let Some(p) = s.scan_rows.get(i) {
            let file = p.display().to_string();
            let verdict = s.scan_verdict.get(i).cloned().unwrap_or_default();
            let threat = s.scan_threat.get(i).cloned().unwrap_or_default();
            lines.push(format!("{file}\t{verdict}\t{threat}"));
        }
    }
    let n = lines.len();
    let text = lines.join("\r\n");
    let msg = if set_clipboard_text(hwnd, &text) {
        format!("Copied {n} row(s) to clipboard.")
    } else {
        "Copy failed.".to_string()
    };
    set_status(hwnd, s, &msg);
}

/// Put UTF-16 text on the clipboard via the classic Global-memory dance.
/// On success ownership of the allocation transfers to the clipboard.
unsafe fn set_clipboard_text(hwnd: HWND, text: &str) -> bool {
    let mut utf16: Vec<u16> = text.encode_utf16().collect();
    utf16.push(0); // NUL terminator the clipboard expects
    let bytes = utf16.len() * std::mem::size_of::<u16>();

    if OpenClipboard(Some(hwnd)).is_err() {
        return false;
    }
    let mut ok = false;
    if EmptyClipboard().is_ok() {
        if let Ok(hmem) = GlobalAlloc(GMEM_MOVEABLE, bytes) {
            let dst = GlobalLock(hmem) as *mut u16;
            if !dst.is_null() {
                std::ptr::copy_nonoverlapping(utf16.as_ptr(), dst, utf16.len());
                let _ = GlobalUnlock(hmem); // returns Err on success (lock→0); ignore
                // HGLOBAL and HANDLE are both newtypes over the same pointer.
                if SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hmem.0))).is_ok() {
                    ok = true; // clipboard now owns hmem — must not free it
                }
            }
        }
    }
    let _ = CloseClipboard();
    ok
}

unsafe fn act_on_selected(hwnd: HWND, s: &mut AppState, clean: bool) {
    let paths: Vec<PathBuf> = lv_selected(s.scan_list)
        .into_iter()
        .filter_map(|i| s.scan_rows.get(i as usize).cloned())
        .collect();
    if paths.is_empty() {
        set_status(hwnd, s, "Select one or more detected files first.");
        return;
    }
    let prompt = if clean {
        format!("Clean {} selected file(s)?\nMatched regions are neutralized in place (a .bak is kept) or the file is quarantined.", paths.len())
    } else {
        format!("Remove Windows traces for {} selected file(s)?\nA System Restore Point and per-key .reg backups are created first.", paths.len())
    };
    if confirm(hwnd, &prompt) {
        let _ = s.work_tx.send(if clean {
            WorkRequest::Clean(paths)
        } else {
            WorkRequest::RemoveTraces(paths)
        });
    }
}

unsafe fn refresh_quarantine(s: &mut AppState) {
    lv_clear(s.quar_list);
    s.quar_ids.clear();
    let q = Quarantine::new(&s.quarantine_dir);
    let items = q.list();
    for e in &items {
        lv_add_row(
            s.quar_list,
            &[&e.id, &e.original_path.display().to_string(), &e.detection, &e.size.to_string()],
        );
        s.quar_ids.push(e.id.clone());
    }
    s.status = format!("{} quarantined item(s).", items.len());
}

unsafe fn quarantine_action(s: &mut AppState, restore: bool) {
    let ids: Vec<String> = lv_selected(s.quar_list)
        .into_iter()
        .filter_map(|i| s.quar_ids.get(i as usize).cloned())
        .collect();
    if ids.is_empty() {
        s.status = "Select one or more quarantined items first.".into();
        return;
    }
    let q = Quarantine::new(&s.quarantine_dir);
    let mut ok = 0;
    for id in &ids {
        let r = if restore { q.restore(id).map(|_| ()) } else { q.delete(id) };
        if r.is_ok() {
            ok += 1;
        }
    }
    let verb = if restore { "restored" } else { "deleted" };
    refresh_quarantine(s);
    s.status = format!("{ok}/{} item(s) {verb}.", ids.len());
}

unsafe fn drain_results(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let prev_state = s.scan_state;
    let mut changed = false;
    while let Ok(m) = s.result_rx.try_recv() {
        changed = true;
        match m {
            ScanMsg::Row { file, verdict, threat, sev } => {
                lv_add_row(s.scan_list, &[&file, &verdict, &threat]);
                s.scan_rows.push(PathBuf::from(file));
                s.scan_sev.push(sev);
                s.scan_verdict.push(verdict);
                s.scan_threat.push(threat);
            }
            ScanMsg::Status(t) => s.status = t,
            ScanMsg::Begin => {
                s.scan_state = ScanState::Scanning;
                s.scanned_count = 0;
                s.threat_count = 0;
                s.scan_discovered = 0;
                s.scan_speed = 0.0;
                s.scan_eta_secs = 0.0;
                s.scan_discovering = true;
                s.status = "Discovering & scanning…".into();
            }
            ScanMsg::Progress { scanned, threats, discovered, speed, eta_secs, discovering } => {
                s.scan_state = ScanState::Scanning;
                s.scanned_count = scanned;
                s.threat_count = threats;
                s.scan_discovered = discovered;
                s.scan_speed = speed;
                s.scan_eta_secs = eta_secs;
                s.scan_discovering = discovering;
                let eta = if discovering {
                    format!("~{} (discovering)", fmt_eta(eta_secs))
                } else {
                    fmt_eta(eta_secs)
                };
                s.status = format!(
                    "Scanned {scanned}/{discovered} · {speed:.0} files/s · ETA {eta} · {threats} threat(s)"
                );
            }
            ScanMsg::Done { scanned, threats } => {
                s.scanned_count = scanned;
                s.threat_count = threats;
                s.scan_state = if threats > 0 { ScanState::Threats } else { ScanState::Clean };
                s.status = format!("Done. {scanned} scanned, {threats} threat(s).");
            }
            ScanMsg::Paused { scanned, threats, remaining } => {
                s.scanned_count = scanned;
                s.threat_count = threats;
                s.scan_state = ScanState::Paused;
                s.status = format!("Paused. {scanned} scanned, {remaining} remaining — Resume to continue.");
            }
            ScanMsg::Resumed => {
                s.scan_state = ScanState::Scanning;
                s.status = "Resuming…".into();
            }
            ScanMsg::Rescanned { file, verdict, threat, sev, threat_found } => {
                let row = s.scan_rows.iter().position(|p| p.to_string_lossy() == file);
                s.status = format!("Rescanned {file}.");
                match (row, threat_found) {
                    // Still a threat → update the existing row's columns + severity.
                    (Some(i), true) => {
                        lv_set_item_text(s.scan_list, i as i32, 1, &verdict);
                        lv_set_item_text(s.scan_list, i as i32, 2, &threat);
                        s.scan_sev[i] = sev;
                        s.scan_verdict[i] = verdict;
                        s.scan_threat[i] = threat;
                    }
                    // Came back clean → drop the row and its parallel metadata.
                    (Some(i), false) => {
                        lv_delete_item(s.scan_list, i as i32);
                        s.scan_rows.remove(i);
                        s.scan_sev.remove(i);
                        s.scan_verdict.remove(i);
                        s.scan_threat.remove(i);
                    }
                    // Not currently listed but now flagged → append it.
                    (None, true) => {
                        lv_add_row(s.scan_list, &[&file, &verdict, &threat]);
                        s.scan_rows.push(PathBuf::from(file));
                        s.scan_sev.push(sev);
                        s.scan_verdict.push(verdict);
                        s.scan_threat.push(threat);
                    }
                    (None, false) => {}
                }
                // Every stored row is a detection, so the threat count is just the
                // row count; refresh the hero banner to match.
                s.threat_count = s.scan_rows.len();
                s.scan_state = if s.threat_count > 0 { ScanState::Threats } else { ScanState::Clean };
                let _ = InvalidateRect(Some(s.scan_list), None, true);
            }
        }
    }
    if changed {
        // Only re-layout on an actual state transition (Scanning/Paused/Done),
        // since that changes which buttons the Scan page shows. Doing it every
        // Row/Progress tick would needlessly MoveWindow the list and flicker.
        if s.scan_state != prev_state {
            layout(hwnd);
        }
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

unsafe fn confirm(hwnd: HWND, t: &str) -> bool {
    MessageBoxW(Some(hwnd), PCWSTR(wide(t).as_ptr()), w!("HydraDragon Antivirus"), MB_YESNO | MB_ICONWARNING)
        == IDYES
}

// ---------------------------------------------------------------------------
// ListView helpers + custom draw
// ---------------------------------------------------------------------------

unsafe fn lv_col(list: HWND, index: i32, title: &str, width: i32) {
    let mut t = wide(title);
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
        cx: width,
        pszText: PWSTR(t.as_mut_ptr()),
        iSubItem: index,
        ..Default::default()
    };
    SendMessageW(list, msg::LVM_INSERTCOLUMNW, Some(WPARAM(index as usize)), Some(LPARAM(&col as *const _ as isize)));
}

unsafe fn lv_add_row(list: HWND, cols: &[&str]) -> i32 {
    let count = SendMessageW(list, msg::LVM_GETITEMCOUNT, None, None).0 as i32;
    let mut first = wide(cols[0]);
    let item = LVITEMW {
        mask: LVIF_TEXT,
        iItem: count,
        pszText: PWSTR(first.as_mut_ptr()),
        ..Default::default()
    };
    let idx = SendMessageW(list, msg::LVM_INSERTITEMW, None, Some(LPARAM(&item as *const _ as isize))).0 as i32;
    for (sub, t) in cols.iter().enumerate().skip(1) {
        let mut tw = wide(t);
        let it = LVITEMW { iSubItem: sub as i32, pszText: PWSTR(tw.as_mut_ptr()), ..Default::default() };
        SendMessageW(list, msg::LVM_SETITEMTEXTW, Some(WPARAM(idx as usize)), Some(LPARAM(&it as *const _ as isize)));
    }
    idx
}

unsafe fn lv_clear(list: HWND) {
    SendMessageW(list, msg::LVM_DELETEALLITEMS, None, None);
}

/// Overwrite the text of one subitem (column) of an existing row.
unsafe fn lv_set_item_text(list: HWND, row: i32, col: i32, t: &str) {
    let mut tw = wide(t);
    let it = LVITEMW {
        iSubItem: col,
        pszText: PWSTR(tw.as_mut_ptr()),
        ..Default::default()
    };
    SendMessageW(list, msg::LVM_SETITEMTEXTW, Some(WPARAM(row as usize)), Some(LPARAM(&it as *const _ as isize)));
}

/// Delete one row by index.
unsafe fn lv_delete_item(list: HWND, row: i32) {
    SendMessageW(list, msg::LVM_DELETEITEM, Some(WPARAM(row as usize)), None);
}

unsafe fn lv_selected(list: HWND) -> Vec<i32> {
    let mut out = Vec::new();
    let mut idx: i32 = -1;
    loop {
        let r = SendMessageW(list, msg::LVM_GETNEXTITEM, Some(WPARAM(idx as usize)), Some(LPARAM(sty::LVNI_SELECTED))).0 as i32;
        if r == -1 {
            break;
        }
        out.push(r);
        idx = r;
    }
    out
}

/// Color scan rows by severity (red = malware, amber = suspicious/pua).
unsafe fn on_list_customdraw(hwnd: HWND, cd: *mut NMLVCUSTOMDRAW) -> isize {
    let cd = &mut *cd;
    match cd.nmcd.dwDrawStage.0 {
        CDDS_PREPAINT => CDRF_NOTIFYITEMDRAW,
        CDDS_ITEMPREPAINT => {
            let item = cd.nmcd.dwItemSpec;
            if let Some(s) = state(hwnd) {
                let t = s.theme();
                let sev = s.scan_sev.get(item).copied().unwrap_or(0);
                cd.clrText = match sev {
                    2 => t.danger,
                    1 => t.warn,
                    _ => t.text,
                };
                // Zebra striping for readability.
                cd.clrTextBk = if item % 2 == 0 { t.surface } else { t.stripe };
            }
            CDRF_NEWFONT
        }
        _ => CDRF_DODEFAULT,
    }
}

/// Native shell file/folder picker via `IFileOpenDialog`.
unsafe fn pick_path(folder: bool) -> Option<PathBuf> {
    let dialog: IFileOpenDialog = CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
    if folder {
        let opts = dialog.GetOptions().ok()?;
        dialog.SetOptions(opts | FOS_PICKFOLDERS).ok()?;
    }
    dialog.Show(None).ok()?;
    let item: IShellItem = dialog.GetResult().ok()?;
    let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
    let path = pw.to_string().ok();
    CoTaskMemFree(Some(pw.0 as *const c_void));
    path.map(PathBuf::from)
}

/// Native shell "Save As" dialog via `IFileSaveDialog`. Offers CSV and TXT
/// filters; returns the chosen path (with the picked extension) or None on cancel.
unsafe fn pick_save_path(default_name: &str) -> Option<PathBuf> {
    let dialog: IFileSaveDialog = CoCreateInstance(&FileSaveDialog, None, CLSCTX_INPROC_SERVER).ok()?;

    // Filter strings must outlive Show(); keep them alive in locals.
    let csv_name = wide("CSV report (*.csv)");
    let csv_spec = wide("*.csv");
    let txt_name = wide("Text report (*.txt)");
    let txt_spec = wide("*.txt");
    let filters = [
        COMDLG_FILTERSPEC { pszName: PCWSTR(csv_name.as_ptr()), pszSpec: PCWSTR(csv_spec.as_ptr()) },
        COMDLG_FILTERSPEC { pszName: PCWSTR(txt_name.as_ptr()), pszSpec: PCWSTR(txt_spec.as_ptr()) },
    ];
    let _ = dialog.SetFileTypes(&filters);
    let _ = dialog.SetDefaultExtension(w!("csv"));
    let name = wide(default_name);
    let _ = dialog.SetFileName(PCWSTR(name.as_ptr()));

    dialog.Show(None).ok()?;
    let item: IShellItem = dialog.GetResult().ok()?;
    let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
    let path = pw.to_string().ok();
    CoTaskMemFree(Some(pw.0 as *const c_void));
    path.map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

/// A scan in progress (or stopped). The file tree is walked lazily *during* the
/// scan (not collected up front), so `dirs` holds folders still to descend and
/// `queue` holds discovered-but-unscanned files. Kept across requests so a
/// stopped scan can be resumed where it left off.
struct ScanSession {
    dirs: VecDeque<PathBuf>,  // folders not yet walked
    queue: VecDeque<PathBuf>, // files discovered but not yet scanned
    scanned: usize,           // files completed so far
    threats: usize,           // detections so far
    discovered: usize,        // files discovered so far (running total)
    full: bool,               // also run registry/logs/memory after the files
}

/// Seed a session from the chosen roots WITHOUT walking them: directories are
/// queued for lazy discovery, single picked files go straight to the scan queue.
fn seed_session(paths: &[PathBuf], full: bool) -> ScanSession {
    let mut dirs = VecDeque::new();
    let mut queue = VecDeque::new();
    let mut discovered = 0;
    for p in paths {
        if p.is_dir() {
            dirs.push_back(p.clone());
        } else if p.is_file() && p.metadata().map(|m| m.len() >= 12).unwrap_or(false) {
            queue.push_back(p.clone());
            discovered += 1;
        }
    }
    ScanSession { dirs, queue, scanned: 0, threats: 0, discovered, full }
}

fn worker(
    raw: isize,
    work_rx: Receiver<WorkRequest>,
    tx: Sender<ScanMsg>,
    quarantine_dir: PathBuf,
    cancel: Arc<AtomicBool>,
) {
    let hwnd = HWND(raw as *mut c_void);
    let mut pipeline: Option<Pipeline> = None;
    let mut session: Option<ScanSession> = None;

    while let Ok(req) = work_rx.recv() {
        match req {
            WorkRequest::Scan(paths) => {
                send(&tx, hwnd, ScanMsg::Begin);
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                session = Some(seed_session(&paths, false));
                let completed = run_session(pl, session.as_mut().unwrap(), &cancel, &tx, hwnd);
                if completed {
                    session = None;
                }
            }
            WorkRequest::FullScan(paths) => {
                send(&tx, hwnd, ScanMsg::Begin);
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                session = Some(seed_session(&paths, true));
                let completed = run_session(pl, session.as_mut().unwrap(), &cancel, &tx, hwnd);
                if completed {
                    session = None;
                }
            }
            WorkRequest::Resume => {
                if let Some(sess) = session.as_mut() {
                    send(&tx, hwnd, ScanMsg::Resumed);
                    let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                    let completed = run_session(pl, sess, &cancel, &tx, hwnd);
                    if completed {
                        session = None;
                    }
                } else {
                    send(&tx, hwnd, ScanMsg::Status("Nothing to resume.".into()));
                }
            }
            WorkRequest::Rescan(paths) => {
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                let n = paths.len();
                for path in &paths {
                    // Uncached scan_file so a previously-cached good/bad result
                    // never short-circuits the re-verification.
                    let r = pl.scan_file(path);
                    let prio = r.verdict.priority();
                    let threat_found = prio > 1;
                    send(&tx, hwnd, ScanMsg::Rescanned {
                        file: path.display().to_string(),
                        verdict: r.verdict.label().to_string(),
                        threat: detail_summary(&r),
                        sev: if prio >= 6 { 2 } else if threat_found { 1 } else { 0 },
                        threat_found,
                    });
                }
                send(&tx, hwnd, ScanMsg::Status(format!("Rescan complete ({n} file(s)).")));
            }
            WorkRequest::Clean(paths) => {
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                for path in &paths {
                    let arenas = pl.arenas_for_file(path);
                    let line = match disinfector::disinfect_file(path, &arenas, &quarantine_dir) {
                        DisinfectOutcome::Neutralized { bytes, .. } => format!("neutralized {bytes} byte(s) in {}", path.display()),
                        DisinfectOutcome::Quarantined { to } => format!("quarantined {} -> {}", path.display(), to.display()),
                        DisinfectOutcome::Failed { reason } => format!("FAILED {}: {reason}", path.display()),
                    };
                    send(&tx, hwnd, ScanMsg::Status(line));
                }
                send(&tx, hwnd, ScanMsg::Status("Clean complete.".into()));
            }
            WorkRequest::RemoveTraces(paths) => {
                match remediation::create_restore_point("HydraDragon GUI remediation") {
                    Ok(_) => send(&tx, hwnd, ScanMsg::Status("Restore point created.".into())),
                    Err(e) => send(&tx, hwnd, ScanMsg::Status(format!("Restore point skipped: {e}"))),
                }
                let mut removed = 0usize;
                for path in &paths {
                    for trace in remediation::find_traces(path) {
                        match remediation::apply(&trace, &quarantine_dir) {
                            Ok(_) => removed += 1,
                            Err(e) => send(&tx, hwnd, ScanMsg::Status(format!("trace [{}] failed: {e}", trace.category))),
                        }
                    }
                }
                send(&tx, hwnd, ScanMsg::Status(format!("Removed {removed} trace(s).")));
            }
            WorkRequest::ClearCache => {
                if let Some(pl) = pipeline.as_mut() {
                    pl.clear_result_caches();
                } else {
                    // Engine not loaded yet — remove the persisted blooms directly.
                    let dir = exe_dir();
                    let _ = std::fs::remove_file(dir.join("good_results.bloom"));
                    let _ = std::fs::remove_file(dir.join("bad_results.bloom"));
                }
                send(&tx, hwnd, ScanMsg::Status("Result cache cleared.".into()));
            }
        }
    }
}

/// Drive a scan session: the streaming parallel file phase, then (if completed
/// and this is a Full Scan) the registry / event-log / memory phases. Sends
/// `Paused` if stopped, otherwise `Done`. Returns true when the whole session is
/// finished (so the caller can drop it). Resets the cancel flag on entry.
fn run_session(
    pl: &Pipeline,
    sess: &mut ScanSession,
    cancel: &AtomicBool,
    tx: &Sender<ScanMsg>,
    hwnd: HWND,
) -> bool {
    cancel.store(false, Ordering::Relaxed);
    let completed = run_streaming(pl, sess, cancel, tx, hwnd);
    pl.save_result_caches(); // persist learned good/bad results either way

    if !completed {
        send(tx, hwnd, ScanMsg::Paused {
            scanned: sess.scanned,
            threats: sess.threats,
            remaining: sess.queue.len(),
        });
        return false;
    }

    if !sess.full {
        send(tx, hwnd, ScanMsg::Done { scanned: sess.scanned, threats: sess.threats });
        return true;
    }

    // Full mode = files + registry + Windows event logs + process memory. These
    // phases run to completion (they are not part of the pausable file loop).
    send(tx, hwnd, ScanMsg::Status("Full scan: registry…".into()));
    let reg = RegistryScanner::default().scan();
    for e in &reg.entries {
        if e.pua_match || e.static_match {
            send(tx, hwnd, ScanMsg::Row {
                file: format!("{}\\{}\\{}", e.hive, e.path, e.value_name),
                verdict: "Registry".into(),
                threat: e.threat_name.clone().unwrap_or_else(|| e.detail.clone()),
                sev: if e.static_match { 2 } else { 1 },
            });
        }
    }

    send(tx, hwnd, ScanMsg::Status("Full scan: Windows event logs…".into()));
    let logs = scan_hayabusa_once(&exe_dir().join("hayabusa"));
    for m in &logs {
        send(tx, hwnd, ScanMsg::Row {
            file: "Windows Event Logs".into(),
            verdict: "Hayabusa".into(),
            threat: m.clone(),
            sev: 2,
        });
    }

    send(tx, hwnd, ScanMsg::Status("Full scan: process memory…".into()));
    let mem = memory_scanner::scan_process_memory(pl);
    for d in &mem {
        send(tx, hwnd, ScanMsg::Row {
            file: format!("{} (pid {}) @ 0x{:x}", d.process, d.pid, d.address),
            verdict: d.verdict.label().to_string(),
            threat: d.threat_name.clone(),
            sev: if d.verdict.priority() >= 6 { 2 } else { 1 },
        });
    }

    let total = sess.threats + reg.threats_found as usize + logs.len() + mem.len();
    send(tx, hwnd, ScanMsg::Done { scanned: sess.scanned, threats: total });
    send(tx, hwnd, ScanMsg::Status(format!(
        "Full scan done. Files {}, registry {} threat(s), logs {} alert(s), memory {} hit(s).",
        sess.threats, reg.threats_found, logs.len(), mem.len()
    )));
    true
}

/// Streaming, parallel file-scan phase. One producer thread walks the directory
/// tree lazily (so a whole-drive scan starts immediately instead of enumerating
/// everything first), pushing discovered files into a shared queue; N consumer
/// threads pull and scan concurrently; one ticker thread emits speed/ETA progress
/// a few times a second. Each thread checks `cancel` before taking new work, so a
/// Stop takes effect after the in-flight files finish (a file scan is never cut
/// mid-way). Remaining folders + queued files are written back into `sess` for
/// Resume. Returns true if the tree was fully scanned, false if stopped early.
fn run_streaming(
    pl: &Pipeline,
    sess: &mut ScanSession,
    cancel: &AtomicBool,
    tx: &Sender<ScanMsg>,
    hwnd: HWND,
) -> bool {
    if sess.dirs.is_empty() && sess.queue.is_empty() {
        return true;
    }

    let dirs = Mutex::new(std::mem::take(&mut sess.dirs));
    let files = Mutex::new(std::mem::take(&mut sess.queue));
    let discovered = AtomicUsize::new(sess.discovered);
    let scanned = AtomicUsize::new(sess.scanned);
    let threats = AtomicUsize::new(sess.threats);
    let discovery_done = AtomicBool::new(false);
    let scanned_at_start = sess.scanned;

    let raw = hwnd.0 as isize; // HWND isn't Send; rebuild it inside each thread
    let nconsumers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(1);

    let dirs_ref = &dirs;
    let files_ref = &files;
    let discovered_ref = &discovered;
    let scanned_ref = &scanned;
    let threats_ref = &threats;
    let done_ref = &discovery_done;

    std::thread::scope(|scope| {
        // ---- producer: lazy directory walk ----
        scope.spawn(move || {
            'walk: loop {
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                let dir = { dirs_ref.lock().unwrap().pop_front() };
                let Some(dir) = dir else { break };
                let Ok(rd) = std::fs::read_dir(&dir) else { continue };
                for entry in rd.flatten() {
                    if cancel.load(Ordering::Relaxed) {
                        // Re-walk this dir on Resume (dedup makes re-enqueue cheap).
                        dirs_ref.lock().unwrap().push_front(dir);
                        break 'walk;
                    }
                    let path = entry.path();
                    match entry.file_type() {
                        Ok(ft) if ft.is_dir() => {
                            dirs_ref.lock().unwrap().push_back(path);
                        }
                        Ok(ft) if ft.is_file() => {
                            if entry.metadata().map(|m| m.len() >= 12).unwrap_or(false) {
                                files_ref.lock().unwrap().push_back(path);
                                discovered_ref.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        _ => {}
                    }
                }
            }
            done_ref.store(true, Ordering::Relaxed);
        });

        // ---- consumers: scan discovered files concurrently ----
        for _ in 0..nconsumers {
            let txc = tx.clone();
            scope.spawn(move || {
                let hwnd = HWND(raw as *mut c_void);
                loop {
                    if cancel.load(Ordering::Relaxed) {
                        break;
                    }
                    let next = { files_ref.lock().unwrap().pop_front() };
                    let Some(file) = next else {
                        if done_ref.load(Ordering::Relaxed) {
                            break; // discovery finished and queue drained
                        }
                        std::thread::sleep(Duration::from_millis(2));
                        continue;
                    };
                    let r = pl.scan_file_cached(&file);
                    scanned_ref.fetch_add(1, Ordering::Relaxed);
                    let prio = r.verdict.priority(); // Trusted=0, Clean=1, …, Malware=8
                    if prio > 1 {
                        threats_ref.fetch_add(1, Ordering::Relaxed);
                        let sev = if prio >= 6 { 2 } else { 1 };
                        send(&txc, hwnd, ScanMsg::Row {
                            file: file.display().to_string(),
                            verdict: r.verdict.label().to_string(),
                            threat: detail_summary(&r),
                            sev,
                        });
                    }
                }
            });
        }

        // ---- ticker: emit speed/ETA a few times a second ----
        let txc = tx.clone();
        scope.spawn(move || {
            let hwnd = HWND(raw as *mut c_void);
            let start = Instant::now();
            loop {
                let done = done_ref.load(Ordering::Relaxed);
                let scanned_now = scanned_ref.load(Ordering::Relaxed);
                let discovered_now = discovered_ref.load(Ordering::Relaxed);
                let threats_now = threats_ref.load(Ordering::Relaxed);
                let elapsed = start.elapsed().as_secs_f64();
                let run_scanned = scanned_now.saturating_sub(scanned_at_start) as f64;
                let speed = if elapsed > 0.0 { run_scanned / elapsed } else { 0.0 };
                let remaining = discovered_now.saturating_sub(scanned_now);
                let eta_secs = if speed > 0.0 { remaining as f64 / speed } else { 0.0 };
                send(&txc, hwnd, ScanMsg::Progress {
                    scanned: scanned_now,
                    threats: threats_now,
                    discovered: discovered_now,
                    speed,
                    eta_secs,
                    discovering: !done,
                });
                if cancel.load(Ordering::Relaxed) {
                    break;
                }
                if done && scanned_now >= discovered_now {
                    break;
                }
                std::thread::sleep(Duration::from_millis(350));
            }
        });
    });

    // Save remaining work back for a possible Resume (empty if completed).
    sess.dirs = std::mem::take(&mut *dirs.lock().unwrap());
    sess.queue = std::mem::take(&mut *files.lock().unwrap());
    sess.scanned = scanned.load(Ordering::Relaxed);
    sess.threats = threats.load(Ordering::Relaxed);
    sess.discovered = discovered.load(Ordering::Relaxed);

    !cancel.load(Ordering::Relaxed)
}

/// All engine details for a detection: every engine that flagged it (ClamAV
/// signature, YARA-X rules, hydradragonsig, ML probability, bloom, …), joined.
fn detail_summary(r: &hydradragonav::verdict::ScanResult) -> String {
    let mut parts: Vec<String> = Vec::new();
    for e in &r.engines {
        // Only engines that actually flagged something (Trusted=0, Clean=1).
        if e.verdict.priority() > 1 && !e.detail.is_empty() {
            parts.push(format!("{}: {}", e.engine, e.detail));
        }
    }
    if let Some(p) = r.ml_malware_probability {
        parts.push(format!("ml p={p:.3}"));
    }
    if parts.is_empty() {
        r.threat_name.clone().unwrap_or_default()
    } else {
        parts.join("  |  ")
    }
}

fn ensure_pipeline<'a>(pl: &'a mut Option<Pipeline>, tx: &Sender<ScanMsg>, hwnd: HWND) -> &'a Pipeline {
    if pl.is_none() {
        send(tx, hwnd, ScanMsg::Status("Loading engines…".into()));
        *pl = Some(Pipeline::new(default_config()));
    }
    pl.as_ref().unwrap()
}

fn send(tx: &Sender<ScanMsg>, hwnd: HWND, m: ScanMsg) {
    if tx.send(m).is_ok() {
        unsafe {
            let _ = PostMessageW(Some(hwnd), WM_APP_RESULT, WPARAM(0), LPARAM(0));
        }
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn theme_pref_path() -> PathBuf {
    exe_dir().join("hydradragon_theme")
}

/// Loads the remembered theme (defaults to light if absent).
fn load_dark() -> bool {
    std::fs::read_to_string(theme_pref_path())
        .map(|s| s.trim() == "dark")
        .unwrap_or(false)
}

/// Remembers the theme choice across launches.
fn save_dark(dark: bool) {
    let _ = std::fs::write(theme_pref_path(), if dark { "dark" } else { "light" });
}

fn default_config() -> PipelineConfig {
    let dir = exe_dir();
    PipelineConfig {
        bloom_dir: Some(dir.join("bloom_filter")).filter(|p| p.exists()),
        yara_rules_dir: Some(dir.join("yara-x")).filter(|p| p.exists()),
        hydradragonsig_rules_dir: Some(dir.join("hydradragonsig_rules")).filter(|p| p.exists()),
        pe_ml_model_path: Some(dir.join("ml").join("pe_model.mpk")).filter(|p| p.exists()),
        js_ml_model_path: Some(dir.join("ml").join("js_model.mpk")).filter(|p| p.exists()),
        clamav_db: Some(dir.join("database")).filter(|p| p.exists()),
        hayabusa_dir: None,
        // Persist the good/bad result blooms next to the executable.
        results_cache_dir: Some(dir.clone()),
        ..Default::default()
    }
}
