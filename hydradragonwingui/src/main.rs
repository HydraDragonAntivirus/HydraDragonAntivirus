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
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
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
use windows::Win32::Graphics::Dwm::{DwmSetWindowAttribute, DWMWINDOWATTRIBUTE};
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
    LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LIST_VIEW_ITEM_STATE_FLAGS, LVITEMW, NMHDR, NMLVCUSTOMDRAW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    ReleaseCapture, SetCapture, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows::Win32::UI::Shell::Common::COMDLG_FILTERSPEC;
use windows::Win32::UI::Shell::{
    FileOpenDialog, FileSaveDialog, IFileOpenDialog, IFileSaveDialog, IShellItem,
    FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
    DragAcceptFiles, DragQueryFileW, DragFinish, HDROP,
    Shell_NotifyIconW, NOTIFYICONDATAW, NOTIFY_ICON_MESSAGE, NOTIFY_ICON_DATA_FLAGS,
};
use windows::Win32::UI::WindowsAndMessaging::*;

// ---------------------------------------------------------------------------
// IDs, messages, geometry
// ---------------------------------------------------------------------------

const ID_SCAN_LIST: usize = 1001;
const ID_QUAR_LIST: usize = 1002;

// Painted-button command ids.
const CMD_CUSTOM_SCAN: usize = 1;
const CMD_CLEAN: usize = 3;
const CMD_TRACES: usize = 4;
const CMD_QUAR_REFRESH: usize = 5;
const CMD_QUAR_RESTORE: usize = 6;
const CMD_QUAR_DELETE: usize = 7;
const CMD_CLEAR_CACHE: usize = 8;
const CMD_SAVE_RESULTS: usize = 10;
// Context-menu-only command (right-click a detection row → re-scan it fresh).
const CMD_RESCAN: usize = 11;
const CMD_STOP: usize = 12;
const CMD_RESUME: usize = 13;
// Context-menu: copy the selected detection rows to the clipboard.
const CMD_COPY: usize = 14;
// Settings page: load / unload the scanning engine.
const CMD_START_ENGINE: usize = 15;
const CMD_STOP_ENGINE: usize = 16;
const CMD_PAUSE: usize = 17;
const CMD_SELECT_ALL: usize = 18;
const CMD_DESELECT_ALL: usize = 19;
// Settings page: context menu install / uninstall
const CMD_INSTALL_MENU: usize = 20;
const CMD_UNINSTALL_MENU: usize = 21;

const WM_APP_RESULT: u32 = WM_APP + 1;
const WM_APP_TRAY: u32 = WM_APP + 2;
// Not surfaced by the WindowsAndMessaging glob in this build — define it raw, or
// its match arm silently becomes a catch-all binding.
const WM_MOUSELEAVE: u32 = 0x02A3;
// Defined locally for the same reason; shadows the glob if present.
const WM_CONTEXTMENU: u32 = 0x007B;
const WM_TIMER: u32 = 0x0113;
const WM_DROPFILES: u32 = 0x0233;
const WM_LBUTTONDBLCLK: u32 = 0x0203;

// Animation timer.
const ANIM_TIMER: usize = 100;
const ANIM_INTERVAL_MS: u32 = 33; // ~30 fps

// The number of DWM window corner preference. 2 = DWMWCP_ROUND (small round).
const DWMWA_WINDOW_CORNER_PREFERENCE: u32 = 33;
const DWMWCP_ROUNDSMALL: u32 = 3;

// System tray constants.
const ID_TRAY: u32 = 1001;

const HEADER_H: i32 = 68;           // slimmer header — cleaner top bar feel
const SIDEBAR_W: i32 = 220;         // slightly wider for breathing room
const STATUS_H: i32 = 28;           // slim status bar
const PAD: i32 = 16;
const BTN_W: i32 = 152;             // slightly narrower — fits more per row
const BTN_H: i32 = 48;              // slimmer pill-style buttons
const GAP: i32 = 10;
const NAV_H: i32 = 42;              // tighter nav items
const NAV_TOP: i32 = HEADER_H + 38;
const HERO_H: i32 = 114;            // hero banner height (Scan page)

mod msg {
    pub const LVM_FIRST: u32 = 0x1000;
    pub const LVM_SETBKCOLOR: u32 = LVM_FIRST + 1;
    pub const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;
    pub const LVM_DELETEITEM: u32 = LVM_FIRST + 8;
    pub const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
    pub const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
    pub const LVM_GETSUBITEMRECT: u32 = LVM_FIRST + 56;
    pub const LVM_SETTEXTCOLOR: u32 = LVM_FIRST + 36;
    pub const LVM_SETTEXTBKCOLOR: u32 = LVM_FIRST + 38;
    pub const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
    pub const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
    pub const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
    pub const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
    pub const LVM_GETITEMSTATE: u32 = LVM_FIRST + 44;
    pub const LVM_SETITEMSTATE: u32 = LVM_FIRST + 43;
}
mod sty {
    pub const CHILD: u32 = 0x4000_0000;
    pub const VISIBLE: u32 = 0x1000_0000;
    pub const CLIPCHILDREN: u32 = 0x0200_0000;
    pub const OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
    pub const LVS_REPORT: u32 = 0x0001;
    pub const LVS_EX_GRIDLINES: u32 = 0x0000_0001;
    pub const LVS_EX_FULLROWSELECT: u32 = 0x0000_0020;
    pub const LVS_EX_DOUBLEBUFFER: u32 = 0x0001_0000;
    pub const LVS_EX_CHECKBOXES: u32 = 0x0000_0004;
    pub const LVNI_SELECTED: isize = 0x0002;
}
// Custom-draw notification + stages (raw NM/CDDS/CDRF values).
const NM_CUSTOMDRAW: u32 = 0xFFFF_FFF4; // -12
const CDDS_PREPAINT: u32 = 0x0000_0001;
const CDDS_ITEMPREPAINT: u32 = 0x0001_0001;
#[allow(dead_code)]
const CDDS_SUBITEM: u32 = 0x0002_0000;
const CDDS_ITEMPOSTPAINT: u32 = 0x0001_0002;
const CDRF_DODEFAULT: isize = 0x0000_0000;
const CDRF_NEWFONT: isize = 0x0000_0002;
const CDRF_NOTIFYITEMDRAW: isize = 0x0000_0020;
const CDRF_NOTIFYPOSTPAINT: isize = 0x0000_0010;
#[allow(dead_code)]
const CDRF_NOTIFYSUBITEMDRAW: isize = 0x0000_0020; // same bit, used for subitems

/// State-image mask for ListView checkbox state (bits 12-15).
const LVIS_STATEIMAGEMASK: usize = 0xF000;

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
    #[allow(dead_code)]
    danger_soft: COLORREF,
    warn: COLORREF,
    shadow: COLORREF,
    stripe: COLORREF,
    ok: COLORREF,
    #[allow(dead_code)]
    ok_soft: COLORREF,
}

const LIGHT: Theme = Theme {
    bg: rgb(0xF0, 0xF2, 0xF8),         // cool blue-grey canvas
    header_top: rgb(0x0D, 0x11, 0x1F), // near-black navy top
    header_bot: rgb(0x06, 0x08, 0x12), // pure deep bottom
    header_sub: rgb(0x68, 0x82, 0xAC), // muted steel blue
    sidebar: rgb(0xFA, 0xFB, 0xFD),    // almost white, slight blue tint
    surface: rgb(0xFF, 0xFF, 0xFF),
    border: rgb(0xD8, 0xDD, 0xEA),     // cooler, slightly stronger
    text: rgb(0x08, 0x0C, 0x18),       // near-black with blue undertone
    text2: rgb(0x52, 0x5D, 0x72),      // cool mid-grey
    accent: rgb(0x06, 0x4F, 0xF0),     // electric indigo-blue
    accent_hot: rgb(0x26, 0x67, 0xF5),
    accent_down: rgb(0x04, 0x3A, 0xC8),
    accent_soft: rgb(0xE4, 0xED, 0xFF),
    nav_hot: rgb(0xEC, 0xF0, 0xFA),
    danger: rgb(0xCC, 0x1F, 0x3A),     // vivid crimson
    danger_hot: rgb(0xDE, 0x3A, 0x52),
    danger_down: rgb(0xAA, 0x14, 0x2E),
    danger_soft: rgb(0xFD, 0xE8, 0xEC),
    warn: rgb(0xB8, 0x6E, 0x00),       // amber-orange
    shadow: rgb(0xC8, 0xD0, 0xE4),     // cool blue shadow
    stripe: rgb(0xF4, 0xF6, 0xFB),
    ok: rgb(0x0A, 0x8F, 0x4A),         // saturated emerald
    ok_soft: rgb(0xE2, 0xF5, 0xEC),
};

const DARK: Theme = Theme {
    bg: rgb(0x0C, 0x0E, 0x14),         // deep space base
    header_top: rgb(0x12, 0x15, 0x22), // slightly lifted from bg
    header_bot: rgb(0x07, 0x08, 0x0E),
    header_sub: rgb(0x6A, 0x76, 0x96), // cool slate
    sidebar: rgb(0x11, 0x14, 0x1D),    // subtle separation from bg
    surface: rgb(0x18, 0x1C, 0x28),    // card surface
    border: rgb(0x25, 0x2A, 0x3A),     // visible but not harsh
    text: rgb(0xE8, 0xEA, 0xF2),       // cool white
    text2: rgb(0x84, 0x8E, 0xA8),      // desaturated blue-grey
    accent: rgb(0x4A, 0x90, 0xFF),     // bright periwinkle blue
    accent_hot: rgb(0x68, 0xA6, 0xFF),
    accent_down: rgb(0x2C, 0x6E, 0xF5),
    accent_soft: rgb(0x14, 0x22, 0x44),
    nav_hot: rgb(0x20, 0x26, 0x36),
    danger: rgb(0xF0, 0x4C, 0x62),     // neon crimson
    danger_hot: rgb(0xF8, 0x6C, 0x7E),
    danger_down: rgb(0xD4, 0x20, 0x3A),
    danger_soft: rgb(0x38, 0x18, 0x22),
    warn: rgb(0xF0, 0xA8, 0x00),       // clean amber
    shadow: rgb(0x05, 0x06, 0x0A),     // near-black crisp shadow
    stripe: rgb(0x15, 0x18, 0x24),
    ok: rgb(0x28, 0xD4, 0x6A),         // vivid emerald
    ok_soft: rgb(0x0E, 0x28, 0x1C),
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
    icon: &'static str, // Segoe MDL2 Assets glyph
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

/// Lifecycle of the scanning engine (pipeline). It is loaded on a loading screen
/// at startup and can be unloaded/reloaded via Start/Stop Engine.
#[derive(Clone, Copy, PartialEq)]
enum EngineState {
    Loading,
    Ready,
    Stopped,
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
        mbps: f64,
        eta_secs: f64,
        discovering: bool,
        current: String,
    },
    Done { scanned: usize, threats: usize },
    /// Scan was paused mid-run; `remaining` files are queued for Resume.
    Paused { scanned: usize, threats: usize, remaining: usize },
    /// Scan was stopped (aborted) mid-run; the session is discarded — no Resume.
    Stopped,
    /// A paused scan has been picked back up.
    Resumed,
    /// Engine lifecycle (drives the loading screen / status indicator).
    EngineLoading,
    EngineReady { signatures: usize },
    EngineStopped,
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
    /// Full scan: files + registry + Windows event logs + process memory
    FullScan(Vec<PathBuf>),
    /// Force a fresh (uncached) re-scan of specific files already in the list.
    Rescan(Vec<PathBuf>),
    /// Continue a scan that was stopped (the worker keeps the remaining file list).
    Resume,
    /// Load the engine (pipeline) if not already loaded.
    StartEngine,
    /// Unload the engine to free memory.
    StopEngine,
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
    engine: EngineState,
    scanned_count: usize,
    threat_count: usize,
    /// Total signatures loaded, shown once the engine is ready.
    sig_count: usize,
    // Live throughput for the hero banner / status bar (streaming scan).
    scan_discovered: usize,
    scan_speed: f64,
    scan_mbps: f64,
    scan_eta_secs: f64,
    scan_discovering: bool,
    /// Wall-clock start of the current scan (set on `Begin`).
    scan_started_at: Option<Instant>,
    /// Total duration of the last completed scan (set on `Done`), shown in the
    /// status bar and exported in the report.
    scan_elapsed: Option<Duration>,
    anim_frame: u32,
    anim_timer_active: bool,
    /// Button hover animation: (cmd, entering[true]/exiting[false], progress 0-5)
    hover_anim: Vec<(usize, bool, u32)>,
    tray_icon_shown: bool,
    work_tx: Sender<WorkRequest>,
    result_rx: Receiver<ScanMsg>,
    /// Set from the UI thread (Pause/Stop) and polled by the worker's scan loop
    /// to interrupt between files. Shared with the worker thread.
    cancel: Arc<AtomicBool>,
    /// Distinguishes Stop (abort → discard session, back to home) from Pause
    /// (keep session for Resume). Set together with `cancel` on Stop.
    abort: Arc<AtomicBool>,
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
            WM_SYSCOMMAND if wp.0 as u32 == SC_MINIMIZE => {
                // Minimize to tray instead of taskbar.
                let _ = ShowWindow(hwnd, SW_HIDE);
                if let Some(s) = state(hwnd) {
                    show_tray_icon(hwnd, s);
                }
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
            x if x == WM_DROPFILES => {
                let hdrop = HDROP(wp.0 as *mut c_void);
                on_dropfiles(hwnd, hdrop);
                LRESULT(0)
            }
            x if x == WM_APP_TRAY => {
                let hiword = (lp.0 >> 16) as u32;
                if hiword == WM_LBUTTONUP || hiword == WM_LBUTTONDBLCLK {
                    let _ = ShowWindow(hwnd, SW_SHOW);
                    _ = SetForegroundWindow(hwnd);
                    if let Some(s) = state(hwnd) {
                        if s.tray_icon_shown {
                            s.tray_icon_shown = false;
                            let nid = NOTIFYICONDATAW {
                                cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                                uID: ID_TRAY,
                                uFlags: NOTIFY_ICON_DATA_FLAGS(0),
                                ..Default::default()
                            };
                            _ = Shell_NotifyIconW(NOTIFY_ICON_MESSAGE(2), &nid);
                        }
                    }
                }
                LRESULT(0)
            }
            x if x == WM_TIMER && wp.0 == ANIM_TIMER => {
                on_anim_tick(hwnd);
                LRESULT(0)
            }
            WM_DESTROY => {
                let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
                if !ptr.is_null() {
                    let s = Box::from_raw(ptr);
                    delete_fonts(&s.fonts);
                    // Remove tray icon if still showing.
                    if s.tray_icon_shown {
                        let nid = NOTIFYICONDATAW {
                            cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
                            uID: ID_TRAY,
                            uFlags: NOTIFY_ICON_DATA_FLAGS(0),
                            ..Default::default()
                        };
                        _ = Shell_NotifyIconW(NOTIFY_ICON_MESSAGE(2), &nid);
                    }
                    if s.anim_timer_active {
                        let _ = KillTimer(Some(hwnd), ANIM_TIMER);
                    }
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
        logo: make_font(-18, 700),
        title: make_font(-20, 600),      // header title — tighter
        sub: make_font(-12, 400),        // header subtitle
        nav: make_font(-14, 600),        // nav labels — slightly smaller
        button: make_font(-13, 600),     // button labels — compact
        body: make_font(-14, 400),       // list body text
        status: make_font(-12, 400),     // slim status bar
        icon: make_font_face(-16, 400, "Segoe MDL2 Assets"),
        icon_lg: make_font_face(-20, 400, "Segoe MDL2 Assets"),
        hero: make_font(-22, 600),       // hero headline
        hero_icon: make_font_face(-26, 400, "Segoe MDL2 Assets"),
    };

    let lv = sty::CHILD | sty::VISIBLE | sty::LVS_REPORT;
    let scan_list = make_list(hwnd, hinst, lv, ID_SCAN_LIST, fonts.body);
    // Enable checkboxes on the scan results list so the user can select which
    // threats to clean — the check state is independent of selection highlights.
    SendMessageW(
        scan_list,
        msg::LVM_SETEXTENDEDLISTVIEWSTYLE,
        Some(WPARAM(sty::LVS_EX_CHECKBOXES as usize)),
        Some(LPARAM(sty::LVS_EX_CHECKBOXES as isize)),
    );
    lv_col(scan_list, 0, "File", 470);
    lv_col(scan_list, 1, "Verdict", 120);
    lv_col(scan_list, 2, "Type", 240);

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
    let abort = Arc::new(AtomicBool::new(false));
    let worker_abort = abort.clone();
    std::thread::spawn(move || worker(raw, work_rx, result_tx, qdir, worker_cancel, worker_abort));
    // Load the engine immediately so the loading screen shows on startup.
    let _ = work_tx.send(WorkRequest::StartEngine);

    // Accept dragged files/folders.
    let _ = DragAcceptFiles(hwnd, true);

    // Win11 rounded window corners via DWM.
    let corner_pref = DWMWCP_ROUNDSMALL;
    let _ = DwmSetWindowAttribute(
        hwnd,
        DWMWINDOWATTRIBUTE(DWMWA_WINDOW_CORNER_PREFERENCE as i32),
        &corner_pref as *const u32 as *const c_void,
        std::mem::size_of::<u32>() as u32,
    );

    let mut s = Box::new(AppState {
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
        engine: EngineState::Loading,
        scanned_count: 0,
        threat_count: 0,
        sig_count: 0,
        scan_discovered: 0,
        scan_speed: 0.0,
        scan_mbps: 0.0,
        scan_eta_secs: 0.0,
        scan_discovering: false,
        scan_started_at: None,
        scan_elapsed: None,
        anim_frame: 0,
        anim_timer_active: false,
        hover_anim: Vec::new(),
        tray_icon_shown: false,
        work_tx,
        result_rx,
        cancel,
        abort,
        scan_rows: Vec::new(),
        scan_sev: Vec::new(),
        scan_verdict: Vec::new(),
        scan_threat: Vec::new(),
        quar_ids: Vec::new(),
        quarantine_dir,
    });
    // Start the animation timer (runs during loading and scanning).
    SetTimer(Some(hwnd), ANIM_TIMER, ANIM_INTERVAL_MS, None);
    s.anim_timer_active = true;

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
        Some(LPARAM((sty::LVS_EX_FULLROWSELECT | sty::LVS_EX_DOUBLEBUFFER | sty::LVS_EX_GRIDLINES) as isize)),
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

fn buttons_for(page: usize, state: ScanState) -> Vec<(usize, &'static str, &'static str, Kind)> {
    match page {
        // Scan page buttons depend on the scan state: while scanning, Pause +
        // Stop; while paused, Resume + Stop (Pause's label toggles to Resume).
        0 => match state {
            ScanState::Scanning => vec![
                (CMD_PAUSE, "Pause Scan", "\u{E769}", Kind::Primary),
                (CMD_STOP, "Stop Scan", "\u{E71A}", Kind::Danger),
            ],
            ScanState::Paused => vec![
                (CMD_RESUME, "Resume", "\u{E768}", Kind::Primary),
                (CMD_STOP, "Stop Scan", "\u{E71A}", Kind::Danger),
            ],
            _ => vec![
                (CMD_CUSTOM_SCAN, "Custom Scan", "\u{E721}", Kind::Primary),
                (CMD_CLEAN, "Clean Threats", "\u{E74D}", Kind::Primary),
                (CMD_SAVE_RESULTS, "Save Results", "\u{E74E}", Kind::Neutral),
            ],
        },
        1 => vec![
            (CMD_QUAR_REFRESH, "Refresh", "\u{E72C}", Kind::Neutral),
            (CMD_QUAR_RESTORE, "Restore Selected", "\u{E777}", Kind::Primary),
            (CMD_QUAR_DELETE, "Delete Selected", "\u{E74D}", Kind::Danger),
        ],
        _ => vec![
            (CMD_START_ENGINE, "Start Engine", "\u{E768}", Kind::Primary),
            (CMD_STOP_ENGINE, "Stop Engine", "\u{E71A}", Kind::Neutral),
            (CMD_CLEAR_CACHE, "Clear Result Cache", "\u{E894}", Kind::Danger),
        ],
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

    // Sidebar nav items (below the "MENU" caption).
    for (i, item) in s.nav.iter_mut().enumerate() {
        let top = NAV_TOP + i as i32 * (NAV_H + 6);
        item.rect = RECT { left: 12, top, right: SIDEBAR_W - 12, bottom: top + NAV_H };
    }

    // Theme toggle in the header (top-right).
    let tb = 36;
    let ty = (HEADER_H - tb) / 2;
    s.theme_btn = RECT { left: w - PAD - tb, top: ty, right: w - PAD, bottom: ty + tb };

    // Content buttons (wrap into rows if narrow). None while the loading screen
    // is up, so nothing under the overlay is clickable.
    let content_l = SIDEBAR_W + PAD;
    let content_r = w - PAD;
    let defs = if s.engine == EngineState::Loading {
        Vec::new()
    } else {
        buttons_for(s.page, s.scan_state)
    };
    s.buttons.clear();
    let mut x = content_l;
    // Scan page reserves a status hero banner above the action buttons.
    let mut y = HEADER_H + PAD + if s.page == 0 { HERO_H + PAD } else { 0 };
    for (cmd, label, icon, kind) in defs {
        if x + BTN_W > content_r && x > content_l {
            x = content_l;
            y += BTN_H + GAP;
        }
        s.buttons.push(UiButton {
            cmd,
            label,
            icon,
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
/// While the engine is loading the lists stay hidden so the loading screen shows.
unsafe fn apply_page(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let ready = s.engine != EngineState::Loading;
    let _ = ShowWindow(s.scan_list, if ready && s.page == 0 { SW_SHOW } else { SW_HIDE });
    let _ = ShowWindow(s.quar_list, if ready && s.page == 1 { SW_SHOW } else { SW_HIDE });
    layout(hwnd);
    if ready && s.page == 1 {
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
    // Sidebar top separator line under header.
    fill(mem, &RECT { left: 0, top: HEADER_H, right: SIDEBAR_W, bottom: HEADER_H + 1 }, t.border);
    // Compact section label.
    text(
        mem,
        "NAVIGATION",
        &RECT { left: 18, top: HEADER_H + 14, right: SIDEBAR_W - 12, bottom: HEADER_H + 30 },
        t.text2,
        s.fonts.status,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    for (i, item) in s.nav.iter().enumerate() {
        let active = s.page == item.page;
        let hot = s.hot_nav == Some(i);
        // Active: full-width rounded pill with accent tint + left 3px bar.
        if active {
            fill_round(mem, item.rect, 8, t.accent_soft);
            let bar = RECT {
                left: item.rect.left,
                top: item.rect.top + 8,
                right: item.rect.left + 3,
                bottom: item.rect.bottom - 8,
            };
            fill_round(mem, bar, 2, t.accent);
        } else if hot {
            fill_round(mem, item.rect, 8, t.nav_hot);
        }
        let icon_col = if active { t.accent } else { t.text2 };
        let txt_col = if active { t.accent } else { t.text };
        // Icon in a small accent-tinted badge when active.
        let icon_r = RECT { left: item.rect.left + 14, right: item.rect.left + 38, ..item.rect };
        if active {
            let ibadge = RECT { left: icon_r.left - 2, top: item.rect.top + 9, right: icon_r.right + 2, bottom: item.rect.bottom - 9 };
            fill_round(mem, ibadge, 6, lerp_color(t.accent_soft, t.accent, 0.18));
        }
        text(mem, item.icon, &icon_r, icon_col, s.fonts.icon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        let tr = RECT { left: item.rect.left + 44, right: item.rect.right - 8, ..item.rect };
        text(mem, item.label, &tr, txt_col, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }

    // --- Header: flat dark bar, no gradient on the sidebar portion ---
    let _head = RECT { left: 0, top: 0, right: w, bottom: HEADER_H };
    fill(mem, &RECT { left: 0, top: 0, right: SIDEBAR_W, bottom: HEADER_H }, t.header_top);
    gradient_v(mem, &RECT { left: SIDEBAR_W, top: 0, right: w, bottom: HEADER_H }, t.header_top, t.header_bot);
    // Thin accent line at bottom of header.
    fill(mem, &RECT { left: SIDEBAR_W, top: HEADER_H - 2, right: w, bottom: HEADER_H }, t.accent);
    // Bottom border across full header.
    fill(mem, &RECT { left: 0, top: HEADER_H, right: w, bottom: HEADER_H + 1 }, t.border);

    // Logo: rounded-square badge with a shield icon.
    let lsz = 38;
    let lpad = (HEADER_H - lsz) / 2;
    let logo = RECT { left: PAD, top: lpad, right: PAD + lsz, bottom: lpad + lsz };
    fill_round(mem, logo, 10, t.accent);
    text(mem, "\u{1F6E1}", &logo, WHITE, s.fonts.hero, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // App name + tagline.
    let tx = logo.right + 12;
    let title_mid = HEADER_H / 2;
    text(
        mem,
        "HydraDragon",
        &RECT { left: tx, top: title_mid - 22, right: SIDEBAR_W - PAD, bottom: title_mid },
        WHITE,
        s.fonts.title,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    text(
        mem,
        "Antivirus",
        &RECT { left: tx, top: title_mid, right: SIDEBAR_W - PAD, bottom: title_mid + 18 },
        t.header_sub,
        s.fonts.sub,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    // Right side: engine status pill + theme toggle.
    // Engine pill.
    let (dotc, elabel) = match s.engine {
        EngineState::Ready => (t.ok, "Engine ready"),
        EngineState::Loading => (t.warn, "Loading…"),
        EngineState::Stopped => (t.text2, "Stopped"),
    };
    let pill_right = s.theme_btn.left - 14;
    let pill_h = 24;
    let pill_top = (HEADER_H - pill_h) / 2;
    let pill_w = 110;
    let pill = RECT { left: pill_right - pill_w, top: pill_top, right: pill_right, bottom: pill_top + pill_h };
    fill_round(mem, pill, pill_h / 2, lerp_color(t.header_top, dotc, 0.14));
    let dot = RECT { left: pill.left + 10, top: pill_top + (pill_h / 2) - 4, right: pill.left + 18, bottom: pill_top + (pill_h / 2) + 4 };
    fill_round(mem, dot, 4, dotc);
    text(mem, elabel, &RECT { left: dot.right + 6, top: pill_top, right: pill.right - 8, bottom: pill_top + pill_h }, t.header_sub, s.fonts.status, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

    // Theme toggle button.
    let toggle_bg = if s.hot_theme {
        lerp_color(t.header_top, t.accent, 0.35)
    } else {
        lerp_color(t.header_top, WHITE, 0.08)
    };
    fill_round(mem, s.theme_btn, 8, toggle_bg);
    let toggle_glyph = if s.dark { "\u{E706}" } else { "\u{E708}" };
    text(mem, toggle_glyph, &s.theme_btn, WHITE, s.fonts.icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // --- Hero status banner (Scan page) — hidden behind the loading screen ---
    if s.page == 0 && s.engine != EngineState::Loading {
        let content_l = SIDEBAR_W + PAD;
        let hero = RECT { left: content_l, top: HEADER_H + PAD, right: w - PAD, bottom: HEADER_H + PAD + HERO_H };
        draw_shadow(mem, hero, 16, t);
        draw_hero(mem, s, hero);
    }

    // --- Buttons ---
    for b in &s.buttons {
        let hot = s.hot_cmd == Some(b.cmd);
        let down = s.down_cmd == Some(b.cmd);
        // Resolve the animated hover progress for this button (0.0–1.0).
        let anim_t = s
            .hover_anim
            .iter()
            .find(|(id, _, _)| *id == b.cmd)
            .map(|(_, entering, frame)| {
                let f = (*frame as f64) / 5.0;
                if *entering { f } else { 1.0 - f }
            })
            .unwrap_or(if hot { 1.0 } else { 0.0 });
        draw_button(mem, b, hot, down, anim_t, &s.fonts, t);
    }

    // --- Loading screen: while the engine loads, cover the content area ---
    if s.engine == EngineState::Loading {
        let content_l = SIDEBAR_W + PAD;
        let area = RECT { left: content_l, top: HEADER_H + PAD, right: w - PAD, bottom: h - STATUS_H - PAD };
        draw_shadow(mem, area, 16, t);
        fill_round(mem, area, 16, t.surface);
        frame_round(mem, area, 16, t.border);
        let cx = (area.left + area.right) / 2;
        let cy = (area.top + area.bottom) / 2;

        // Animated spinner: 12 dots rotating above the badge.
        let spinner_cx = cx;
        let spinner_cy = cy - 104;
        let spinner_r = 38;
        let dot_r = 5;
        let num_dots: i32 = 12;
        for i in 0..num_dots {
            let phase = (i as f64 / num_dots as f64) * std::f64::consts::TAU;
            let t_offset = (s.anim_frame as f64 * 0.12) * std::f64::consts::TAU;
            let brightness = ((phase - t_offset).sin() * 0.45 + 0.55).clamp(0.15, 1.0);
            let angle = (i as f64 / num_dots as f64) * std::f64::consts::TAU;
            let dx = (spinner_r as f64 * angle.cos()) as i32;
            let dy = (spinner_r as f64 * angle.sin()) as i32;
            let dot_color = lerp_color(t.text2, t.accent, brightness);
            let dot_rect = RECT {
                left: spinner_cx + dx - dot_r,
                top: spinner_cy + dy - dot_r,
                right: spinner_cx + dx + dot_r,
                bottom: spinner_cy + dy + dot_r,
            };
            fill_round(mem, dot_rect, dot_r, dot_color);
        }

        let bsz = 76;
        let badge = RECT { left: cx - bsz / 2, top: cy - bsz - 12, right: cx + bsz / 2, bottom: cy - 12 };
        fill_round(mem, badge, bsz / 2, t.accent);
        text(mem, "\u{1F6E1}", &badge, WHITE, s.fonts.hero, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        text(
            mem,
            "Loading engines…",
            &RECT { left: area.left, top: cy, right: area.right, bottom: cy + 34 },
            t.text,
            s.fonts.hero,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        text(
            mem,
            "YARA-X rules · ClamAV signatures · ML models",
            &RECT { left: area.left, top: cy + 38, right: area.right, bottom: cy + 62 },
            t.text2,
            s.fonts.body,
            DT_CENTER | DT_VCENTER | DT_SINGLELINE,
        );
        // Status bar (into the same back-buffer), then one blit.
        let status = RECT { left: 0, top: h - STATUS_H, right: w, bottom: h };
        fill(mem, &status, t.surface);
        fill(mem, &RECT { left: 0, top: h - STATUS_H, right: w, bottom: h - STATUS_H + 1 }, t.shadow);
        text(mem, &s.status, &RECT { left: PAD, top: h - STATUS_H, right: w - PAD, bottom: h }, t.text2, s.fonts.status, DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        let _ = BitBlt(hdc, 0, 0, w, h, Some(mem), 0, 0, SRCCOPY);
        SelectObject(mem, old);
        let _ = DeleteObject(bmp.into());
        let _ = DeleteDC(mem);
        let _ = EndPaint(hwnd, &ps);
        return;
    }

    // --- Content card (flat border around the active ListView / settings text) ---
    let content_l = SIDEBAR_W + PAD;
    let list_top = s.buttons.iter().map(|b| b.rect.bottom).max().unwrap_or(HEADER_H + PAD) + PAD;
    let card = RECT { left: content_l - 1, top: list_top - 1, right: w - PAD + 1, bottom: h - STATUS_H - PAD + 1 };
    draw_shadow(mem, card, 12, t);
    if s.page == 2 {
        // Settings page has no list — fill the card and show engine/version info.
        fill_round(mem, card, 12, t.surface);
        let pad = 18;
        let inner = RECT { left: card.left + pad, top: card.top + pad, right: card.right - pad, bottom: card.bottom - pad };

        // Engine status section with icon.
        let engine_icon = RECT { left: inner.left, top: inner.top + 2, right: inner.left + 28, bottom: inner.top + 30 };
        fill_round(mem, engine_icon, 14, match s.engine {
            EngineState::Ready => t.ok,
            EngineState::Loading => t.warn,
            EngineState::Stopped => t.text2,
        });
        let glyph = match s.engine {
            EngineState::Ready => "\u{E7FC}",
            EngineState::Loading => "\u{E895}",
            EngineState::Stopped => "\u{E7FC}",
        };
        text(mem, glyph, &engine_icon, WHITE, s.fonts.icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        let engine_label = RECT { left: engine_icon.right + 12, top: inner.top, right: inner.right, bottom: inner.top + 26 };
        let engine_txt = match s.engine {
            EngineState::Ready => format!("Engine ready — {} signatures", fmt_count(s.sig_count)),
            EngineState::Loading => "Engine loading…".to_string(),
            EngineState::Stopped => "Engine stopped — click Start Engine to load".to_string(),
        };
        text(mem, &engine_txt, &engine_label, t.text, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        // Separator.
        let sep_y = inner.top + 40;
        fill(mem, &RECT { left: inner.left, top: sep_y, right: inner.right, bottom: sep_y + 1 }, t.border);

        // Cache section.
        let cache_top = sep_y + 16;
        let cache_icon = RECT { left: inner.left, top: cache_top + 2, right: inner.left + 28, bottom: cache_top + 30 };
        fill_round(mem, cache_icon, 14, t.text2);
        text(mem, "\u{E752}", &cache_icon, WHITE, s.fonts.icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        let cache_label = RECT { left: cache_icon.right + 12, top: cache_top, right: inner.right, bottom: cache_top + 26 };
        text(mem, "Result cache (Bloom filters)", &cache_label, t.text, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);

        let body_top = cache_top + 34;
        let body = RECT { top: body_top, bottom: inner.bottom, ..inner };
        text(
            mem,
            "The scanner remembers every file it has already classified, so \
             repeat scans are nearly instant. “Clear Result Cache” wipes both \
             blooms — the scanner will re-scan everything from scratch.",
            &body,
            t.text2,
            s.fonts.body,
            DT_LEFT | DT_WORDBREAK,
        );

        // Context menu section.
        let cm_top = body_top + 68;
        fill(mem, &RECT { left: inner.left, top: cm_top, right: inner.right, bottom: cm_top + 1 }, t.border);
        let cm_icon = RECT { left: inner.left, top: cm_top + 18, right: inner.left + 28, bottom: cm_top + 46 };
        fill_round(mem, cm_icon, 14, t.text2);
        text(mem, "\u{E70B}", &cm_icon, WHITE, s.fonts.icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        let cm_label = RECT { left: cm_icon.right + 12, top: cm_top + 16, right: inner.right, bottom: cm_top + 42 };
        text(mem, "Explorer context menu", &cm_label, t.text, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        let cm_desc = RECT { left: inner.left, top: cm_top + 48, right: inner.right, bottom: cm_top + 72 };
        text(
            mem,
            "Add a “Scan with HydraDragonAV” entry when right-clicking files and folders in File Explorer.",
            &cm_desc, t.text2, s.fonts.body, DT_LEFT | DT_WORDBREAK,
        );
        // Button positions - buttons will be placed below this text
    }
    frame_round(mem, card, 12, t.border);

    // --- Status bar: slim, with a colored state dot ---
    let status = RECT { left: 0, top: h - STATUS_H, right: w, bottom: h };
    fill(mem, &status, t.surface);
    fill(mem, &RECT { left: 0, top: h - STATUS_H, right: w, bottom: h - STATUS_H + 1 }, t.border);
    // State dot color.
    let state_dot_c = match s.scan_state {
        ScanState::Idle => t.text2,
        ScanState::Scanning => t.accent,
        ScanState::Paused => t.warn,
        ScanState::Clean => t.ok,
        ScanState::Threats => t.danger,
    };
    let dot_cy = h - STATUS_H / 2;
    let sdot = RECT { left: PAD, top: dot_cy - 3, right: PAD + 6, bottom: dot_cy + 3 };
    fill_round(mem, sdot, 3, state_dot_c);
    text(
        mem,
        &s.status,
        &RECT { left: PAD + 12, top: h - STATUS_H, right: w - PAD, bottom: h },
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

/// Modern status hero: a gradient-backed banner with a large accent badge + italic-free
/// headline + subtitle. Uses a soft gradient of the accent color instead of a flat fill.
unsafe fn draw_hero(hdc: HDC, s: &AppState, r: RECT) {
    let t = s.theme();
    let (accent, glyph, head, sub) = match s.scan_state {
        ScanState::Idle => (
            t.accent,
            "\u{1F6E1}",
            "Ready to scan".to_string(),
            if s.sig_count > 0 {
                format!("{} signatures loaded — run a scan to check for threats.", fmt_count(s.sig_count))
            } else {
                "Run a scan to check your system for threats.".to_string()
            },
        ),
        ScanState::Scanning => (
            t.accent,
            "\u{E721}", // search
            if s.threat_count > 0 {
                format!("Scanning… {} threat(s)", s.threat_count)
            } else {
                "Scanning…".to_string()
            },
            {
                let eta = if s.scan_discovering {
                    "estimating…".to_string()
                } else {
                    format!("ETA {}", fmt_eta(s.scan_eta_secs))
                };
                format!(
                    "{}/{} files · {:.0}/s · {:.1} MB/s · {}",
                    s.scanned_count, s.scan_discovered, s.scan_speed, s.scan_mbps, eta
                )
            },
        ),
        ScanState::Paused => (
            t.warn,
            "\u{E769}", // pause
            "Scan paused".to_string(),
            format!("{} scanned · {} threat(s) — Resume to continue.", s.scanned_count, s.threat_count),
        ),
        ScanState::Clean => (
            t.ok,
            "\u{E73E}", // checkmark
            "No threats found".to_string(),
            format!("{} files scanned — your system looks clean.", s.scanned_count),
        ),
        ScanState::Threats => (
            t.danger,
            "\u{E7BA}", // warning
            format!("{} threat(s) found", s.threat_count),
            "Review the detections below, then Clean Selected.".to_string(),
        ),
    };

    // Flat surface background with subtle accent tint.
    let bg_top = lerp_color(accent, t.surface, 0.90);
    let bg_bot = lerp_color(accent, t.surface, 0.97);
    gradient_v(hdc, &r, bg_top, bg_bot);
    // 3px left accent stripe.
    let stripe_r = RECT { left: r.left, top: r.top, right: r.left + 3, bottom: r.bottom };
    fill_round(hdc, stripe_r, 0, accent);
    frame_round(hdc, r, 12, lerp_color(accent, t.border, 0.45));

    let bsize = 58;  // slightly smaller to fit the slimmer HERO_H
    let bx = r.left + 18;
    let by = r.top + (r.bottom - r.top - bsize) / 2;
    // Soft outer halo.
    let glow = RECT { left: bx - 4, top: by - 4, right: bx + bsize + 4, bottom: by + bsize + 4 };
    let glow_col = lerp_color(accent, t.surface, 0.70);
    fill_round(hdc, glow, (bsize / 2) + 4, glow_col);
    // Main badge circle.
    let badge = RECT { left: bx, top: by, right: bx + bsize, bottom: by + bsize };
    fill_round(hdc, badge, bsize / 2, accent);
    text(hdc, glyph, &badge, WHITE, s.fonts.hero_icon, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

    // A determinate progress bar shows while scanning or paused.
    let show_bar = matches!(s.scan_state, ScanState::Scanning | ScanState::Paused);
    let frac = if s.scan_discovered > 0 {
        s.scanned_count as f64 / s.scan_discovered as f64
    } else {
        0.0
    };

    let tx = badge.right + 22;
    // Lift the text a little when the bar is shown so they don't collide.
    let (head_top, sub_top, sub_bot) = if show_bar {
        (r.top + 18, r.top + 50, r.top + 74)
    } else {
        (r.top + 24, r.top + 60, r.bottom - 22)
    };
    text(
        hdc,
        &head,
        &RECT { left: tx, top: head_top, right: r.right - 20, bottom: head_top + 34 },
        t.text,
        s.fonts.hero,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );
    text(
        hdc,
        &sub,
        &RECT { left: tx, top: sub_top, right: r.right - 20, bottom: sub_bot },
        t.text2,
        s.fonts.body,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    if show_bar {
        let bar = RECT { left: tx, top: r.bottom - 20, right: r.right - 20, bottom: r.bottom - 12 };
        draw_progress_with_anim(hdc, bar, frac, s.anim_frame, t.border, accent);
        // Percentage at the right edge of the bar (skip while still discovering,
        // where the denominator is still growing and the % would be misleading).
        if !s.scan_discovering {
            text(
                hdc,
                &format!("{:.0}%", (frac * 100.0).clamp(0.0, 100.0)),
                &RECT { left: r.right - 56, top: sub_top, right: r.right - 20, bottom: sub_bot },
                t.text2,
                s.fonts.body,
                DT_RIGHT | DT_VCENTER | DT_SINGLELINE,
            );
        }
    }
}

/// A rounded determinate progress bar: a `track` background with an `accent` fill
/// proportional to `frac` (0.0–1.0). Includes an animated shimmer highlight that
/// sweeps across the filled portion for a modern look.
unsafe fn draw_progress_with_anim(hdc: HDC, r: RECT, frac: f64, anim_frame: u32, track: COLORREF, accent: COLORREF) {
    let radius = ((r.bottom - r.top) / 2).max(1);
    fill_round(hdc, r, radius, track);
    let frac = frac.clamp(0.0, 1.0);
    let w = ((r.right - r.left) as f64 * frac) as i32;
    if w > radius {
        let fr = RECT { right: r.left + w, ..r };
        fill_round(hdc, fr, radius, accent);
        // Animated shimmer: a light highlight sweeps across the filled width.
        let cycle_frames = 60u32; // ~2 seconds at 30fps
        let pos = (anim_frame % cycle_frames) as f64 / cycle_frames as f64;
        let shimmer_center = r.left + (w as f64 * pos) as i32;
        let sw = 40i32;
        let sh_left = (shimmer_center - sw / 2).max(r.left + 2);
        let sh_right = (shimmer_center + sw / 2).min(r.left + w - 2);
        if sh_right > sh_left {
            let sh = RECT { left: sh_left, top: r.top + 1, right: sh_right, bottom: r.bottom - 1 };
            let light = lerp_color(accent, WHITE, 0.3);
            fill_round(hdc, sh, radius.saturating_sub(1).max(1), light);
        }
    }
}

unsafe fn draw_button(hdc: HDC, b: &UiButton, _hot: bool, down: bool, anim_t: f64, fonts: &Fonts, t: &Theme) {
    let btn_h = b.rect.bottom - b.rect.top;
    let radius = btn_h / 2; // pill shape
    let (base, hot_c, down_c, textc) = match b.kind {
        Kind::Primary => (t.accent, t.accent_hot, t.accent_down, WHITE),
        Kind::Danger => (t.danger, t.danger_hot, t.danger_down, WHITE),
        Kind::Neutral => (t.surface, lerp_color(t.surface, t.accent_soft, 0.5), t.nav_hot, t.text),
    };
    let fillc = if down {
        down_c
    } else {
        lerp_color(base, hot_c, anim_t)
    };
    // Single subtle shadow layer only.
    let shadow_r = RECT { left: b.rect.left + 1, top: b.rect.top + 2, right: b.rect.right + 1, bottom: b.rect.bottom + 2 };
    let shadow_c = lerp_color(t.shadow, t.bg, 0.6);
    fill_round(hdc, shadow_r, radius, shadow_c);

    fill_round(hdc, b.rect, radius, fillc);

    // Neutral buttons get a 1px border.
    if b.kind == Kind::Neutral {
        frame_round(hdc, b.rect, radius, t.border);
    }
    // Subtle top highlight on primary/danger for a slight 3D lift.
    if b.kind != Kind::Neutral && !down {
        let highlight_r = RECT { left: b.rect.left + 2, top: b.rect.top + 1, right: b.rect.right - 2, bottom: b.rect.top + btn_h / 2 };
        let light = lerp_color(fillc, WHITE, 0.12);
        fill_round(hdc, highlight_r, radius.saturating_sub(1), light);
    }
    // Leading icon (small, tight to text).
    let icon_r = RECT { left: b.rect.left + 12, right: b.rect.left + 30, ..b.rect };
    text(hdc, b.icon, &icon_r, textc, fonts.icon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    let label_r = RECT { left: b.rect.left + 30, right: b.rect.right - 8, ..b.rect };
    text(hdc, b.label, &label_r, textc, fonts.button, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
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

/// Multi-layer material shadow (3 layers) for premium depth.
/// Draws an outer-soft, mid, and tight-dark shadow at increasing offsets,
/// simulating the look of modern design systems (Material, Fluent).
unsafe fn draw_shadow(hdc: HDC, r: RECT, radius: i32, t: &Theme) {
    // Layer 1 (outermost, softest): large offset, very transparent.
    let s1 = RECT { left: r.left + 2, top: r.top + 5, right: r.right + 2, bottom: r.bottom + 5 };
    let c1 = lerp_color(t.shadow, t.bg, 0.55);
    fill_round(hdc, s1, radius, c1);
    // Layer 2 (mid): medium offset, standard shadow color.
    let s2 = RECT { left: r.left + 1, top: r.top + 3, right: r.right + 1, bottom: r.bottom + 3 };
    fill_round(hdc, s2, radius, t.shadow);
    // Layer 3 (tightest, darkest): small offset, deeper shadow.
    let s3 = RECT { left: r.left, top: r.top + 1, right: r.right, bottom: r.bottom + 1 };
    let c3 = lerp_color(t.shadow, rgb(0, 0, 0), 0.12);
    fill_round(hdc, s3, radius, c3);
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
// Drag-and-drop, tray icon, animation
// ---------------------------------------------------------------------------

unsafe fn on_dropfiles(hwnd: HWND, hdrop: HDROP) {
    let Some(s) = state(hwnd) else {
        DragFinish(hdrop);
        return;
    };
    let count = DragQueryFileW(hdrop, 0xFFFFFFFF, None);
    if count == 0 {
        DragFinish(hdrop);
        return;
    }
    let mut paths: Vec<PathBuf> = Vec::new();
    for i in 0..count {
        let mut buf = vec![0u16; 260];
        let len = DragQueryFileW(hdrop, i, Some(&mut buf));
        if len > 0 {
            buf.truncate(len as usize);
            if let Ok(p) = String::from_utf16(&buf) {
                paths.push(PathBuf::from(p));
            }
        }
    }
    DragFinish(hdrop);

    if paths.is_empty() {
        return;
    }
    s.cancel.store(false, Ordering::Relaxed);
    s.abort.store(false, Ordering::Relaxed);
    lv_clear(s.scan_list);
    clear_scan_results(s);
    // Navigate to Scan page.
    if s.page != 0 {
        s.page = 0;
        apply_page(hwnd);
    }
    if paths.len() == 1 {
        s.status = format!("Scanning {}…", paths[0].display());
    } else {
        s.status = format!("Scanning {} items…", paths.len());
    }
    let _ = s.work_tx.send(WorkRequest::FullScan(paths));
}

unsafe fn show_tray_icon(_hwnd: HWND, s: &mut AppState) {
    if s.tray_icon_shown {
        return;
    }
    let hinst = GetModuleHandleW(None).unwrap_or_default();
    let hicon = LoadIconW(Some(HINSTANCE::from(hinst)), PCWSTR(1 as *const u16)).unwrap_or_default();
    let tip: Vec<u16> = "HydraDragon Antivirus".encode_utf16().collect();
    let mut nid = NOTIFYICONDATAW {
        cbSize: std::mem::size_of::<NOTIFYICONDATAW>() as u32,
        uID: ID_TRAY,
        uFlags: NOTIFY_ICON_DATA_FLAGS(0x0087), // NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_SHOWTIP
        uCallbackMessage: WM_APP_TRAY,
        hIcon: hicon,
        ..Default::default()
    };
    // Copy tip into the fixed-size array.
    for (i, &c) in tip.iter().enumerate().take(128) {
        nid.szTip[i] = c;
    }
    if Shell_NotifyIconW(NOTIFY_ICON_MESSAGE(0), &nid).as_bool() {
        s.tray_icon_shown = true;
    }
}

unsafe fn on_anim_tick(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    s.anim_frame = s.anim_frame.wrapping_add(1);
    // Advance hover animations.
    s.hover_anim.retain(|(_, entering, frame)| {
        if *entering {
            *frame < 5 // remove when fully entered (frame reaches 5)
        } else {
            *frame > 1 // keep until frame 1 to interpolate out
        }
    });
    for (_, entering, frame) in &mut s.hover_anim {
        if *entering && *frame < 5 { *frame += 1; }
        if !*entering && *frame > 0 { *frame -= 1; }
    }
    let hover_active = !s.hover_anim.is_empty();
    // Only invalidate when there is visible animation.
    if hover_active || s.engine == EngineState::Loading || matches!(s.scan_state, ScanState::Scanning) {
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

fn lerp_color(a: COLORREF, b: COLORREF, t: f64) -> COLORREF {
    let t = t.clamp(0.0, 1.0);
    let ra = (a.0 & 0xFF) as f64;
    let ga = ((a.0 >> 8) & 0xFF) as f64;
    let ba = ((a.0 >> 16) & 0xFF) as f64;
    let rb = (b.0 & 0xFF) as f64;
    let gb = ((b.0 >> 8) & 0xFF) as f64;
    let bb = ((b.0 >> 16) & 0xFF) as f64;
    COLORREF(
        (ra * (1.0 - t) + rb * t) as u32
            | ((ga * (1.0 - t) + gb * t) as u32) << 8
            | ((ba * (1.0 - t) + bb * t) as u32) << 16,
    )
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
        // Push hover-out animation for the previously hovered cmd.
        if let Some(old) = s.hot_cmd {
            if !s.hover_anim.iter().any(|(id, _, _)| *id == old) {
                s.hover_anim.push((old, false, 5));
            }
        }
        if let Some(old) = s.hot_nav {
            let id = 100 + old;
            if !s.hover_anim.iter().any(|(id2, _, _)| *id2 == id) {
                s.hover_anim.push((id, false, 5));
            }
        }
        s.hot_cmd = hot_cmd;
        s.hot_nav = hot_nav;
        s.hot_theme = hot_theme;
        // Push hover-in animation for the new hovered element.
        if let Some(new) = hot_cmd {
            if !s.hover_anim.iter().any(|(id, _, _)| *id == new) {
                s.hover_anim.push((new, true, 0));
            }
        }
        if let Some(new) = hot_nav {
            let id = 100 + new;
            if !s.hover_anim.iter().any(|(id2, _, _)| *id2 == id) {
                s.hover_anim.push((id, true, 0));
            }
        }
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
        CMD_CUSTOM_SCAN => pick_and_custom_scan(s),
        CMD_CLEAN => act_clean_and_traces(hwnd, s),
        CMD_SAVE_RESULTS => save_results(hwnd, s),
        CMD_RESCAN => rescan_selected(hwnd, s),
        CMD_COPY => copy_selected(hwnd, s),
        CMD_PAUSE => {
            // Pause: interrupt the scan but keep the remaining queue so it can be
            // resumed. Flip to the Paused toolbar immediately (the Pause button
            // becomes Resume) instead of waiting for the worker to acknowledge;
            // the worker's later `Paused` message just refreshes the counts.
            s.cancel.store(true, Ordering::Relaxed);
            s.abort.store(false, Ordering::Relaxed);
            s.scan_state = ScanState::Paused;
            s.status = "Pausing… (Resume to continue)".into();
            layout(hwnd);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }
        CMD_STOP => {
            // Stop: abort the scan and go straight back to the home menu. The
            // session is discarded (no Resume). `abort` tells the worker to drop
            // the session and emit `Stopped` instead of `Paused`.
            s.abort.store(true, Ordering::Relaxed);
            s.cancel.store(true, Ordering::Relaxed);
            s.scan_state = ScanState::Idle;
            s.status = "Scan stopped.".into();
            layout(hwnd);
            let _ = InvalidateRect(Some(hwnd), None, false);
        }
        CMD_RESUME => {
            let _ = s.work_tx.send(WorkRequest::Resume);
        }
        CMD_START_ENGINE => {
            let _ = s.work_tx.send(WorkRequest::StartEngine);
        }
        CMD_STOP_ENGINE => {
            let _ = s.work_tx.send(WorkRequest::StopEngine);
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
        CMD_SELECT_ALL => {
            lv_check_all(s.scan_list, true);
            let _ = InvalidateRect(Some(s.scan_list), None, true);
        }
        CMD_DESELECT_ALL => {
            lv_check_all(s.scan_list, false);
            let _ = InvalidateRect(Some(s.scan_list), None, true);
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
        CMD_INSTALL_MENU => {
            s.status = "Installing context menu…".into();
            let _ = InvalidateRect(Some(hwnd), None, false);
            let exe = std::env::current_exe().ok();
            if let Some(exe) = exe {
                let exe_str = exe.to_string_lossy().to_string();
                let cmd = format!("\"{}\" scan --files \"%1\"", exe_str);
                if let Ok(()) = install_context_menu_impl(&cmd) {
                    s.status = "Context menu installed.".into();
                } else {
                    s.status = "Failed to install context menu.".into();
                }
            } else {
                s.status = "Cannot locate executable.".into();
            }
            let _ = InvalidateRect(Some(hwnd), None, false);
        }
        CMD_UNINSTALL_MENU => {
            s.status = "Removing context menu…".into();
            let _ = InvalidateRect(Some(hwnd), None, false);
            if uninstall_context_menu_impl().is_ok() {
                s.status = "Context menu removed.".into();
            } else {
                s.status = "Failed to remove context menu.".into();
            }
            let _ = InvalidateRect(Some(hwnd), None, false);
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
    let item_count = SendMessageW(s.scan_list, msg::LVM_GETITEMCOUNT, None, None).0;
    if item_count == 0 {
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
    let _ = AppendMenuW(menu, MF_STRING, CMD_SELECT_ALL, w!("Select All"));
    let _ = AppendMenuW(menu, MF_STRING, CMD_DESELECT_ALL, w!("Deselect All"));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, CMD_RESCAN, w!("Rescan Selected"));
    let _ = AppendMenuW(menu, MF_STRING, CMD_COPY, w!("Copy"));
    let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
    let _ = AppendMenuW(menu, MF_STRING, CMD_CLEAN, w!("Clean Checked"));
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

fn install_context_menu_impl(cmd: &str) -> std::io::Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes = hkcu.open_subkey_with_flags("Software\\Classes", KEY_WRITE)?;
    let (fs, _) = classes.create_subkey("*\\shell\\HydraDragonAV")?;
    fs.set_value("", &"Scan with HydraDragonAV")?;
    fs.set_value("Icon", &cmd)?;
    let (fc, _) = fs.create_subkey("command")?;
    fc.set_value("", &cmd)?;
    let (ds, _) = classes.create_subkey("Directory\\shell\\HydraDragonAV")?;
    ds.set_value("", &"Scan with HydraDragonAV")?;
    ds.set_value("Icon", &cmd)?;
    let (dc, _) = ds.create_subkey("command")?;
    dc.set_value("", &cmd)?;
    Ok(())
}

fn uninstall_context_menu_impl() -> std::io::Result<()> {
    use winreg::enums::*;
    use winreg::RegKey;
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let classes = hkcu.open_subkey_with_flags("Software\\Classes", KEY_WRITE)?;
    let _ = classes.delete_subkey_all("*\\shell\\HydraDragonAV");
    let _ = classes.delete_subkey_all("Directory\\shell\\HydraDragonAV");
    Ok(())
}

unsafe fn pick_and_custom_scan(s: &mut AppState) {
    // Pick file or folder
    if let Some(path) = pick_path(true) {
        s.cancel.store(false, Ordering::Relaxed);
        s.abort.store(false, Ordering::Relaxed);
        lv_clear(s.scan_list);
        clear_scan_results(s);
        s.status = format!("Scanning {}…", path.display());
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
        0..=10 => "Info",
        11..=30 => "Low",
        31..=50 => "Moderate",
        51..=70 => "Elevated",
        71..=90 => "High",
        _ => "Critical",
    }
}

fn sev_color(t: &Theme, sev: u8) -> COLORREF {
    if sev >= 80 { t.danger }
    else if sev >= 55 { t.warn }
    else if sev >= 30 { t.accent }
    else { t.ok }
}

/// Quote a CSV field only when it contains a delimiter/quote/newline, doubling
/// any embedded quotes (RFC 4180).
/// Human-readable scan duration, e.g. `850ms`, `12.3s`, `2m 05s`.
fn fmt_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{}ms", d.as_millis())
    } else if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        let m = (secs / 60.0).floor() as u64;
        let s = secs - (m as f64) * 60.0;
        format!("{m}m {s:04.1}s")
    }
}

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
    let dur = s
        .scan_elapsed
        .map(|d| format!(", scan time {}", fmt_duration(d)))
        .unwrap_or_default();
    if txt {
        out.push_str("HydraDragon Antivirus — scan results\r\n");
        out.push_str(&format!(
            "{} file(s) scanned, {} threat(s) found{dur}\r\n\r\n",
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
            "# {} file(s) scanned, {} threat(s) found{dur}\r\n",
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

/// United "Clean & Remove Traces": neutralize/quarantine the checked detections
/// AND remove their Windows traces, behind a single confirmation.
unsafe fn act_clean_and_traces(hwnd: HWND, s: &mut AppState) {
    let paths: Vec<PathBuf> = lv_checked(s.scan_list)
        .into_iter()
        .filter_map(|i| s.scan_rows.get(i as usize).cloned())
        .collect();
    if paths.is_empty() {
        set_status(hwnd, s, "Check one or more detected files first.");
        return;
    }
    let prompt = format!(
        "Clean {} checked file(s) AND remove their Windows traces?\n\
         Matched regions are neutralized in place (a .bak is kept) or the file is \
         quarantined; a System Restore Point and per-key .reg backups are created first.",
        paths.len()
    );
    if confirm(hwnd, &prompt) {
        // Clean first, then remove traces — both run on the worker thread.
        let _ = s.work_tx.send(WorkRequest::Clean(paths.clone()));
        let _ = s.work_tx.send(WorkRequest::RemoveTraces(paths));
    }
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
                s.scan_started_at = Some(Instant::now());
                s.scan_elapsed = None;
                s.scanned_count = 0;
                s.threat_count = 0;
                s.scan_discovered = 0;
                s.scan_speed = 0.0;
                s.scan_mbps = 0.0;
                s.scan_eta_secs = 0.0;
                s.scan_discovering = true;
                s.status = "Discovering & scanning…".into();
            }
            ScanMsg::Progress { scanned, threats, discovered, speed, mbps, eta_secs, discovering, current } => {
                // Once the user has hit Pause/Stop, ignore in-flight Progress
                // ticks — otherwise a late tick flips the UI back to "Scanning"
                // (the Stop/Pause toolbar) after we've already gone to Paused/home.
                if s.cancel.load(Ordering::Relaxed) {
                    continue;
                }
                s.scan_state = ScanState::Scanning;
                s.scanned_count = scanned;
                s.threat_count = threats;
                s.scan_discovered = discovered;
                s.scan_speed = speed;
                s.scan_mbps = mbps;
                s.scan_eta_secs = eta_secs;
                s.scan_discovering = discovering;
                // Status bar shows the file currently being scanned; the hero
                // banner shows the throughput stats.
                s.status = if current.is_empty() {
                    "Discovering & scanning…".to_string()
                } else {
                    format!("Scanning: {current}")
                };
            }
            ScanMsg::Done { scanned, threats } => {
                s.scanned_count = scanned;
                s.threat_count = threats;
                s.scan_elapsed = s.scan_started_at.map(|t| t.elapsed());
                s.scan_state = if threats > 0 { ScanState::Threats } else { ScanState::Clean };
                let dur = s
                    .scan_elapsed
                    .map(|d| format!(" in {}", fmt_duration(d)))
                    .unwrap_or_default();
                s.status = format!("Done. {scanned} scanned, {threats} threat(s){dur}.");
            }
            ScanMsg::Paused { scanned, threats, remaining } => {
                s.scanned_count = scanned;
                s.threat_count = threats;
                s.scan_state = ScanState::Paused;
                s.status = format!("Paused. {scanned} scanned, {remaining} remaining — Resume to continue.");
            }
            ScanMsg::Stopped => {
                // Aborted scan: session was discarded; return to the home menu.
                s.scan_state = ScanState::Idle;
                s.status = "Scan stopped.".into();
            }
            ScanMsg::Resumed => {
                s.scan_state = ScanState::Scanning;
                s.status = "Resuming…".into();
            }
            ScanMsg::EngineLoading => {
                s.engine = EngineState::Loading;
                s.status = "Loading engines…".into();
                apply_page(hwnd); // hides the lists so the loading screen shows
            }
            ScanMsg::EngineReady { signatures } => {
                s.engine = EngineState::Ready;
                s.sig_count = signatures;
                s.status = format!("Engine ready — {} signatures loaded.", fmt_count(signatures));
                apply_page(hwnd); // reveals the active page's list
            }
            ScanMsg::EngineStopped => {
                s.engine = EngineState::Stopped;
                s.status = "Engine stopped — a scan will start it again.".into();
                apply_page(hwnd);
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

/// Return the indices of all checked (checkbox-ticked) rows. Each row's state
/// image index is stored in bits 12-15 of the item state (1 = unchecked, 2 = checked).
unsafe fn lv_checked(list: HWND) -> Vec<i32> {
    let mut out = Vec::new();
    let count = SendMessageW(list, msg::LVM_GETITEMCOUNT, None, None).0 as i32;
    for i in 0..count {
        let state = SendMessageW(
            list,
            msg::LVM_GETITEMSTATE,
            Some(WPARAM(i as usize)),
            Some(LPARAM(LVIS_STATEIMAGEMASK as isize)),
        )
        .0;
        if (state >> 12) == 2 {
            out.push(i);
        }
    }
    out
}

/// Set the checkbox state of one row (true = checked, false = unchecked).
unsafe fn lv_set_check(list: HWND, index: i32, checked: bool) {
    let state = if checked {
        LIST_VIEW_ITEM_STATE_FLAGS(0x2000)
    } else {
        LIST_VIEW_ITEM_STATE_FLAGS(0x1000)
    };
    let item = LVITEMW {
        stateMask: LIST_VIEW_ITEM_STATE_FLAGS(0xF000),
        state,
        iItem: index,
        ..Default::default()
    };
    SendMessageW(
        list,
        msg::LVM_SETITEMSTATE,
        Some(WPARAM(index as usize)),
        Some(LPARAM(&item as *const _ as isize)),
    );
}

/// Check or uncheck every row in the list.
unsafe fn lv_check_all(list: HWND, checked: bool) {
    let count = SendMessageW(list, msg::LVM_GETITEMCOUNT, None, None).0 as i32;
    for i in 0..count {
        lv_set_check(list, i, checked);
    }
}

/// Color scan rows by severity and draw a small severity bar in the Verdict column.
unsafe fn on_list_customdraw(hwnd: HWND, cd: *mut NMLVCUSTOMDRAW) -> isize {
    let cd = &mut *cd;
    match cd.nmcd.dwDrawStage.0 {
        CDDS_PREPAINT => CDRF_NOTIFYITEMDRAW,
        CDDS_ITEMPREPAINT => {
            let item = cd.nmcd.dwItemSpec;
            if let Some(s) = state(hwnd) {
                let t = s.theme();
                let sev = s.scan_sev.get(item).copied().unwrap_or(0);
                cd.clrText = sev_color(t, sev);
                // Zebra striping for readability.
                cd.clrTextBk = if item % 2 == 0 { t.surface } else { t.stripe };
            }
            // Ask for post-paint so we can draw the severity bar over the Verdict cell.
            CDRF_NEWFONT | CDRF_NOTIFYPOSTPAINT
        }
        x if x == CDDS_ITEMPOSTPAINT => {
            let item = cd.nmcd.dwItemSpec;
            let hdc = cd.nmcd.hdc;
            let list_hwnd = cd.nmcd.hdr.hwndFrom;
            if let Some(s) = state(hwnd) {
                let t = s.theme();
                let sev = s.scan_sev.get(item).copied().unwrap_or(0);
                // Get the bounding rect of subitem 1 (Verdict column).
                let mut rc = RECT { left: 0, top: 1, right: 0, bottom: 0 };
                SendMessageW(
                    list_hwnd,
                    msg::LVM_GETSUBITEMRECT,
                    Some(WPARAM(item)),
                    Some(LPARAM(&mut rc as *mut RECT as isize)),
                );
                if rc.right > rc.left + 4 {
                    // Severity bar: horizontal colored bar with width proportional to score.
                    let bar_h = 14i32;
                    let max_w = 64i32;
                    let cell_h = rc.bottom - rc.top;
                    let py = rc.top + (cell_h - bar_h) / 2;
                    let bar_left = rc.left + 4;
                    let bar_top = py;
                    // Background track
                    let track = RECT { left: bar_left, top: bar_top, right: bar_left + max_w, bottom: bar_top + bar_h };
                    fill_round(hdc, track, 3, t.surface);
                    // Fill portion
                    if sev > 0 {
                        let fill_w = ((max_w as u16).saturating_sub(2) as u32 * sev as u32 / 100).min(max_w as u32 - 2) as i32;
                        let fill = RECT { left: bar_left + 1, top: bar_top + 1, right: bar_left + 1 + fill_w, bottom: bar_top + bar_h - 1 };
                        fill_round(hdc, fill, 2, sev_color(t, sev));
                    }
                    // Score label
                    let label = format!("{}", sev);
                    let lr = RECT { left: bar_left + max_w + 4, top: rc.top, right: rc.right - 2, bottom: rc.bottom };
                    text(hdc, &label, &lr, t.text2, s.fonts.status, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
                }
            }
            CDRF_DODEFAULT
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
    abort: Arc<AtomicBool>,
) {
    let hwnd = HWND(raw as *mut c_void);
    let mut pipeline: Option<Pipeline> = None;
    let mut session: Option<ScanSession> = None;

    while let Ok(req) = work_rx.recv() {
        match req {
            WorkRequest::FullScan(paths) => {
                send(&tx, hwnd, ScanMsg::Begin);
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                session = Some(seed_session(&paths, true));
                let completed = run_session(pl, session.as_mut().unwrap(), &cancel, &abort, &tx, hwnd);
                if completed {
                    session = None;
                }
            }
            WorkRequest::StartEngine => {
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                // Idempotent confirm so the indicator flips to Ready even if it
                // was already loaded.
                let signatures = pl.loaded_signature_count();
                send(&tx, hwnd, ScanMsg::EngineReady { signatures });
            }
            WorkRequest::StopEngine => {
                if let Some(pl) = pipeline.as_ref() {
                    pl.save_result_caches(); // persist learned results before unloading
                }
                pipeline = None; // drop frees the rules/models/db memory
                session = None; // a stopped engine has no scan to resume
                send(&tx, hwnd, ScanMsg::EngineStopped);
            }
            WorkRequest::Resume => {
                if let Some(sess) = session.as_mut() {
                    send(&tx, hwnd, ScanMsg::Resumed);
                    let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                    let completed = run_session(pl, sess, &cancel, &abort, &tx, hwnd);
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
                        sev: match prio {
                            0..=1 => 0,
                            2 => 30,
                            3 => 50,
                            4 => 75,
                            _ => 100,
                        },
                        threat_found,
                    });
                }
                send(&tx, hwnd, ScanMsg::Status(format!("Rescan complete ({n} file(s)).")));
            }
            WorkRequest::Clean(paths) => {
                use hydradragonav::restart_disinfect::{escalated_disinfect, reboot_for_disinfection, EscalationOutcome};
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                let mut restart_pending: Vec<(PathBuf, String)> = Vec::new();
                for path in &paths {
                    let arenas = pl.arenas_for_file(path);
                    let line = match disinfector::disinfect_file(path, &arenas, &quarantine_dir) {
                        DisinfectOutcome::Neutralized { bytes, .. } => format!("neutralized {bytes} byte(s) in {}", path.display()),
                        DisinfectOutcome::Quarantined { to } => format!("quarantined {} -> {}", path.display(), to.display()),
                        DisinfectOutcome::Failed { reason } => {
                            // Locked/critical/driver: escalate (kill process or stop+
                            // delete a .sys service; clear critical flag; else defer to
                            // reboot). Don't reboot here — confirm with the user after.
                            match escalated_disinfect(path, &quarantine_dir, "GUI disinfect", false) {
                                EscalationOutcome::Quarantined => format!("quarantined (escalated) {}", path.display()),
                                EscalationOutcome::KilledAndQuarantined(n) => format!("stopped {n} blocker(s), quarantined {}", path.display()),
                                EscalationOutcome::ScheduledForRestart { detail, .. } => {
                                    restart_pending.push((path.clone(), detail.clone()));
                                    format!("deferred to restart: {} ({detail})", path.display())
                                }
                                EscalationOutcome::Failed(e) => format!("FAILED {}: {reason}; escalation: {e}", path.display()),
                            }
                        }
                    };
                    send(&tx, hwnd, ScanMsg::Status(line));
                }
                // If anything was deferred to reboot, ask the user to restart now.
                if !restart_pending.is_empty() {
                    let msg = format!(
                        "{} threat(s) could not be removed while running and were scheduled for cleanup at the next restart (a RunOnce task will finish the job).\r\n\r\nRestart this computer now to complete disinfection?",
                        restart_pending.len()
                    );
                    if unsafe { confirm(hwnd, &msg) } {
                        match reboot_for_disinfection("GUI disinfect") {
                            Ok(_) => send(&tx, hwnd, ScanMsg::Status("Restarting in 30s to finish disinfection (run 'shutdown /a' to cancel).".into())),
                            Err(e) => send(&tx, hwnd, ScanMsg::Status(format!("Restart failed (run as admin): {e}"))),
                        }
                    } else {
                        send(&tx, hwnd, ScanMsg::Status("Restart skipped — cleanup will run automatically at next boot.".into()));
                    }
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
    abort: &AtomicBool,
    tx: &Sender<ScanMsg>,
    hwnd: HWND,
) -> bool {
    cancel.store(false, Ordering::Relaxed);
    abort.store(false, Ordering::Relaxed);
    let completed = run_streaming(pl, sess, cancel, tx, hwnd);
    pl.save_result_caches(); // persist learned good/bad results either way

    if !completed {
        // Interrupted: Stop (abort) discards the session and returns home;
        // Pause keeps the remaining queue so it can be resumed.
        if abort.load(Ordering::Relaxed) {
            send(tx, hwnd, ScanMsg::Stopped);
            return true; // drop the session — no resume
        }
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
                sev: if e.static_match { 80 } else { 35 },
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
            sev: 85,
        });
    }

    send(tx, hwnd, ScanMsg::Status("Full scan: process memory…".into()));
    let mem = memory_scanner::scan_process_memory(pl);
    for d in &mem {
        let prio = d.verdict.priority();
        send(tx, hwnd, ScanMsg::Row {
            file: format!("{} (pid {}) @ 0x{:x}", d.process, d.pid, d.address),
            verdict: d.verdict.label().to_string(),
            threat: d.threat_name.clone(),
            sev: match prio {
                2 => 30,
                3 => 50,
                4 => 75,
                _ => 100,
            },
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
    let bytes = AtomicU64::new(0); // bytes scanned this run, for MB/s
    let current = Mutex::new(String::new()); // a sampled "now scanning" path
    let discovery_done = AtomicBool::new(false);
    let scanned_at_start = sess.scanned;

    let raw = hwnd.0 as isize; // HWND isn't Send; rebuild it inside each thread
    let nconsumers = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).max(1);

    let dirs_ref = &dirs;
    let files_ref = &files;
    let discovered_ref = &discovered;
    let scanned_ref = &scanned;
    let threats_ref = &threats;
    let bytes_ref = &bytes;
    let current_ref = &current;
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
                    if let Ok(mut c) = current_ref.lock() {
                        *c = file.display().to_string();
                    }
                    let sz = std::fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
                    let r = pl.scan_file_cached(&file);
                    scanned_ref.fetch_add(1, Ordering::Relaxed);
                    bytes_ref.fetch_add(sz, Ordering::Relaxed);
                    let prio = r.verdict.priority(); // Trusted=0, Clean=1, Pua=2, Suspicious=3, Phishing=4, Malware=5
                    let threat_found = prio > 1;
                    if threat_found {
                        threats_ref.fetch_add(1, Ordering::Relaxed);
                        let sev = match prio {
                            2 => 30,
                            3 => 50,
                            4 => 75,
                            _ => 100,
                        };
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
                let bytes_now = bytes_ref.load(Ordering::Relaxed) as f64;
                let mbps = if elapsed > 0.0 { bytes_now / (1024.0 * 1024.0) / elapsed } else { 0.0 };
                let remaining = discovered_now.saturating_sub(scanned_now);
                let eta_secs = if speed > 0.0 { remaining as f64 / speed } else { 0.0 };
                let cur = current_ref.lock().map(|c| c.clone()).unwrap_or_default();
                send(&txc, hwnd, ScanMsg::Progress {
                    scanned: scanned_now,
                    threats: threats_now,
                    discovered: discovered_now,
                    speed,
                    mbps,
                    eta_secs,
                    discovering: !done,
                    current: cur,
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
        // Drives the loading screen: EngineLoading → (blocking load) → EngineReady.
        send(tx, hwnd, ScanMsg::EngineLoading);
        let pipeline = Pipeline::new(default_config());
        let signatures = pipeline.loaded_signature_count();
        *pl = Some(pipeline);
        send(tx, hwnd, ScanMsg::EngineReady { signatures });
    }
    pl.as_ref().unwrap()
}

/// Format a count with thousands separators, e.g. 520134 -> "520,134".
fn fmt_count(n: usize) -> String {
    let s = n.to_string();
    let len = s.len();
    let mut out = String::with_capacity(len + len / 3);
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && (len - i) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
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
