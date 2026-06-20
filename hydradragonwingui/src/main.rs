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

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use hydradragonav::disinfector::{self, DisinfectOutcome};
use hydradragonav::memory_scanner;
use hydradragonav::pipeline::{scan_hayabusa_once, Pipeline, PipelineConfig};
use hydradragonav::quarantine::Quarantine;
use hydradragonav::registry_scanner::RegistryScanner;
use hydradragonav::remediation;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{COLORREF, HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::*;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, LVCF_SUBITEM, LVCF_TEXT,
    LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVITEMW, NMHDR, NMLVCUSTOMDRAW,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    ReleaseCapture, SetCapture, TrackMouseEvent, TME_LEAVE, TRACKMOUSEEVENT,
};
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, IShellItem, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
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

const WM_APP_RESULT: u32 = WM_APP + 1;
// Not surfaced by the WindowsAndMessaging glob in this build — define it raw, or
// its match arm silently becomes a catch-all binding.
const WM_MOUSELEAVE: u32 = 0x02A3;

const HEADER_H: i32 = 68;
const SIDEBAR_W: i32 = 210;
const STATUS_H: i32 = 30;
const PAD: i32 = 16;
const BTN_W: i32 = 150;
const BTN_H: i32 = 38;
const GAP: i32 = 10;
const NAV_H: i32 = 46;

mod msg {
    pub const LVM_FIRST: u32 = 0x1000;
    pub const LVM_SETBKCOLOR: u32 = LVM_FIRST + 1;
    pub const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;
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
const C_BG: COLORREF = rgb(0xF4, 0xF5, 0xF8);
const C_HEADER_SUB: COLORREF = rgb(0x9F, 0xB0, 0xCC);
const C_SIDEBAR: COLORREF = rgb(0xFF, 0xFF, 0xFF);
const C_BORDER: COLORREF = rgb(0xE3, 0xE6, 0xEC);
const C_TEXT: COLORREF = rgb(0x14, 0x1A, 0x24);
const C_TEXT2: COLORREF = rgb(0x6B, 0x72, 0x80);
const C_ACCENT: COLORREF = rgb(0x2D, 0x6C, 0xF6);
const C_ACCENT_HOT: COLORREF = rgb(0x4B, 0x82, 0xF8);
const C_ACCENT_DOWN: COLORREF = rgb(0x1F, 0x57, 0xD6);
const C_NAV_HOT: COLORREF = rgb(0xF1, 0xF3, 0xF7);
const C_DANGER: COLORREF = rgb(0xD8, 0x2C, 0x2C);
const C_DANGER_HOT: COLORREF = rgb(0xE5, 0x48, 0x48);
const C_DANGER_DOWN: COLORREF = rgb(0xB7, 0x20, 0x20);
const C_WARN: COLORREF = rgb(0xC2, 0x7A, 0x06);
const C_WHITE: COLORREF = rgb(0xFF, 0xFF, 0xFF);
// Header vertical gradient + depth/striping accents.
const C_HEADER_TOP: COLORREF = rgb(0x27, 0x36, 0x57);
const C_HEADER_BOT: COLORREF = rgb(0x12, 0x19, 0x2A);
const C_SHADOW: COLORREF = rgb(0xDD, 0xE1, 0xE9);
const C_STRIPE: COLORREF = rgb(0xF7, 0xF8, 0xFB);
// Hero status banner tints (Kaspersky-style colored state panel).
const C_OK: COLORREF = rgb(0x15, 0x9A, 0x52);
const C_OK_SOFT: COLORREF = rgb(0xE7, 0xF6, 0xEC);
const C_DANGER_SOFT: COLORREF = rgb(0xFD, 0xEC, 0xEC);
const C_ACCENT_SOFT: COLORREF = rgb(0xEC, 0xF2, 0xFE);

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
    Progress { scanned: usize, threats: usize },
    Done { scanned: usize, threats: usize },
}

enum WorkRequest {
    Scan(Vec<PathBuf>),
    /// Full mode: in-memory file scan of the path + registry + Windows event logs.
    FullScan(Vec<PathBuf>),
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
    tracking: bool,
    status: String,
    scan_state: ScanState,
    scanned_count: usize,
    threat_count: usize,
    work_tx: Sender<WorkRequest>,
    result_rx: Receiver<ScanMsg>,
    scan_rows: Vec<PathBuf>,
    scan_sev: Vec<u8>,
    quar_ids: Vec<String>,
    quarantine_dir: PathBuf,
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

    let (work_tx, work_rx) = channel::<WorkRequest>();
    let (result_tx, result_rx) = channel::<ScanMsg>();
    let quarantine_dir = exe_dir().join("quarantine");
    let qdir = quarantine_dir.clone();
    let raw = hwnd.0 as isize;
    std::thread::spawn(move || worker(raw, work_rx, result_tx, qdir));

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
        tracking: false,
        status: "Ready.".into(),
        scan_state: ScanState::Idle,
        scanned_count: 0,
        threat_count: 0,
        work_tx,
        result_rx,
        scan_rows: Vec::new(),
        scan_sev: Vec::new(),
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
    SendMessageW(h, msg::LVM_SETBKCOLOR, Some(WPARAM(0)), Some(LPARAM(C_WHITE.0 as isize)));
    SendMessageW(h, msg::LVM_SETTEXTBKCOLOR, Some(WPARAM(0)), Some(LPARAM(C_WHITE.0 as isize)));
    SendMessageW(h, msg::LVM_SETTEXTCOLOR, Some(WPARAM(0)), Some(LPARAM(C_TEXT.0 as isize)));
    SendMessageW(h, WM_SETFONT, Some(WPARAM(font.0 as usize)), Some(LPARAM(1)));
    h
}

fn buttons_for(page: usize) -> Vec<(usize, &'static str, Kind)> {
    match page {
        0 => vec![
            (CMD_SCAN_FILE, "Scan File", Kind::Primary),
            (CMD_SCAN_FOLDER, "Scan Folder", Kind::Primary),
            (CMD_FULL_SCAN, "Full Scan", Kind::Primary),
            (CMD_CLEAN, "Clean Selected", Kind::Primary),
            (CMD_TRACES, "Remove Traces", Kind::Danger),
        ],
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

    // Content buttons (wrap into rows if narrow).
    let content_l = SIDEBAR_W + PAD;
    let content_r = w - PAD;
    let defs = buttons_for(s.page);
    s.buttons.clear();
    let mut x = content_l;
    let mut y = HEADER_H + PAD;
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

    fill(mem, &rc, C_BG);

    // --- Sidebar ---
    let side = RECT { left: 0, top: 0, right: SIDEBAR_W, bottom: h };
    fill(mem, &side, C_SIDEBAR);
    fill(mem, &RECT { left: SIDEBAR_W - 1, top: 0, right: SIDEBAR_W, bottom: h }, C_BORDER);
    for (i, item) in s.nav.iter().enumerate() {
        let active = s.page == item.page;
        let hot = s.hot_nav == Some(i);
        if active {
            fill_round(mem, item.rect, 10, C_ACCENT); // full accent pill
        } else if hot {
            fill_round(mem, item.rect, 10, C_NAV_HOT);
        }
        let icon_col = if active { C_WHITE } else { C_ACCENT };
        let txt_col = if active { C_WHITE } else { C_TEXT };
        let icon_r = RECT { left: item.rect.left + 14, right: item.rect.left + 42, ..item.rect };
        text(mem, item.icon, &icon_r, icon_col, s.fonts.icon, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
        let tr = RECT { left: item.rect.left + 46, ..item.rect };
        text(mem, item.label, &tr, txt_col, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
    }

    // --- Header (vertical gradient + thin drop shadow) ---
    let head = RECT { left: 0, top: 0, right: w, bottom: HEADER_H };
    gradient_v(mem, &head, C_HEADER_TOP, C_HEADER_BOT);
    fill(mem, &RECT { left: 0, top: HEADER_H, right: w, bottom: HEADER_H + 1 }, C_SHADOW);
    let logo = RECT { left: PAD, top: (HEADER_H - 40) / 2, right: PAD + 40, bottom: (HEADER_H - 40) / 2 + 40 };
    fill_round(mem, logo, 11, C_ACCENT);
    text(mem, "\u{E83D}", &logo, C_WHITE, s.fonts.icon_lg, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
    let tx = logo.right + 14;
    text(
        mem,
        "HydraDragon Antivirus",
        &RECT { left: tx, top: 12, right: w - PAD, bottom: 38 },
        C_WHITE,
        s.fonts.title,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );
    text(
        mem,
        "Portable malware scanner",
        &RECT { left: tx, top: 38, right: w - PAD, bottom: 58 },
        C_HEADER_SUB,
        s.fonts.sub,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE,
    );

    // --- Buttons ---
    for b in &s.buttons {
        let hot = s.hot_cmd == Some(b.cmd);
        let down = s.down_cmd == Some(b.cmd);
        draw_button(mem, b, hot, down, &s.fonts);
    }

    // --- Content card (flat border around the active ListView / settings text) ---
    let content_l = SIDEBAR_W + PAD;
    let list_top = s.buttons.iter().map(|b| b.rect.bottom).max().unwrap_or(HEADER_H + PAD) + PAD;
    let card = RECT { left: content_l - 1, top: list_top - 1, right: w - PAD + 1, bottom: h - STATUS_H - PAD + 1 };
    if s.page == 2 {
        // Settings page has no list — fill the card and explain the cache.
        fill_round(mem, card, 8, C_WHITE);
        let pad = 18;
        let inner = RECT { left: card.left + pad, top: card.top + pad, right: card.right - pad, bottom: card.bottom - pad };
        text(mem, "Result cache", &RECT { bottom: inner.top + 26, ..inner }, C_TEXT, s.fonts.nav, DT_LEFT | DT_VCENTER | DT_SINGLELINE);
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
            C_TEXT2,
            s.fonts.body,
            DT_LEFT | DT_WORDBREAK,
        );
    }
    frame_round(mem, card, 8, C_BORDER);

    // --- Status bar ---
    let status = RECT { left: 0, top: h - STATUS_H, right: w, bottom: h };
    fill(mem, &status, C_WHITE);
    fill(mem, &RECT { left: 0, top: h - STATUS_H, right: w, bottom: h - STATUS_H + 1 }, C_SHADOW);
    text(
        mem,
        &s.status,
        &RECT { left: PAD, top: h - STATUS_H, right: w - PAD, bottom: h },
        C_TEXT2,
        s.fonts.status,
        DT_LEFT | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
    );

    let _ = BitBlt(hdc, 0, 0, w, h, Some(mem), 0, 0, SRCCOPY);
    SelectObject(mem, old);
    let _ = DeleteObject(bmp.into());
    let _ = DeleteDC(mem);
    let _ = EndPaint(hwnd, &ps);
}

unsafe fn draw_button(hdc: HDC, b: &UiButton, hot: bool, down: bool, fonts: &Fonts) {
    let (fillc, textc) = match b.kind {
        Kind::Primary => (
            if down { C_ACCENT_DOWN } else if hot { C_ACCENT_HOT } else { C_ACCENT },
            C_WHITE,
        ),
        Kind::Danger => (
            if down { C_DANGER_DOWN } else if hot { C_DANGER_HOT } else { C_DANGER },
            C_WHITE,
        ),
        Kind::Neutral => (if down { C_NAV_HOT } else if hot { C_BG } else { C_WHITE }, C_TEXT),
    };
    fill_round(hdc, b.rect, 9, fillc);
    if b.kind == Kind::Neutral {
        frame_round(hdc, b.rect, 9, C_BORDER);
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
    if hot_cmd != s.hot_cmd || hot_nav != s.hot_nav {
        s.hot_cmd = hot_cmd;
        s.hot_nav = hot_nav;
        let _ = InvalidateRect(Some(hwnd), None, false);
    }
}

unsafe fn on_lbutton_down(hwnd: HWND, (x, y): (i32, i32)) {
    let Some(s) = state(hwnd) else { return };
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
        s.scan_rows.clear();
        s.scan_sev.clear();
        s.status = format!("Scanning {}…", path.display());
        let _ = s.work_tx.send(WorkRequest::Scan(vec![path]));
    }
}

/// Full mode: pick a folder, then scan its files (in memory) + registry + logs.
unsafe fn pick_and_full_scan(s: &mut AppState) {
    if let Some(path) = pick_path(true) {
        lv_clear(s.scan_list);
        s.scan_rows.clear();
        s.scan_sev.clear();
        s.status = format!("Full scan: {} + registry + logs…", path.display());
        let _ = s.work_tx.send(WorkRequest::FullScan(vec![path]));
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
    let mut changed = false;
    while let Ok(m) = s.result_rx.try_recv() {
        changed = true;
        match m {
            ScanMsg::Row { file, verdict, threat, sev } => {
                lv_add_row(s.scan_list, &[&file, &verdict, &threat]);
                s.scan_rows.push(PathBuf::from(file));
                s.scan_sev.push(sev);
            }
            ScanMsg::Status(t) => s.status = t,
        }
    }
    if changed {
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
                let sev = s.scan_sev.get(item).copied().unwrap_or(0);
                cd.clrText = match sev {
                    2 => C_DANGER,
                    1 => C_WARN,
                    _ => C_TEXT,
                };
            }
            // Zebra striping for readability.
            cd.clrTextBk = if item % 2 == 0 { C_WHITE } else { C_STRIPE };
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

// ---------------------------------------------------------------------------
// Background worker
// ---------------------------------------------------------------------------

fn worker(raw: isize, work_rx: Receiver<WorkRequest>, tx: Sender<ScanMsg>, quarantine_dir: PathBuf) {
    let hwnd = HWND(raw as *mut c_void);
    let mut pipeline: Option<Pipeline> = None;

    while let Ok(req) = work_rx.recv() {
        match req {
            WorkRequest::Scan(paths) => {
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                let (scanned, threats) = scan_paths(pl, &paths, &tx, hwnd);
                pl.save_result_caches(); // persist learned good/bad results
                send(&tx, hwnd, ScanMsg::Status(format!("Done. {scanned} scanned, {threats} threat(s).")));
            }
            WorkRequest::FullScan(paths) => {
                // Full mode = memory (in-memory file scan) + registry + logs.
                let pl = ensure_pipeline(&mut pipeline, &tx, hwnd);
                let (scanned, threats) = scan_paths(pl, &paths, &tx, hwnd);
                pl.save_result_caches();

                send(&tx, hwnd, ScanMsg::Status("Full scan: registry…".into()));
                let reg = RegistryScanner::default().scan();
                for e in &reg.entries {
                    if e.pua_match || e.static_match {
                        send(&tx, hwnd, ScanMsg::Row {
                            file: format!("{}\\{}\\{}", e.hive, e.path, e.value_name),
                            verdict: "Registry".into(),
                            threat: e.threat_name.clone().unwrap_or_else(|| e.detail.clone()),
                            sev: if e.static_match { 2 } else { 1 },
                        });
                    }
                }

                send(&tx, hwnd, ScanMsg::Status("Full scan: Windows event logs…".into()));
                let logs = scan_hayabusa_once(&exe_dir().join("hayabusa"));
                for m in &logs {
                    send(&tx, hwnd, ScanMsg::Row {
                        file: "Windows Event Logs".into(),
                        verdict: "Hayabusa".into(),
                        threat: m.clone(),
                        sev: 2,
                    });
                }
                send(&tx, hwnd, ScanMsg::Status("Full scan: process memory…".into()));
                let mem = memory_scanner::scan_process_memory(pl);
                for d in &mem {
                    send(&tx, hwnd, ScanMsg::Row {
                        file: format!("{} (pid {}) @ 0x{:x}", d.process, d.pid, d.address),
                        verdict: d.verdict.label().to_string(),
                        threat: d.threat_name.clone(),
                        sev: if d.verdict.priority() >= 6 { 2 } else { 1 },
                    });
                }

                send(&tx, hwnd, ScanMsg::Status(format!(
                    "Full scan done. Files: {scanned} scanned, {threats} threat(s); registry: {} threat(s); logs: {} alert(s); memory: {} hit(s).",
                    reg.threats_found,
                    logs.len(),
                    mem.len()
                )));
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

/// Scan every file under `paths` (engine dedups by content hash). Returns
/// (scanned, threats). Shared by the Scan and Full Scan work items.
fn scan_paths(pl: &Pipeline, paths: &[PathBuf], tx: &Sender<ScanMsg>, hwnd: HWND) -> (usize, usize) {
    let mut files = Vec::new();
    for p in paths {
        collect_files(p, &mut files);
    }
    let (mut scanned, mut threats) = (0usize, 0usize);
    for file in &files {
        let r = pl.scan_file_cached(file);
        scanned += 1;
        let prio = r.verdict.priority(); // Trusted=0, Clean=1, …, Malware=8
        if prio > 1 {
            // amber for PUA/Mining/Spam/Suspicious, red for Phishing/Abuse/Malware.
            threats += 1;
            let sev = if prio >= 6 { 2 } else { 1 };
            send(tx, hwnd, ScanMsg::Row {
                file: file.display().to_string(),
                verdict: r.verdict.label().to_string(),
                threat: detail_summary(&r),
                sev,
            });
        }
        if scanned % 25 == 0 {
            send(tx, hwnd, ScanMsg::Status(format!("Scanned {scanned}, {threats} threat(s)…")));
        }
    }
    (scanned, threats)
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

fn collect_files(path: &std::path::Path, out: &mut Vec<PathBuf>) {
    if path.is_file() {
        if let Ok(meta) = path.metadata() {
            if meta.len() >= 12 {
                out.push(path.to_path_buf());
            }
        }
        return;
    }
    if let Ok(entries) = std::fs::read_dir(path) {
        for entry in entries.flatten() {
            collect_files(&entry.path(), out);
        }
    }
}

fn exe_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
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
