#![cfg(windows)]
#![windows_subsystem = "windows"]

//! Native Win32 GUI for the HydraDragon portable antivirus. Built from scratch
//! on the Win32 API (window class + message loop + native controls) with the
//! `windows` crate. Scanning runs on a background thread that drives the
//! `hydradragonav` pipeline; results are posted back to the UI thread.

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use hydradragonav::pipeline::{Pipeline, PipelineConfig};

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{GetSysColorBrush, COLOR_BTNFACE};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{InitCommonControlsEx, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX};
use windows::Win32::UI::Shell::Common::IShellItem;
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::*;

// Control IDs.
const ID_SCAN_FILE: usize = 1001;
const ID_SCAN_FOLDER: usize = 1002;
const ID_EDIT: usize = 1003;
const ID_STATUS: usize = 1004;

// Custom message: results are waiting in the channel.
const WM_APP_RESULT: u32 = WM_APP + 1;

// Edit-control messages / styles (not all are surfaced as typed constants).
const EM_SETSEL: u32 = 0x00B1;
const EM_REPLACESEL: u32 = 0x00C2;
mod style {
    pub const CHILD: u32 = 0x4000_0000;
    pub const VISIBLE: u32 = 0x1000_0000;
    pub const BORDER: u32 = 0x0080_0000;
    pub const VSCROLL: u32 = 0x0020_0000;
    pub const TABSTOP: u32 = 0x0001_0000;
    pub const OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
    pub const ES_MULTILINE: u32 = 0x0004;
    pub const ES_AUTOVSCROLL: u32 = 0x0040;
    pub const ES_READONLY: u32 = 0x0800;
    pub const BS_DEFPUSHBUTTON: u32 = 0x0001;
}

/// A message from the scan worker back to the UI.
enum ScanMsg {
    Line(String),
    Status(String),
}

/// A request from the UI to the scan worker.
enum WorkRequest {
    Scan(Vec<PathBuf>),
}

/// Per-window state, stored in the window's GWLP_USERDATA.
struct AppState {
    edit: HWND,
    status: HWND,
    work_tx: Sender<WorkRequest>,
    result_rx: Receiver<ScanMsg>,
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn main() {
    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);

        let hinst = GetModuleHandleW(None).expect("GetModuleHandle");
        let class = w!("HydraDragonWinGuiClass");

        let wc = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(wndproc),
            hInstance: hinst.into(),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: GetSysColorBrush(COLOR_BTNFACE),
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
            WINDOW_STYLE(style::OVERLAPPEDWINDOW),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            760,
            520,
            None,
            None,
            hinst.into(),
            None,
        )
        .expect("CreateWindow");

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);

        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    unsafe {
        match msg {
            WM_CREATE => {
                on_create(hwnd);
                LRESULT(0)
            }
            WM_SIZE => {
                layout(hwnd);
                LRESULT(0)
            }
            WM_COMMAND => {
                let id = (wparam.0 & 0xFFFF) as usize;
                if let Some(state) = state(hwnd) {
                    match id {
                        ID_SCAN_FILE => start_scan(state, false),
                        ID_SCAN_FOLDER => start_scan(state, true),
                        _ => {}
                    }
                }
                LRESULT(0)
            }
            x if x == WM_APP_RESULT => {
                if let Some(state) = state(hwnd) {
                    while let Ok(m) = state.result_rx.try_recv() {
                        match m {
                            ScanMsg::Line(s) => append_line(state.edit, &s),
                            ScanMsg::Status(s) => {
                                let _ = SetWindowTextW(state.status, PCWSTR(wide(&s).as_ptr()));
                            }
                        }
                    }
                }
                LRESULT(0)
            }
            WM_DESTROY => {
                // Reclaim and drop the state (dropping work_tx stops the worker).
                let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
                if !ptr.is_null() {
                    drop(Box::from_raw(ptr));
                    SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
                }
                PostQuitMessage(0);
                LRESULT(0)
            }
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }
}

unsafe fn state(hwnd: HWND) -> Option<&'static mut AppState> {
    let ptr = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState;
    ptr.as_mut()
}

unsafe fn on_create(hwnd: HWND) {
    let hinst = GetModuleHandleW(None).unwrap_or_default();

    let btn_style = WINDOW_STYLE(
        style::CHILD | style::VISIBLE | style::TABSTOP | style::BS_DEFPUSHBUTTON,
    );
    create_child(hwnd, hinst.into(), w!("BUTTON"), w!("Scan File…"), btn_style, ID_SCAN_FILE);
    create_child(hwnd, hinst.into(), w!("BUTTON"), w!("Scan Folder…"), btn_style, ID_SCAN_FOLDER);

    let edit = create_child(
        hwnd,
        hinst.into(),
        w!("EDIT"),
        w!(""),
        WINDOW_STYLE(
            style::CHILD
                | style::VISIBLE
                | style::BORDER
                | style::VSCROLL
                | style::ES_MULTILINE
                | style::ES_AUTOVSCROLL
                | style::ES_READONLY,
        ),
        ID_EDIT,
    );

    let status = create_child(
        hwnd,
        hinst.into(),
        w!("STATIC"),
        w!("Ready. Pick a file or folder to scan."),
        WINDOW_STYLE(style::CHILD | style::VISIBLE),
        ID_STATUS,
    );

    let (work_tx, work_rx) = channel::<WorkRequest>();
    let (result_tx, result_rx) = channel::<ScanMsg>();
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || worker(hwnd_raw, work_rx, result_tx));

    let state = Box::new(AppState {
        edit,
        status,
        work_tx,
        result_rx,
    });
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize);

    layout(hwnd);
}

unsafe fn create_child(
    parent: HWND,
    hinst: windows::Win32::Foundation::HINSTANCE,
    class: PCWSTR,
    text: PCWSTR,
    style: WINDOW_STYLE,
    id: usize,
) -> HWND {
    CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        text,
        style,
        0,
        0,
        0,
        0,
        parent,
        HMENU(id as *mut c_void),
        hinst,
        None,
    )
    .unwrap_or_default()
}

unsafe fn layout(hwnd: HWND) {
    let Some(state) = state(hwnd) else { return };
    let mut rc = RECT::default();
    if GetClientRect(hwnd, &mut rc).is_err() {
        return;
    }
    let w = rc.right - rc.left;
    let h = rc.bottom - rc.top;
    let pad = 10;
    let btn_w = 130;
    let btn_h = 30;
    let status_h = 22;

    if let Some(b) = child(hwnd, ID_SCAN_FILE) {
        let _ = MoveWindow(b, pad, pad, btn_w, btn_h, true);
    }
    if let Some(b) = child(hwnd, ID_SCAN_FOLDER) {
        let _ = MoveWindow(b, pad * 2 + btn_w, pad, btn_w, btn_h, true);
    }
    let edit_y = pad * 2 + btn_h;
    let edit_h = h - edit_y - status_h - pad;
    let _ = MoveWindow(state.edit, pad, edit_y, w - pad * 2, edit_h.max(50), true);
    let _ = MoveWindow(state.status, pad, h - status_h, w - pad * 2, status_h, true);
}

unsafe fn child(parent: HWND, id: usize) -> Option<HWND> {
    let h = GetDlgItem(parent, id as i32);
    if h.0.is_null() {
        None
    } else {
        Some(h)
    }
}

unsafe fn append_line(edit: HWND, text: &str) {
    let buf = wide(&format!("{text}\r\n"));
    let len = GetWindowTextLengthW(edit);
    SendMessageW(edit, EM_SETSEL, WPARAM(len as usize), LPARAM(len as isize));
    SendMessageW(edit, EM_REPLACESEL, WPARAM(0), LPARAM(buf.as_ptr() as isize));
}

unsafe fn start_scan(state: &mut AppState, folder: bool) {
    if let Some(path) = pick_path(folder) {
        let _ = SetWindowTextW(
            state.status,
            PCWSTR(wide(&format!("Scanning {}…", path.display())).as_ptr()),
        );
        let _ = state.work_tx.send(WorkRequest::Scan(vec![path]));
    }
}

/// Native shell file/folder picker via `IFileOpenDialog`.
unsafe fn pick_path(folder: bool) -> Option<PathBuf> {
    let dialog: IFileOpenDialog =
        CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
    if folder {
        let opts = dialog.GetOptions().ok()?;
        dialog.SetOptions(opts | FOS_PICKFOLDERS).ok()?;
    }
    dialog.Show(None).ok()?; // Err == cancelled
    let item: IShellItem = dialog.GetResult().ok()?;
    let pw: PWSTR = item.GetDisplayName(SIGDN_FILESYSPATH).ok()?;
    let path = pw.to_string().ok();
    CoTaskMemFree(Some(pw.0 as *const c_void));
    path.map(PathBuf::from)
}

// ---------------------------------------------------------------------------
// Background scan worker
// ---------------------------------------------------------------------------

fn worker(hwnd_raw: isize, work_rx: Receiver<WorkRequest>, result_tx: Sender<ScanMsg>) {
    let hwnd = HWND(hwnd_raw as *mut c_void);
    let mut pipeline: Option<Pipeline> = None;

    while let Ok(WorkRequest::Scan(paths)) = work_rx.recv() {
        if pipeline.is_none() {
            send(&result_tx, hwnd, ScanMsg::Status("Loading engines…".into()));
            pipeline = Some(Pipeline::new(default_config()));
        }
        let pl = pipeline.as_ref().unwrap();

        let mut files = Vec::new();
        for p in &paths {
            collect_files(p, &mut files);
        }

        let mut scanned = 0usize;
        let mut threats = 0usize;
        for file in &files {
            let result = pl.scan_file(file);
            scanned += 1;
            let verdict = result.verdict.label();
            if verdict != "Clean" && verdict != "Trusted" {
                threats += 1;
                let threat = result.threat_name.unwrap_or_default();
                send(
                    &result_tx,
                    hwnd,
                    ScanMsg::Line(format!("[{verdict}] {}  {threat}", file.display())),
                );
            }
            if scanned % 25 == 0 {
                send(
                    &result_tx,
                    hwnd,
                    ScanMsg::Status(format!("Scanned {scanned}, {threats} threat(s)…")),
                );
            }
        }
        send(
            &result_tx,
            hwnd,
            ScanMsg::Line(format!(
                "— done: {scanned} file(s) scanned, {threats} threat(s) found —"
            )),
        );
        send(
            &result_tx,
            hwnd,
            ScanMsg::Status(format!("Done. {scanned} scanned, {threats} threat(s).")),
        );
    }
}

fn send(tx: &Sender<ScanMsg>, hwnd: HWND, msg: ScanMsg) {
    if tx.send(msg).is_ok() {
        unsafe {
            let _ = PostMessageW(hwnd, WM_APP_RESULT, WPARAM(0), LPARAM(0));
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
        ..Default::default()
    }
}
