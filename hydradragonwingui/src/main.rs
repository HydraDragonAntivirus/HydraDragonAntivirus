#![cfg(windows)]
#![windows_subsystem = "windows"]
// Every function here is `unsafe fn` wrapping raw Win32/COM calls; the whole body
// is the unsafe surface, so we don't double-wrap each call (edition-2024 lint).
#![allow(unsafe_op_in_unsafe_fn)]

//! Native Win32 GUI for the HydraDragon portable antivirus. Raw Win32 (no GUI
//! framework): a tab control (Scan / Quarantine), two report-mode ListViews,
//! native buttons, and the shell file/folder picker. Scanning, disinfection and
//! trace-removal run on a background worker thread driving the `hydradragonav`
//! engine; the quarantine manager (list/restore/delete) runs on the UI thread.

use std::ffi::c_void;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};

use hydradragonav::disinfector::{self, DisinfectOutcome};
use hydradragonav::pipeline::{Pipeline, PipelineConfig};
use hydradragonav::quarantine::Quarantine;
use hydradragonav::remediation;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{HINSTANCE, HWND, LPARAM, LRESULT, RECT, WPARAM};
use windows::Win32::Graphics::Gdi::{GetSysColorBrush, UpdateWindow, COLOR_BTNFACE};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoTaskMemFree, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::UI::Controls::{
    InitCommonControlsEx, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, LVCF_SUBITEM, LVCF_TEXT,
    LVCF_WIDTH, LVCOLUMNW, LVIF_TEXT, LVITEMW, NMHDR, TCIF_TEXT, TCITEMW,
};
use windows::Win32::UI::Shell::{
    FileOpenDialog, IFileOpenDialog, IShellItem, FOS_PICKFOLDERS, SIGDN_FILESYSPATH,
};
use windows::Win32::UI::WindowsAndMessaging::*;

// Control IDs.
const ID_TAB: usize = 1000;
const ID_SCAN_LIST: usize = 1001;
const ID_QUAR_LIST: usize = 1002;
const ID_STATUS: usize = 1003;
const ID_BTN_SCAN_FILE: usize = 1010;
const ID_BTN_SCAN_FOLDER: usize = 1011;
const ID_BTN_CLEAN: usize = 1012;
const ID_BTN_TRACES: usize = 1013;
const ID_BTN_QUAR_REFRESH: usize = 1020;
const ID_BTN_QUAR_RESTORE: usize = 1021;
const ID_BTN_QUAR_DELETE: usize = 1022;

const WM_APP_RESULT: u32 = WM_APP + 1;

// ListView / TabControl messages + styles (raw values — stable across versions).
mod msg {
    pub const LVM_FIRST: u32 = 0x1000;
    pub const LVM_DELETEALLITEMS: u32 = LVM_FIRST + 9;
    pub const LVM_GETITEMCOUNT: u32 = LVM_FIRST + 4;
    pub const LVM_GETNEXTITEM: u32 = LVM_FIRST + 12;
    pub const LVM_INSERTITEMW: u32 = LVM_FIRST + 77;
    pub const LVM_SETITEMTEXTW: u32 = LVM_FIRST + 116;
    pub const LVM_INSERTCOLUMNW: u32 = LVM_FIRST + 97;
    pub const LVM_SETEXTENDEDLISTVIEWSTYLE: u32 = LVM_FIRST + 54;
    pub const TCM_FIRST: u32 = 0x1300;
    pub const TCM_GETCURSEL: u32 = TCM_FIRST + 11;
    pub const TCM_INSERTITEMW: u32 = TCM_FIRST + 62;
}
mod style {
    pub const CHILD: u32 = 0x4000_0000;
    pub const VISIBLE: u32 = 0x1000_0000;
    pub const BORDER: u32 = 0x0080_0000;
    pub const TABSTOP: u32 = 0x0001_0000;
    pub const OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
    pub const BS_DEFPUSHBUTTON: u32 = 0x0001;
    pub const LVS_REPORT: u32 = 0x0001;
    pub const LVS_EX_FULLROWSELECT: u32 = 0x0000_0020;
    pub const LVS_EX_GRIDLINES: u32 = 0x0000_0001;
    pub const LVNI_SELECTED: isize = 0x0002;
}
const TCN_SELCHANGE: u32 = 0xFFFF_FDD9; // (-551i32) as u32

/// A message from a background worker back to the UI.
enum ScanMsg {
    Row { file: String, verdict: String, threat: String },
    Status(String),
}

/// A request from the UI to the worker.
enum WorkRequest {
    Scan(Vec<PathBuf>),
    Clean(Vec<PathBuf>),
    RemoveTraces(Vec<PathBuf>),
}

/// Per-window state, boxed into the window's GWLP_USERDATA.
struct AppState {
    tab: HWND,
    scan_list: HWND,
    quar_list: HWND,
    status: HWND,
    scan_btns: [HWND; 4],
    quar_btns: [HWND; 3],
    work_tx: Sender<WorkRequest>,
    result_rx: Receiver<ScanMsg>,
    scan_rows: Vec<PathBuf>,
    quar_ids: Vec<String>,
    quarantine_dir: PathBuf,
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
            820,
            560,
            None,
            None,
            Some(HINSTANCE::from(hinst).into()),
            None,
        )
        .expect("CreateWindow");

        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = UpdateWindow(hwnd);

        let mut m = MSG::default();
        while GetMessageW(&mut m, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&m);
            DispatchMessageW(&m);
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
            WM_NOTIFY => {
                let nm = &*(lparam.0 as *const NMHDR);
                if nm.idFrom == ID_TAB && nm.code == TCN_SELCHANGE {
                    update_tab_visibility(hwnd);
                }
                LRESULT(0)
            }
            WM_COMMAND => {
                on_command(hwnd, (wparam.0 & 0xFFFF) as usize);
                LRESULT(0)
            }
            x if x == WM_APP_RESULT => {
                if let Some(s) = state(hwnd) {
                    while let Ok(m) = s.result_rx.try_recv() {
                        match m {
                            ScanMsg::Row {
                                file,
                                verdict,
                                threat,
                            } => {
                                lv_add_row(s.scan_list, &[&file, &verdict, &threat]);
                                s.scan_rows.push(PathBuf::from(file));
                            }
                            ScanMsg::Status(text) => set_text(s.status, &text),
                        }
                    }
                }
                LRESULT(0)
            }
            WM_DESTROY => {
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
    (GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut AppState).as_mut()
}

unsafe fn on_create(hwnd: HWND) {
    let hinst: HINSTANCE = GetModuleHandleW(None).unwrap_or_default().into();

    let tab = create(hwnd, hinst, w!("SysTabControl32"), w!(""), style::CHILD | style::VISIBLE, ID_TAB);
    tab_add(tab, 0, "Scan");
    tab_add(tab, 1, "Quarantine");

    let btn = style::CHILD | style::VISIBLE | style::TABSTOP | style::BS_DEFPUSHBUTTON;
    let scan_btns = [
        create(hwnd, hinst, w!("BUTTON"), w!("Scan File…"), btn, ID_BTN_SCAN_FILE),
        create(hwnd, hinst, w!("BUTTON"), w!("Scan Folder…"), btn, ID_BTN_SCAN_FOLDER),
        create(hwnd, hinst, w!("BUTTON"), w!("Clean Selected"), btn, ID_BTN_CLEAN),
        create(hwnd, hinst, w!("BUTTON"), w!("Remove Traces"), btn, ID_BTN_TRACES),
    ];
    let quar_btns = [
        create(hwnd, hinst, w!("BUTTON"), w!("Refresh"), btn, ID_BTN_QUAR_REFRESH),
        create(hwnd, hinst, w!("BUTTON"), w!("Restore Selected"), btn, ID_BTN_QUAR_RESTORE),
        create(hwnd, hinst, w!("BUTTON"), w!("Delete Selected"), btn, ID_BTN_QUAR_DELETE),
    ];

    let lv = style::CHILD | style::VISIBLE | style::BORDER | style::LVS_REPORT;
    let scan_list = create(hwnd, hinst, w!("SysListView32"), w!(""), lv, ID_SCAN_LIST);
    lv_setup_ex(scan_list);
    lv_add_column(scan_list, 0, "File", 460);
    lv_add_column(scan_list, 1, "Verdict", 110);
    lv_add_column(scan_list, 2, "Threat", 220);

    let quar_list = create(hwnd, hinst, w!("SysListView32"), w!(""), lv, ID_QUAR_LIST);
    lv_setup_ex(quar_list);
    lv_add_column(quar_list, 0, "ID", 240);
    lv_add_column(quar_list, 1, "Original path", 360);
    lv_add_column(quar_list, 2, "Detection", 120);
    lv_add_column(quar_list, 3, "Size", 80);

    let status = create(hwnd, hinst, w!("STATIC"), w!("Ready."), style::CHILD | style::VISIBLE, ID_STATUS);

    let (work_tx, work_rx) = channel::<WorkRequest>();
    let (result_tx, result_rx) = channel::<ScanMsg>();
    let quarantine_dir = exe_dir().join("quarantine");
    let qdir = quarantine_dir.clone();
    let hwnd_raw = hwnd.0 as isize;
    std::thread::spawn(move || worker(hwnd_raw, work_rx, result_tx, qdir));

    let s = Box::new(AppState {
        tab,
        scan_list,
        quar_list,
        status,
        scan_btns,
        quar_btns,
        work_tx,
        result_rx,
        scan_rows: Vec::new(),
        quar_ids: Vec::new(),
        quarantine_dir,
    });
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(s) as isize);
    update_tab_visibility(hwnd);
    layout(hwnd);
}

unsafe fn create(
    parent: HWND,
    hinst: HINSTANCE,
    class: PCWSTR,
    text: PCWSTR,
    style_bits: u32,
    id: usize,
) -> HWND {
    CreateWindowExW(
        WINDOW_EX_STYLE::default(),
        class,
        text,
        WINDOW_STYLE(style_bits),
        0,
        0,
        0,
        0,
        Some(parent),
        Some(HMENU(id as *mut c_void)),
        Some(hinst.into()),
        None,
    )
    .unwrap_or_default()
}

unsafe fn on_command(hwnd: HWND, id: usize) {
    let Some(s) = state(hwnd) else { return };
    match id {
        ID_BTN_SCAN_FILE => pick_and_scan(s, false),
        ID_BTN_SCAN_FOLDER => pick_and_scan(s, true),
        ID_BTN_CLEAN => act_on_selected(hwnd, s, true),
        ID_BTN_TRACES => act_on_selected(hwnd, s, false),
        ID_BTN_QUAR_REFRESH => refresh_quarantine(s),
        ID_BTN_QUAR_RESTORE => quarantine_action(s, true),
        ID_BTN_QUAR_DELETE => quarantine_action(s, false),
        _ => {}
    }
}

unsafe fn pick_and_scan(s: &mut AppState, folder: bool) {
    if let Some(path) = pick_path(folder) {
        lv_clear(s.scan_list);
        s.scan_rows.clear();
        set_text(s.status, &format!("Scanning {}…", path.display()));
        let _ = s.work_tx.send(WorkRequest::Scan(vec![path]));
    }
}

unsafe fn act_on_selected(hwnd: HWND, s: &mut AppState, clean: bool) {
    let paths: Vec<PathBuf> = lv_selected(s.scan_list)
        .into_iter()
        .filter_map(|i| s.scan_rows.get(i as usize).cloned())
        .collect();
    if paths.is_empty() {
        set_text(s.status, "Select one or more detected files first.");
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
            &[
                &e.id,
                &e.original_path.display().to_string(),
                &e.detection,
                &e.size.to_string(),
            ],
        );
        s.quar_ids.push(e.id.clone());
    }
    set_text(s.status, &format!("{} quarantined item(s).", items.len()));
}

unsafe fn quarantine_action(s: &mut AppState, restore: bool) {
    let ids: Vec<String> = lv_selected(s.quar_list)
        .into_iter()
        .filter_map(|i| s.quar_ids.get(i as usize).cloned())
        .collect();
    if ids.is_empty() {
        set_text(s.status, "Select one or more quarantined items first.");
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
    set_text(s.status, &format!("{ok}/{} item(s) {verb}.", ids.len()));
    refresh_quarantine(s);
}

unsafe fn update_tab_visibility(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let scan = tab_cursel(s.tab) == 0;
    let show = |h: HWND, vis: bool| {
        let _ = ShowWindow(h, if vis { SW_SHOW } else { SW_HIDE });
    };
    for b in s.scan_btns {
        show(b, scan);
    }
    show(s.scan_list, scan);
    for b in s.quar_btns {
        show(b, !scan);
    }
    show(s.quar_list, !scan);
    if !scan {
        refresh_quarantine(s);
    }
}

unsafe fn layout(hwnd: HWND) {
    let Some(s) = state(hwnd) else { return };
    let mut rc = RECT::default();
    if GetClientRect(hwnd, &mut rc).is_err() {
        return;
    }
    let w = rc.right;
    let h = rc.bottom;
    let pad = 8;
    let tab_h = 26;
    let btn_w = 140;
    let btn_h = 28;
    let status_h = 22;

    let _ = MoveWindow(s.tab, 0, 0, w, tab_h, true);

    let row_y = tab_h + pad;
    let place_btns = |btns: &[HWND]| {
        for (i, b) in btns.iter().enumerate() {
            let _ = MoveWindow(*b, pad + (btn_w + pad) * i as i32, row_y, btn_w, btn_h, true);
        }
    };
    place_btns(&s.scan_btns);
    place_btns(&s.quar_btns);

    let list_y = row_y + btn_h + pad;
    let list_h = (h - list_y - status_h - pad).max(60);
    let _ = MoveWindow(s.scan_list, pad, list_y, w - pad * 2, list_h, true);
    let _ = MoveWindow(s.quar_list, pad, list_y, w - pad * 2, list_h, true);
    let _ = MoveWindow(s.status, pad, h - status_h, w - pad * 2, status_h, true);
}

unsafe fn confirm(hwnd: HWND, text: &str) -> bool {
    MessageBoxW(
        Some(hwnd),
        PCWSTR(wide(text).as_ptr()),
        w!("HydraDragon Antivirus"),
        MB_YESNO | MB_ICONWARNING,
    ) == IDYES
}

unsafe fn set_text(h: HWND, text: &str) {
    let _ = SetWindowTextW(h, PCWSTR(wide(text).as_ptr()));
}

// --- ListView / TabControl helpers ----------------------------------------

unsafe fn lv_setup_ex(list: HWND) {
    SendMessageW(
        list,
        msg::LVM_SETEXTENDEDLISTVIEWSTYLE,
        Some(WPARAM(0)),
        Some(LPARAM((style::LVS_EX_FULLROWSELECT | style::LVS_EX_GRIDLINES) as isize)),
    );
}

unsafe fn lv_add_column(list: HWND, index: i32, text: &str, width: i32) {
    let mut t = wide(text);
    let col = LVCOLUMNW {
        mask: LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM,
        cx: width,
        pszText: PWSTR(t.as_mut_ptr()),
        iSubItem: index,
        ..Default::default()
    };
    SendMessageW(
        list,
        msg::LVM_INSERTCOLUMNW,
        Some(WPARAM(index as usize)),
        Some(LPARAM(&col as *const _ as isize)),
    );
}

unsafe fn lv_add_row(list: HWND, cols: &[&str]) -> i32 {
    let count = SendMessageW(list, msg::LVM_GETITEMCOUNT, None, None).0 as i32;
    let mut first = wide(cols[0]);
    let item = LVITEMW {
        mask: LVIF_TEXT,
        iItem: count,
        iSubItem: 0,
        pszText: PWSTR(first.as_mut_ptr()),
        ..Default::default()
    };
    let idx = SendMessageW(
        list,
        msg::LVM_INSERTITEMW,
        None,
        Some(LPARAM(&item as *const _ as isize)),
    )
    .0 as i32;
    for (sub, text) in cols.iter().enumerate().skip(1) {
        let mut t = wide(text);
        let it = LVITEMW {
            iSubItem: sub as i32,
            pszText: PWSTR(t.as_mut_ptr()),
            ..Default::default()
        };
        SendMessageW(
            list,
            msg::LVM_SETITEMTEXTW,
            Some(WPARAM(idx as usize)),
            Some(LPARAM(&it as *const _ as isize)),
        );
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
        let r = SendMessageW(
            list,
            msg::LVM_GETNEXTITEM,
            Some(WPARAM(idx as usize)),
            Some(LPARAM(style::LVNI_SELECTED)),
        )
        .0 as i32;
        if r == -1 {
            break;
        }
        out.push(r);
        idx = r;
    }
    out
}

unsafe fn tab_add(tab: HWND, index: i32, text: &str) {
    let mut t = wide(text);
    let it = TCITEMW {
        mask: TCIF_TEXT,
        pszText: PWSTR(t.as_mut_ptr()),
        ..Default::default()
    };
    SendMessageW(
        tab,
        msg::TCM_INSERTITEMW,
        Some(WPARAM(index as usize)),
        Some(LPARAM(&it as *const _ as isize)),
    );
}

unsafe fn tab_cursel(tab: HWND) -> i32 {
    SendMessageW(tab, msg::TCM_GETCURSEL, None, None).0 as i32
}

/// Native shell file/folder picker via `IFileOpenDialog`.
unsafe fn pick_path(folder: bool) -> Option<PathBuf> {
    let dialog: IFileOpenDialog =
        CoCreateInstance(&FileOpenDialog, None, CLSCTX_INPROC_SERVER).ok()?;
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

// --- Background worker -----------------------------------------------------

fn worker(
    hwnd_raw: isize,
    work_rx: Receiver<WorkRequest>,
    result_tx: Sender<ScanMsg>,
    quarantine_dir: PathBuf,
) {
    let hwnd = HWND(hwnd_raw as *mut c_void);
    let mut pipeline: Option<Pipeline> = None;

    while let Ok(req) = work_rx.recv() {
        match req {
            WorkRequest::Scan(paths) => {
                let pl = ensure_pipeline(&mut pipeline, &result_tx, hwnd);
                let mut files = Vec::new();
                for p in &paths {
                    collect_files(p, &mut files);
                }
                let mut scanned = 0usize;
                let mut threats = 0usize;
                for file in &files {
                    let r = pl.scan_file(file);
                    scanned += 1;
                    let verdict = r.verdict.label();
                    if verdict != "Clean" && verdict != "Trusted" {
                        threats += 1;
                        send(
                            &result_tx,
                            hwnd,
                            ScanMsg::Row {
                                file: file.display().to_string(),
                                verdict: verdict.to_string(),
                                threat: r.threat_name.unwrap_or_default(),
                            },
                        );
                    }
                    if scanned % 25 == 0 {
                        send(&result_tx, hwnd, ScanMsg::Status(format!("Scanned {scanned}, {threats} threat(s)…")));
                    }
                }
                send(&result_tx, hwnd, ScanMsg::Status(format!("Done. {scanned} scanned, {threats} threat(s).")));
            }
            WorkRequest::Clean(paths) => {
                let pl = ensure_pipeline(&mut pipeline, &result_tx, hwnd);
                for path in &paths {
                    let arenas = pl.arenas_for_file(path);
                    let outcome = disinfector::disinfect_file(path, &arenas, &quarantine_dir);
                    let line = match outcome {
                        DisinfectOutcome::Neutralized { bytes, .. } => {
                            format!("neutralized {bytes} byte(s) in {}", path.display())
                        }
                        DisinfectOutcome::Quarantined { to } => {
                            format!("quarantined {} -> {}", path.display(), to.display())
                        }
                        DisinfectOutcome::Failed { reason } => {
                            format!("FAILED {}: {reason}", path.display())
                        }
                    };
                    send(&result_tx, hwnd, ScanMsg::Status(line));
                }
                send(&result_tx, hwnd, ScanMsg::Status("Clean complete.".into()));
            }
            WorkRequest::RemoveTraces(paths) => {
                match remediation::create_restore_point("HydraDragon GUI remediation") {
                    Ok(_) => send(&result_tx, hwnd, ScanMsg::Status("Restore point created.".into())),
                    Err(e) => send(&result_tx, hwnd, ScanMsg::Status(format!("Restore point skipped: {e}"))),
                }
                let mut removed = 0usize;
                for path in &paths {
                    for trace in remediation::find_traces(path) {
                        match remediation::apply(&trace, &quarantine_dir) {
                            Ok(_) => removed += 1,
                            Err(e) => send(
                                &result_tx,
                                hwnd,
                                ScanMsg::Status(format!("trace [{}] failed: {e}", trace.category)),
                            ),
                        }
                    }
                }
                send(&result_tx, hwnd, ScanMsg::Status(format!("Removed {removed} trace(s).")));
            }
        }
    }
}

fn ensure_pipeline<'a>(
    pl: &'a mut Option<Pipeline>,
    tx: &Sender<ScanMsg>,
    hwnd: HWND,
) -> &'a Pipeline {
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
        ..Default::default()
    }
}
