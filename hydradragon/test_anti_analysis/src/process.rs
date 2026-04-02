//! Process checking module
//!
//! Provides functions to enumerate and check running processes using Windows API.

use crate::{CheckResult, Result, SignatureMonsterError};
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;
use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
use std::collections::HashSet;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Process checker
pub struct ProcessChecker {
    _private: (),
}

impl ProcessChecker {
    /// Create a new process checker
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Get a list of all running process names
    pub fn list_processes(&self) -> Result<Vec<ProcessInfo>> {
        let snapshot = unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
                .map_err(|e| SignatureMonsterError::ProcessError(e.to_string()))?
        };

        let mut processes = Vec::new();
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if unsafe { Process32FirstW(snapshot, &mut entry) }.is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &entry.szExeFile[..entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len())]
                );
                
                processes.push(ProcessInfo {
                    pid: entry.th32ProcessID,
                    name,
                    parent_pid: entry.th32ParentProcessID,
                    thread_count: entry.cntThreads,
                });

                if unsafe { Process32NextW(snapshot, &mut entry) }.is_err() {
                    break;
                }
            }
        }

        unsafe { let _ = CloseHandle(snapshot); }
        Ok(processes)
    }

    /// Get list of unique process names
    pub fn list_process_names(&self) -> Result<Vec<String>> {
        let processes = self.list_processes()?;
        let unique: HashSet<String> = processes.into_iter().map(|p| p.name).collect();
        Ok(unique.into_iter().collect())
    }

    /// Check if a process with the given name is running (case-insensitive)
    pub fn is_running(&self, name: &str) -> bool {
        match self.list_processes() {
            Ok(processes) => {
                let name_lower = name.to_lowercase();
                processes.iter().any(|p| p.name.to_lowercase() == name_lower)
            }
            Err(_) => false,
        }
    }

    /// Check if a process name matches a regex pattern
    pub fn is_running_regex(&self, pattern: &str) -> Result<bool> {
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        
        let processes = self.list_processes()?;
        Ok(processes.iter().any(|p| re.is_match(&p.name)))
    }

    /// Check if a process name contains a substring
    pub fn is_running_contains(&self, substring: &str) -> bool {
        match self.list_processes() {
            Ok(processes) => {
                let sub_lower = substring.to_lowercase();
                processes.iter().any(|p| p.name.to_lowercase().contains(&sub_lower))
            }
            Err(_) => false,
        }
    }

    /// Check if any of the given processes are running
    pub fn any_running(&self, names: &[&str]) -> CheckResult {
        for name in names {
            if self.is_running(name) {
                return CheckResult::matched(*name);
            }
        }
        CheckResult::not_matched()
    }

    /// Check if all of the given processes are running
    pub fn all_running(&self, names: &[&str]) -> bool {
        names.iter().all(|name| self.is_running(name))
    }

    /// Get process count by name
    pub fn count_by_name(&self, name: &str) -> usize {
        match self.list_processes() {
            Ok(processes) => {
                let name_lower = name.to_lowercase();
                processes.iter().filter(|p| p.name.to_lowercase() == name_lower).count()
            }
            Err(_) => 0,
        }
    }

    /// Find processes by name (returns all matching)
    pub fn find_by_name(&self, name: &str) -> Result<Vec<ProcessInfo>> {
        let processes = self.list_processes()?;
        let name_lower = name.to_lowercase();
        Ok(processes.into_iter().filter(|p| p.name.to_lowercase() == name_lower).collect())
    }

    /// Find processes by PID
    pub fn find_by_pid(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        let processes = self.list_processes()?;
        Ok(processes.into_iter().find(|p| p.pid == pid))
    }

    /// Get the parent process of a given PID
    pub fn get_parent(&self, pid: u32) -> Result<Option<ProcessInfo>> {
        let process = self.find_by_pid(pid)?;
        match process {
            Some(p) => self.find_by_pid(p.parent_pid),
            None => Ok(None),
        }
    }

    /// Get current process ID
    pub fn current_pid(&self) -> u32 {
        unsafe { GetCurrentProcessId() }
    }

    /// Get current process info
    pub fn current_process(&self) -> Result<Option<ProcessInfo>> {
        self.find_by_pid(self.current_pid())
    }

    /// Check if current process is running as the given name
    pub fn current_is_named(&self, name: &str) -> bool {
        match self.current_process() {
            Ok(Some(p)) => p.name.to_lowercase() == name.to_lowercase(),
            _ => false,
        }
    }

    /// Get full path of a process by PID (requires appropriate permissions)
    pub fn get_process_path(&self, pid: u32) -> Result<String> {
        let handle = unsafe {
            OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| SignatureMonsterError::ProcessError(e.to_string()))?
        };

        let mut buffer = [0u16; 32768];
        let mut size = buffer.len() as u32;
        
        let result = unsafe {
            QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                windows::core::PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };

        unsafe { let _ = CloseHandle(handle); }

        if result.is_ok() && size > 0 {
            Ok(String::from_utf16_lossy(&buffer[..size as usize]))
        } else {
            Err(SignatureMonsterError::ProcessError(
                "Failed to get process path".to_string(),
            ))
        }
    }

    /// Check if a process path contains a pattern
    pub fn process_path_contains(&self, pid: u32, pattern: &str) -> bool {
        match self.get_process_path(pid) {
            Ok(path) => path.to_lowercase().contains(&pattern.to_lowercase()),
            Err(_) => false,
        }
    }

    /// List all visible window titles
    pub fn list_window_titles(&self) -> Result<Vec<WindowInfo>> {
        use std::process::Command;
        
        let mut cmd = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd.creation_flags(0x08000000);
        }
        let output = cmd.args([
                "-WindowStyle",
                "Hidden",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Get-Process | Where-Object {$_.MainWindowTitle} | Select-Object Id, ProcessName, MainWindowTitle | ConvertTo-Json -Compress"
            ])
            .output()
            .map_err(|e| SignatureMonsterError::ProcessError(e.to_string()))?;

        if !output.status.success() {
            return Err(SignatureMonsterError::ProcessError(
                String::from_utf8_lossy(&output.stderr).to_string()
            ));
        }

        let json = String::from_utf8(output.stdout)?;
        if json.trim().is_empty() || json.trim() == "null" {
            return Ok(Vec::new());
        }

        let windows: Vec<WindowInfo> = serde_json::from_str(&json)
            .or_else(|_| {
                let single: WindowInfo = serde_json::from_str(&json)?;
                Ok::<_, serde_json::Error>(vec![single])
            })
            .unwrap_or_default();

        Ok(windows)
    }

    /// Check if any window title contains a pattern
    pub fn window_title_contains(&self, pattern: &str) -> bool {
        match self.list_window_titles() {
            Ok(windows) => {
                let p = pattern.to_lowercase();
                windows.iter().any(|w| w.main_window_title.as_ref()
                    .map(|t| t.to_lowercase().contains(&p))
                    .unwrap_or(false))
            }
            Err(_) => false,
        }
    }

    /// Check if any window title matches regex
    pub fn window_title_matches_regex(&self, pattern: &str) -> Result<bool> {
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        
        let windows = self.list_window_titles()?;
        Ok(windows.iter().any(|w| w.main_window_title.as_ref()
            .map(|t| re.is_match(t))
            .unwrap_or(false)))
    }

    /// Find windows by title pattern
    pub fn find_windows_by_title(&self, pattern: &str) -> Result<Vec<WindowInfo>> {
        let windows = self.list_window_titles()?;
        let p = pattern.to_lowercase();
        Ok(windows.into_iter().filter(|w| w.main_window_title.as_ref()
            .map(|t| t.to_lowercase().contains(&p))
            .unwrap_or(false)).collect())
    }

    /// Check if a debugger is attached to the current process
    pub fn is_debugger_present(&self) -> bool {
        unsafe { IsDebuggerPresent().as_bool() }
    }

    /// Perform a basic programmatic check for analysis environment
    pub fn check_for_analysis(&self) -> Result<bool> {
        // 1. Check for standard debugger via Windows API
        if self.is_debugger_present() {
            return Ok(true);
        }

        // Programmatic checks could be expanded here (e.g. timing checks, 
        // specialized NT syscalls for debug bit, etc.)
        
        Ok(false)
    }
}

impl Default for ProcessChecker {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a running process
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessInfo {
    /// Process ID
    pub pid: u32,
    /// Process name (executable name)
    pub name: String,
    /// Parent Process ID
    pub parent_pid: u32,
    /// Number of threads
    pub thread_count: u32,
}

/// Information about a window
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WindowInfo {
    #[serde(rename = "Id")]
    pub pid: Option<u32>,
    #[serde(rename = "ProcessName")]
    pub process_name: Option<String>,
    #[serde(rename = "MainWindowTitle")]
    pub main_window_title: Option<String>,
}
