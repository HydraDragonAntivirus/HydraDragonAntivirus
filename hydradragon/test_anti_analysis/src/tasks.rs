//! Scheduled Tasks checking module
//!
//! Provides functions to enumerate and check Windows scheduled tasks.

use crate::{Result, SignatureMonsterError};
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Task checker
pub struct TaskChecker {
    _private: (),
}

impl TaskChecker {
    pub fn new() -> Self {
        Self { _private: () }
    }

    fn run_powershell(&self, cmd: &str) -> Result<String> {
        let mut cmd_obj = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd_obj.creation_flags(0x08000000);
        }
        let output = cmd_obj
            .args(["-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-Command", cmd])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        if !output.status.success() {
            return Err(SignatureMonsterError::PowerShellError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// List all scheduled task names
    pub fn list_tasks(&self) -> Result<Vec<TaskInfo>> {
        let output = self.run_powershell(
            "Get-ScheduledTask | Select-Object TaskName, TaskPath, State | ConvertTo-Json -Compress"
        )?;

        if output.is_empty() || output == "null" {
            return Ok(Vec::new());
        }

        // Parse JSON response
        let tasks: Vec<TaskInfo> = serde_json::from_str(&output)
            .or_else(|_| {
                // Try as single object
                let single: TaskInfo = serde_json::from_str(&output)?;
                Ok::<_, serde_json::Error>(vec![single])
            })
            .unwrap_or_default();

        Ok(tasks)
    }

    /// List task names only
    pub fn list_task_names(&self) -> Result<Vec<String>> {
        let tasks = self.list_tasks()?;
        Ok(tasks.into_iter().map(|t| t.task_name).collect())
    }

    /// Check if a scheduled task exists
    pub fn exists(&self, name: &str) -> Result<bool> {
        let tasks = self.list_task_names()?;
        let n = name.to_lowercase();
        Ok(tasks.iter().any(|t| t.to_lowercase() == n))
    }

    /// Check if a task exists matching regex
    pub fn exists_regex(&self, pattern: &str) -> Result<bool> {
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        let tasks = self.list_task_names()?;
        Ok(tasks.iter().any(|t| re.is_match(t)))
    }

    /// Check if a task name contains substring
    pub fn exists_contains(&self, substring: &str) -> Result<bool> {
        let tasks = self.list_task_names()?;
        let s = substring.to_lowercase();
        Ok(tasks.iter().any(|t| t.to_lowercase().contains(&s)))
    }

    /// Find tasks by pattern
    pub fn find_by_pattern(&self, pattern: &str) -> Result<Vec<TaskInfo>> {
        let tasks = self.list_tasks()?;
        let p = pattern.to_lowercase();
        Ok(tasks.into_iter().filter(|t| t.task_name.to_lowercase().contains(&p)).collect())
    }

    /// Get task by exact name
    pub fn get_task(&self, name: &str) -> Result<Option<TaskInfo>> {
        let tasks = self.list_tasks()?;
        let n = name.to_lowercase();
        Ok(tasks.into_iter().find(|t| t.task_name.to_lowercase() == n))
    }

    /// Check if task is enabled/running
    pub fn is_enabled(&self, name: &str) -> Result<bool> {
        match self.get_task(name)? {
            Some(t) => Ok(t.state.as_deref() == Some("Ready") || t.state.as_deref() == Some("Running")),
            None => Ok(false),
        }
    }
}

impl Default for TaskChecker { fn default() -> Self { Self::new() } }

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TaskInfo {
    #[serde(rename = "TaskName")]
    pub task_name: String,
    #[serde(rename = "TaskPath")]
    pub task_path: Option<String>,
    #[serde(rename = "State")]
    pub state: Option<String>,
}
