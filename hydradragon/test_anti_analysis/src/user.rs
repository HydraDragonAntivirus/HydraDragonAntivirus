//! User checking module
//!
//! Provides functions to check current user, usernames, and user-related information.

use crate::{CheckResult, Result, SignatureMonsterError};
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// User checker
pub struct UserChecker {
    _private: (),
}

impl UserChecker {
    /// Create a new user checker
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Get the current username
    pub fn current_username(&self) -> Result<String> {
        std::env::var("USERNAME")
            .map_err(|e| SignatureMonsterError::HwidError(format!("Failed to get username: {}", e)))
    }

    /// Get the current user's domain
    pub fn current_domain(&self) -> Result<String> {
        std::env::var("USERDOMAIN")
            .map_err(|e| SignatureMonsterError::HwidError(format!("Failed to get user domain: {}", e)))
    }

    /// Get the fully qualified username (DOMAIN\Username)
    pub fn current_full_username(&self) -> Result<String> {
        let domain = self.current_domain()?;
        let username = self.current_username()?;
        Ok(format!("{}\\{}", domain, username))
    }

    /// Get the user's home directory
    pub fn home_directory(&self) -> Result<String> {
        std::env::var("USERPROFILE")
            .map_err(|e| SignatureMonsterError::HwidError(format!("Failed to get user profile: {}", e)))
    }

    /// Get the computer name
    pub fn computer_name(&self) -> Result<String> {
        std::env::var("COMPUTERNAME")
            .map_err(|e| SignatureMonsterError::HwidError(format!("Failed to get computer name: {}", e)))
    }

    /// Check if current username matches
    pub fn is_user(&self, expected: &str) -> bool {
        match self.current_username() {
            Ok(name) => name.to_lowercase() == expected.to_lowercase(),
            Err(_) => false,
        }
    }

    /// Check if username matches a pattern
    pub fn username_matches(&self, pattern: &str) -> CheckResult {
        match self.current_username() {
            Ok(name) => {
                if name.to_lowercase().contains(&pattern.to_lowercase()) {
                    CheckResult::matched(name)
                } else {
                    CheckResult::not_matched()
                }
            }
            Err(_) => CheckResult::not_matched(),
        }
    }

    /// Check if username matches a regex
    pub fn username_matches_regex(&self, pattern: &str) -> Result<CheckResult> {
        let name = self.current_username()?;
        let re = regex::Regex::new(pattern)
            .map_err(|e| SignatureMonsterError::RegexError(e.to_string()))?;
        
        if re.is_match(&name) {
            Ok(CheckResult::matched(name))
        } else {
            Ok(CheckResult::not_matched())
        }
    }

    /// List all local users on the system
    pub fn list_local_users(&self) -> Result<Vec<String>> {
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
                "(Get-LocalUser | Select-Object -ExpandProperty Name) -join ','",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        if !output.status.success() {
            return Err(SignatureMonsterError::PowerShellError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        let users_str = String::from_utf8(output.stdout)?;
        Ok(users_str
            .trim()
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Check if a local user exists
    pub fn local_user_exists(&self, username: &str) -> bool {
        match self.list_local_users() {
            Ok(users) => users.iter().any(|u| u.to_lowercase() == username.to_lowercase()),
            Err(_) => false,
        }
    }

    /// Check if running as administrator
    pub fn is_admin(&self) -> bool {
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
                "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
            ])
            .output();

        match output {
            Ok(out) => {
                let result = String::from_utf8_lossy(&out.stdout);
                result.trim().to_lowercase() == "true"
            }
            Err(_) => false,
        }
    }

    /// Check if running as SYSTEM
    pub fn is_system(&self) -> bool {
        match self.current_username() {
            Ok(name) => name.to_uppercase() == "SYSTEM",
            Err(_) => false,
        }
    }

    /// Get user SID
    pub fn current_sid(&self) -> Result<String> {
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
                "([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        if !output.status.success() {
            return Err(SignatureMonsterError::PowerShellError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        Ok(String::from_utf8(output.stdout)?.trim().to_string())
    }

    /// Get all group memberships for current user
    pub fn current_groups(&self) -> Result<Vec<String>> {
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
                "([System.Security.Principal.WindowsIdentity]::GetCurrent()).Groups | ForEach-Object { $_.Translate([System.Security.Principal.NTAccount]).Value } | Out-String",
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        if !output.status.success() {
            return Err(SignatureMonsterError::PowerShellError(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }

        let groups_str = String::from_utf8(output.stdout)?;
        Ok(groups_str
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect())
    }

    /// Check if user is member of a specific group
    pub fn is_member_of(&self, group_name: &str) -> bool {
        match self.current_groups() {
            Ok(groups) => groups.iter().any(|g| g.to_lowercase().contains(&group_name.to_lowercase())),
            Err(_) => false,
        }
    }
}

impl Default for UserChecker {
    fn default() -> Self {
        Self::new()
    }
}
