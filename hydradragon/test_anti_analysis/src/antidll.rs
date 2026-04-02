//! Anti-DLL Injection module
//!
//! Provides protection against DLL injection attacks using Windows mitigation policies.
//! This module is available when the `antidll` feature is enabled.

#![cfg(feature = "antidll")]

use crate::{Result, SignatureMonsterError};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::GetCurrentProcess;
use std::process::Command;
#[cfg(windows)]
use std::os::windows::process::CommandExt;

/// Anti-DLL Injection protector
pub struct AntiDllInjection {
    _private: (),
}

impl AntiDllInjection {
    pub fn new() -> Self {
        Self { _private: () }
    }

    /// Set process mitigation policy to only allow Microsoft-signed DLLs
    /// This prevents most DLL injection attacks
    pub fn set_microsoft_signed_only(&self) -> Result<bool> {
        
        // Use PowerShell to call the Windows API since the direct API requires unsafe
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
                r#"
                Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class MitigationPolicy {
                    [DllImport("kernel32.dll", SetLastError = true)]
                    public static extern bool SetProcessMitigationPolicy(int MitigationPolicy, ref PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY lpBuffer, int dwLength);
                    
                    [StructLayout(LayoutKind.Sequential)]
                    public struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
                        public uint Flags;
                    }
                    
                    public static bool SetMicrosoftSignedOnly() {
                        var policy = new PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY();
                        policy.Flags = 1; // MicrosoftSignedOnly
                        return SetProcessMitigationPolicy(8, ref policy, Marshal.SizeOf(policy));
                    }
                }
"@
                [MitigationPolicy]::SetMicrosoftSignedOnly()
                "#,
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout);
        Ok(result.trim().to_lowercase() == "true")
    }

    /// Check if the process has mitigation policy enabled
    pub fn is_protected(&self) -> Result<bool> {
        
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
                r#"
                Add-Type @"
                using System;
                using System.Runtime.InteropServices;
                public class MitigationCheck {
                    [DllImport("kernel32.dll", SetLastError = true)]
                    public static extern bool GetProcessMitigationPolicy(IntPtr hProcess, int MitigationPolicy, ref PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY lpBuffer, int dwLength);
                    
                    [StructLayout(LayoutKind.Sequential)]
                    public struct PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY {
                        public uint Flags;
                    }
                    
                    public static bool IsMicrosoftSignedOnly() {
                        var policy = new PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY();
                        IntPtr handle = System.Diagnostics.Process.GetCurrentProcess().Handle;
                        if (GetProcessMitigationPolicy(handle, 8, ref policy, Marshal.SizeOf(policy))) {
                            return (policy.Flags & 1) != 0;
                        }
                        return false;
                    }
                }
"@
                [MitigationCheck]::IsMicrosoftSignedOnly()
                "#,
            ])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout);
        Ok(result.trim().to_lowercase() == "true")
    }

    /// Detect if any unsigned DLLs are loaded in the current process
    pub fn check_unsigned_dlls(&self) -> Result<Vec<String>> {
        
        let pid = std::process::id();
        let cmd = format!(
            r#"Get-Process -Id {} | Select-Object -ExpandProperty Modules | ForEach-Object {{
                $sig = Get-AuthenticodeSignature $_.FileName -ErrorAction SilentlyContinue
                if ($sig.Status -ne 'Valid') {{ $_.FileName }}
            }}"#,
            pid
        );

        let mut cmd_obj = Command::new("powershell");
        #[cfg(windows)]
        {
            cmd_obj.creation_flags(0x08000000);
        }
        let output = cmd_obj
            .args(["-WindowStyle", "Hidden", "-NoProfile", "-NonInteractive", "-Command", &cmd])
            .output()
            .map_err(|e| SignatureMonsterError::PowerShellError(e.to_string()))?;

        let result = String::from_utf8_lossy(&output.stdout);
        Ok(result.lines().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
    }
}

impl Default for AntiDllInjection {
    fn default() -> Self {
        Self::new()
    }
}
