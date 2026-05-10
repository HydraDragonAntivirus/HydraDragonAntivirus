#![allow(dead_code)]
//! Hardcoded Sanctum-owned protection rules.
//!
//! These constants are compiled into sanctum_ppl_runner.exe. The runner no longer
//! reads mutable rule files from disk at runtime before updating privileged
//! kernel rule state.

pub const OWLY_FSFILTER_EXCLUDE_RULES: &str = r####"
# Dynamic hook exclude rules (normalized/contains match, case-insensitive)
# Put full path fragments under C:\ only.

c:\windows\system32\smss.exe
c:\windows\system32\csrss.exe
c:\windows\system32\wininit.exe
c:\windows\system32\winlogon.exe
c:\windows\system32\lsass.exe
c:\windows\system32\services.exe
c:\windows\system32\svchost.exe
c:\windows\system32\fontdrvhost.exe
c:\windows\system32\sihost.exe
c:\windows\system32\dwm.exe

# HydraDragonAntivirus-specific examples
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc
c:\windows\system32\tasks\hydradragonantivirus
c:\windows\system32\edrpm64.dll
c:\windows\system32\edrpm32.dll
c:\windows\system32\edrmm.dll
c:\windows\system32\drivers\sanctum.sys
c:\windows\system32\drivers\OwlyshieldRansomFilter.sys
c:\windows\system32\drivers\RedDbgDrv.sys
c:\windows\system32\drivers\hyperhv.sys

# Sanctum install directory
c:\program files\hydradragonantivirus\hydradragon\sanctum

"####;

pub const OWLY_PROCESS_PROTECTION_EXCLUDE_RULES: &str = r####"
# Dynamic hook exclude rules (normalized/contains match, case-insensitive)
# Put full path fragments under C:\ only.

c:\windows\system32\smss.exe
c:\windows\system32\csrss.exe
c:\windows\system32\wininit.exe
c:\windows\system32\winlogon.exe
c:\windows\system32\lsass.exe
c:\windows\system32\services.exe
c:\windows\system32\svchost.exe
c:\windows\system32\fontdrvhost.exe
c:\windows\system32\sihost.exe
c:\windows\system32\dwm.exe
# memcompression etc. is hardcoded to avoid confusion and bypasses

# HydraDragonAntivirus-specific examples
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc
c:\windows\system32\tasks\hydradragonantivirus
c:\windows\system32\edrpm64.dll
c:\windows\system32\edrpm32.dll
c:\windows\system32\edrmm.dll
c:\windows\system32\drivers\sanctum.sys
c:\windows\system32\drivers\OwlyshieldRansomFilter.sys
c:\windows\system32\drivers\RedDbgDrv.sys
c:\windows\system32\drivers\hyperhv.sys

# Sanctum install directory
c:\program files\hydradragonantivirus\hydradragon\sanctum

"####;

pub const OWLY_DYNAMIC_HOOK_EXCLUDE_RULES: &str = r####"
# Dynamic hook exclude rules (normalized/contains match, case-insensitive)
# Put full path fragments under C:\ only.

# c:\windows\system32\smss.exe
# c:\windows\system32\csrss.exe
# c:\windows\system32\wininit.exe
# c:\windows\system32\winlogon.exe
# c:\windows\system32\lsass.exe
# c:\windows\system32\services.exe
# c:\windows\system32\svchost.exe
# c:\windows\system32\fontdrvhost.exe
# c:\windows\system32\sihost.exe
# c:\windows\system32\dwm.exe

# HydraDragonAntivirus-specific examples
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc
c:\windows\system32\tasks\hydradragonantivirus
c:\windows\system32\edrpm64.dll
c:\windows\system32\edrpm32.dll
c:\windows\system32\edrmm.dll
c:\windows\system32\drivers\sanctum.sys
c:\windows\system32\drivers\OwlyshieldRansomFilter.sys
c:\windows\system32\drivers\RedDbg.sys
c:\windows\system32\drivers\hyperhv.sys

# Sanctum install directory
c:\program files\hydradragonantivirus\hydradragon\sanctum


"####;

pub const HYDRADRAGON_FILE_PROTECTION_RULES: &str = r####"
# =============================================================================
# HydraDragon Antivirus - File Protection Rules
# =============================================================================
#
# REQUIRED FORMAT: every rule must start with one of:
#   C:\          drive-letter path  (any drive letter A-Z is valid)
#   \??\         NT device namespace path
#   \            relative/suffix path - use only when the absolute path cannot
#                be known statically (e.g. per-user AppData paths).
#                Rules using the \ prefix are matched as substrings of the
#                full normalised file path, so they work across all user accounts.
#                Bare names without a leading separator are rejected.
#
# Matching is case-insensitive substring search: a rule fires if the full
# kernel file path CONTAINS the rule string.  Full drive-letter paths give
# the tightest match and should be preferred wherever possible.
#
# One rule per line.  Blank lines and # / // comments are ignored.
# =============================================================================

# ---------------------------------------------------------------------------
# HydraDragon Antivirus install directory (entire tree)
# ---------------------------------------------------------------------------
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc

# ---------------------------------------------------------------------------
# Sanctum in-box DLL
# ---------------------------------------------------------------------------
c:\windows\system32\sanctum.dll

# ---------------------------------------------------------------------------
# Sanctum install directory
# ---------------------------------------------------------------------------
c:\program files\hydradragonantivirus\hydradragon\sanctum

# ---------------------------------------------------------------------------
# Scheduled task entry
# ---------------------------------------------------------------------------
c:\windows\system32\tasks\hydradragonantivirus

# ---------------------------------------------------------------------------
# Kernel-mode driver binaries
# ---------------------------------------------------------------------------
c:\windows\system32\drivers\owlyshieldransomfilter.sys
c:\windows\system32\drivers\RedDbgDrv.sys
c:\windows\system32\drivers\hyperhv.sys
c:\windows\system32\drivers\simplepyasprotection.sys
c:\windows\system32\drivers\mbrfilter.sys
c:\windows\system32\drivers\fs_minifilter.sys
c:\windows\system32\drivers\sanctum.sys

# ---------------------------------------------------------------------------
# OpenEDR Injection DLLs (Moved to System32)
# ---------------------------------------------------------------------------
c:\windows\system32\edrpm64.dll
c:\windows\system32\edrpm32.dll
c:\windows\system32\edrmm.dll
"####;

pub const HYDRADRAGON_PROCESS_PROTECTION_RULES: &str = r####"
# =============================================================================
# HydraDragon Antivirus - Process Protection Rules
# =============================================================================
#
# REQUIRED FORMAT: every rule must start with one of:
#   C:\          drive-letter path  (most common; any drive letter A-Z is valid)
#   \??\         NT device namespace path
#   \            relative/suffix path - use only when the absolute path is
#                unknown at rule-authoring time (e.g. user-profile executables).
#                Bare filenames without any leading separator are rejected.
#
# Matching is case-insensitive substring search: a rule matches if the full
# image path of the process CONTAINS the rule string.  Full drive-letter paths
# are therefore the most precise and least error-prone choice.
#
# One rule per line.  Blank lines and # / // comments are ignored.
# =============================================================================

# ---------------------------------------------------------------------------
# Windows Shell - protect explorer.exe against termination / injection
# ---------------------------------------------------------------------------
# c:\windows\explorer.exe

# ---------------------------------------------------------------------------
# Sanctum agent executables (installed under Program Files)
# ---------------------------------------------------------------------------
c:\program files\hydradragonantivirus
c:\programdata\hydradragonantivirus
c:\programdata\edrsvc
c:\windows\system32\drivers\sanctum.sys
c:\windows\system32\drivers\OwlyshieldRansomFilter.sys
c:\windows\system32\drivers\RedDbgDrv.sys
c:\windows\system32\drivers\hyperhv.sys

"####;

pub const HYDRADRAGON_REGISTRY_PROTECTION_RULES: &str = r####"
# =============================================================================
# HydraDragon Antivirus - Registry Protection Rules
# =============================================================================
#
# REQUIRED FORMAT: every rule must start with a recognised registry hive.
# Rules that do not match one of the accepted formats are silently rejected
# and a DbgPrint warning is emitted to the kernel debugger.
#
# Accepted prefixes (case-insensitive):
#   HKLM\       -> \REGISTRY\MACHINE\...
#   HKCU\       -> \REGISTRY\USER\...   (NOTE: HKCU is per-SID in the kernel;
#                  the rule will match any user's copy of the key because the
#                  matching engine uses a substring search under \REGISTRY\USER\)
#   HKU\        -> \REGISTRY\USER\...
#   HKCR\       -> \REGISTRY\MACHINE\SOFTWARE\CLASSES\...
#   HKCC\       -> \REGISTRY\MACHINE\SYSTEM\CURRENTCONTROLSET\HARDWARE PROFILES\CURRENT\...
#   \REGISTRY\  -> raw NT kernel path (used verbatim, no conversion)
#
# One rule per line.  Blank lines and lines starting with # or // are ignored.
# Inline comments are also supported:  HKLM\Some\Key  # this is a comment
# =============================================================================

# ---------------------------------------------------------------------------
# Owlyshield antivirus service keys
# ---------------------------------------------------------------------------
HKLM\SOFTWARE\Owlyshield
HKLM\SYSTEM\CurrentControlSet\Services\owlyshield_ransom
HKLM\SYSTEM\CurrentControlSet\Services\SimplePYASProtection
HKLM\SYSTEM\CurrentControlSet\Services\RedDbg
HKLM\SYSTEM\CurrentControlSet\Services\HyperDbg
HKLM\SYSTEM\CurrentControlSet\Services\hyperhv

# ---------------------------------------------------------------------------
# Sanctum / PPL runner service keys
# ---------------------------------------------------------------------------
HKLM\SYSTEM\CurrentControlSet\Services\sanctum_ppl_runner

# ---------------------------------------------------------------------------
# MBRFilter driver service key
# ---------------------------------------------------------------------------
HKLM\SYSTEM\CurrentControlSet\Services\MBRFilter

# ---------------------------------------------------------------------------
# Sanctum fs_minifilter driver service key
# ---------------------------------------------------------------------------
HKLM\SYSTEM\CurrentControlSet\Services\fs_minifilter
HKLM\SYSTEM\CurrentControlSet\Services\sanctum
HKLM\SYSTEM\CurrentControlSet\Services\edrdrv
HKLM\SYSTEM\CurrentControlSet\Services\edrsvc

# ---------------------------------------------------------------------------
# Winlogon Shell value - tampering here enables persistence via shell hijack.
# The driver enforces that the Shell value may only be set to explorer.exe.
# ---------------------------------------------------------------------------
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon
"####;

pub fn owlyshield_embedded_hook_exclude_rules() -> &'static str {
    OWLY_DYNAMIC_HOOK_EXCLUDE_RULES
}
