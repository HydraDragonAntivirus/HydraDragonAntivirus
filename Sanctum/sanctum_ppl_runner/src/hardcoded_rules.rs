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
c:\windows\system32\drivers\edrdrv.sys
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
c:\windows\system32\drivers\edrdrv.sys
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
c:\windows\system32\drivers\edrdrv.sys
c:\windows\system32\drivers\OwlyshieldRansomFilter.sys
c:\windows\system32\drivers\RedDbg.sys
c:\windows\system32\drivers\hyperhv.sys

# Sanctum install directory
c:\program files\hydradragonantivirus\hydradragon\sanctum


"####;

pub fn owlyshield_embedded_hook_exclude_rules() -> &'static str {
    OWLY_DYNAMIC_HOOK_EXCLUDE_RULES
}

