# HydraDragon Threat Coverage Map

Generated: 2026-05-15

This map covers the consolidated zero-trust behavioral rules generated from current public research on syscall abuse, AMSI bypasses, ransomware recovery inhibition, process ghosting/herpaderping, credential dumping, persistence, and beaconing.

## Research Anchors

- syswhispers3: https://github.com/klezVirus/SysWhispers3
- syswhispers2: https://github.com/jthuraisamy/SysWhispers2
- hellsgate: https://github.com/am0nsec/HellsGate
- freshycalls: https://joasasantos-syswhispers4.mintlify.app/advanced/freshycalls
- elastic_endpoint: https://www.elastic.co/docs/reference/integrations/endpoint
- amsi_fail: https://amsi.fail/
- elastic_amsi: https://discuss.elastic.co/t/exception-for-potential-antimalware-scan-interface-bypass-via-powershell/378627
- mitre_t1490: https://attack.mitre.org/techniques/T1490/
- elastic_vss: https://www.elastic.co/docs/reference/security/prebuilt-rules/rules/windows/impact_volume_shadow_copy_deletion_or_resized_via_vssadmin
- lockbit_ng: https://www.trendmicro.com/content/dam/trendmicro/global/en/research/24/b/lockbit-attempts-to-stay-afloat-with-a-new-version/technical-appendix-lockbit-ng-dev-analysis.pdf
- cisa_lockbit: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-075a
- blackcat_ms: https://www.microsoft.com/en-us/security/blog/2022/06/13/the-many-lives-of-blackcat-ransomware/
- process_ghosting: https://www.elastic.co/blog/process-ghosting-a-new-executable-image-tampering-attack
- herpaderping: https://jxy-s.github.io/herpaderping/
- elastic_herp: https://detection.fyi/elastic/detection-rules/_deprecated/defense_evasion_potential_processherpaderping/
- mitre_t1055: https://attack.mitre.org/techniques/T1055/
- mitre_t1055_012: https://attack.mitre.org/techniques/T1055/012/
- mitre_t1071_001: https://attack.mitre.org/techniques/T1071/001/

## MITRE ATT&CK Coverage

### T1003.001

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-HIGH-0035 | [HIGH] LSASS OpenProcess ReadProcessMemory | 90 |
| HD-SAN-HIGH-0036 | [HIGH] LSASS MiniDumpWriteDump chain | 90 |
| HD-ZT-HIGH-0027 | [HIGH] Credential Dumping - procdump dumps LSASS | 90 |
| HD-ZT-HIGH-0028 | [HIGH] Credential Dumping - rundll32 comsvcs MiniDump LSASS | 90 |
| HD-ZT-HIGH-0029 | [HIGH] Credential Dumping - Task manager style LSASS dump | 90 |
| HD-ZT-HIGH-0030 | [HIGH] Credential Dumping - nanodump/ppldump LSASS | 90 |
| HD-ZT-HIGH-0034 | [HIGH] Credential Dumping - credential API memory read chain | 90 |

### T1003.002

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-HIGH-0031 | [HIGH] Credential Dumping - reg save SAM SYSTEM SECURITY | 90 |

### T1003.003

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-HIGH-0032 | [HIGH] Credential Dumping - ntdsutil creates IFM dump | 90 |
| HD-ZT-HIGH-0033 | [HIGH] Credential Dumping - vssadmin exposes NTDS shadow copy | 90 |

### T1014

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0037 | [CRITICAL] Unsigned driver load through Native API | 100 |
| HD-SAN-CRIT-0038 | [CRITICAL] Kernel callback tamper DeviceIoControl burst | 100 |

### T1016

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0052 | [MEDIUM] Suspicious Network Beaconing - Suspicious IP check and payload fetch | 72 |

### T1027

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0014 | [HIGH] AMSI Bypass - ScriptBlockAst manipulation | 88 |
| HD-AMSI-HIGH-0015 | [HIGH] AMSI Bypass - ScriptBlock Create from obfuscated string | 86 |
| HD-AMSI-HIGH-0019 | [HIGH] AMSI Bypass - .NET Assembly.Load from Base64 | 88 |
| HD-AMSI-HIGH-0029 | [HIGH] AMSI Bypass - Concatenated AmsiUtils string | 86 |
| HD-AMSI-HIGH-0033 | [HIGH] AMSI Bypass - NOP hidden encoded PowerShell | 88 |
| HD-AMSI-HIGH-0034 | [HIGH] AMSI Bypass - Reflection BindingFlags NonPublic Static | 86 |
| HD-AMSI-MED-0030 | [MEDIUM] AMSI Bypass - char-code AMSI string build | 84 |
| HD-AMSI-MED-0040 | [MEDIUM] AMSI Bypass - Suspicious base64 compressed PowerShell | 78 |

### T1036

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0031 | [CRITICAL] Process herpaderping overwrite-after-section | 100 |
| HD-SAN-HIGH-0045 | [HIGH] Compiler or temp builder launches ghosted child | 86 |
| HD-SAN-HIGH-0046 | [HIGH] Office parent spawns unusual renamed executable | 86 |
| HD-SAN-HIGH-0047 | [HIGH] Script host starts nonstandard executable extension | 86 |
| HD-SAN-HIGH-0048 | [HIGH] Archive utility parent starts transient PE | 86 |

### T1041

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0048 | [MEDIUM] Suspicious Network Beaconing - Discord webhook exfil | 72 |

### T1053.005

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0035 | [MEDIUM] Persistence - schtasks creates hidden system task | 76 |
| HD-ZT-MED-0036 | [MEDIUM] Persistence - PowerShell scheduled task registration | 76 |

### T1055

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0039 | [HIGH] AMSI Bypass - Reflection Emit shellcode loader | 88 |
| HD-SAN-CRIT-0001 | [CRITICAL] Direct Syscall Trampoline - Hell's Gate x64 mov-r10 syscall ret | 100 |
| HD-SAN-CRIT-0002 | [CRITICAL] Direct Syscall Trampoline - Hell's Gate syscall without ret | 100 |
| HD-SAN-CRIT-0003 | [CRITICAL] Direct Syscall Trampoline - mov eax syscall ret shellcode stub | 100 |
| HD-SAN-CRIT-0004 | [CRITICAL] Direct Syscall Trampoline - raw syscall ret gadget outside ntdll | 100 |
| HD-SAN-CRIT-0005 | [CRITICAL] Direct Syscall Trampoline - syscall ret immediate gadget | 100 |
| HD-SAN-CRIT-0006 | [CRITICAL] Direct Syscall Trampoline - legacy int2e syscall replacement | 100 |
| HD-SAN-CRIT-0007 | [CRITICAL] Direct Syscall Trampoline - sysenter replacement stub | 100 |
| HD-SAN-CRIT-0008 | [CRITICAL] Direct Syscall Trampoline - SysWhispers3 r11 jumper | 100 |
| HD-SAN-CRIT-0009 | [CRITICAL] Direct Syscall Trampoline - SysWhispers3 r10-r11 trampoline | 100 |
| HD-SAN-CRIT-0010 | [CRITICAL] Direct Syscall Trampoline - mov rax immediate jmp rax | 100 |
| HD-SAN-CRIT-0011 | [CRITICAL] Direct Syscall Trampoline - RIP-relative indirect syscall jmp | 100 |
| HD-SAN-CRIT-0012 | [CRITICAL] Direct Syscall Trampoline - near-jump hook into syscall gadget | 100 |
| HD-SAN-CRIT-0013 | [CRITICAL] Direct Syscall Trampoline - service id load followed by near jump | 100 |
| HD-SAN-CRIT-0014 | [CRITICAL] Direct Syscall Trampoline - LEA/JMP dynamically resolved gate | 100 |
| HD-SAN-CRIT-0015 | [CRITICAL] Direct Syscall Trampoline - clustered direct syscall stubs | 100 |
| HD-SAN-CRIT-0016 | [CRITICAL] Direct Syscall Trampoline - FreshyCalls unhooked syscall harvest | 100 |
| HD-SAN-CRIT-0017 | [CRITICAL] Direct Syscall Trampoline - BouncyGate-style indirect transfer | 100 |
| HD-SAN-CRIT-0018 | [CRITICAL] Direct Syscall Trampoline - WoW64 far transition syscall gate | 100 |
| HD-SAN-CRIT-0024 | [CRITICAL] RtlCreateUserThread after remote write | 100 |
| HD-SAN-CRIT-0027 | [CRITICAL] MapView shellcode execution pivot | 100 |
| HD-SAN-HIGH-0042 | [HIGH] Unbacked shellcode execution plus sensitive API | 90 |

### T1055.001

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-HIGH-0033 | [HIGH] Reflective DLL loader chain | 90 |
| HD-SAN-HIGH-0034 | [HIGH] SetWindowsHookEx DLL injection | 90 |

### T1055.002

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0019 | [CRITICAL] Remote allocation-write-thread syscall chain | 100 |
| HD-SAN-CRIT-0021 | [CRITICAL] Section map plus remote thread | 100 |
| HD-SAN-CRIT-0025 | [CRITICAL] Classic Win32 remote thread injection | 100 |
| HD-SAN-CRIT-0028 | [CRITICAL] Native section-backed remote map | 100 |

### T1055.003

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0022 | [CRITICAL] Thread context hijack and resume | 100 |

### T1055.004

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0020 | [CRITICAL] RWX protect-write-APC syscall chain | 100 |
| HD-SAN-CRIT-0026 | [CRITICAL] QueueUserAPC with remote memory staging | 100 |

### T1055.012

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0023 | [CRITICAL] Process hollowing unmap-write-context | 100 |
| HD-SAN-CRIT-0030 | [CRITICAL] Process ghosting delete-pending image section | 100 |
| HD-SAN-CRIT-0031 | [CRITICAL] Process herpaderping overwrite-after-section | 100 |
| HD-SAN-CRIT-0032 | [CRITICAL] Ghosted executable close-delete-execute | 100 |
| HD-SAN-HIGH-0045 | [HIGH] Compiler or temp builder launches ghosted child | 86 |
| HD-SAN-HIGH-0046 | [HIGH] Office parent spawns unusual renamed executable | 86 |
| HD-SAN-HIGH-0047 | [HIGH] Script host starts nonstandard executable extension | 86 |
| HD-SAN-HIGH-0048 | [HIGH] Archive utility parent starts transient PE | 86 |

### T1055.013

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0029 | [CRITICAL] Process doppelganging transaction rollback | 100 |

### T1059.001

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0033 | [HIGH] AMSI Bypass - NOP hidden encoded PowerShell | 88 |
| HD-AMSI-MED-0036 | [MEDIUM] AMSI Bypass - Obfuscated web cradle plus invoke expression | 75 |
| HD-AMSI-MED-0040 | [MEDIUM] AMSI Bypass - Suspicious base64 compressed PowerShell | 78 |

### T1060

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0038 | [MEDIUM] Persistence - Run key persistence | 76 |

### T1070.004

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-CRIT-0030 | [CRITICAL] Process ghosting delete-pending image section | 100 |
| HD-SAN-CRIT-0032 | [CRITICAL] Ghosted executable close-delete-execute | 100 |
| HD-ZT-MED-0026 | [MEDIUM] Ransomware IO Pattern - Rapid delete after unknown extension create | 78 |

### T1071.001

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0045 | [MEDIUM] Suspicious Network Beaconing - Dynamic DNS beacon domain | 72 |
| HD-ZT-MED-0046 | [MEDIUM] Suspicious Network Beaconing - Paste/service C2 staging | 72 |
| HD-ZT-MED-0047 | [MEDIUM] Suspicious Network Beaconing - Telegram bot API beacon | 72 |
| HD-ZT-MED-0054 | [MEDIUM] Suspicious Network Beaconing - Rare user-agent beacon body marker | 72 |

### T1090

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0049 | [MEDIUM] Suspicious Network Beaconing - Cloudflare tunnel client beacon | 72 |
| HD-ZT-MED-0050 | [MEDIUM] Suspicious Network Beaconing - Ngrok tunnel client beacon | 72 |

### T1090.003

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0051 | [MEDIUM] Suspicious Network Beaconing - Tor bootstrap from non-browser | 72 |

### T1102

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0047 | [MEDIUM] Suspicious Network Beaconing - Telegram bot API beacon | 72 |
| HD-ZT-MED-0048 | [MEDIUM] Suspicious Network Beaconing - Discord webhook exfil | 72 |

### T1105

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-MED-0036 | [MEDIUM] AMSI Bypass - Obfuscated web cradle plus invoke expression | 75 |
| HD-ZT-MED-0046 | [MEDIUM] Suspicious Network Beaconing - Paste/service C2 staging | 72 |
| HD-ZT-MED-0049 | [MEDIUM] Suspicious Network Beaconing - Cloudflare tunnel client beacon | 72 |
| HD-ZT-MED-0050 | [MEDIUM] Suspicious Network Beaconing - Ngrok tunnel client beacon | 72 |
| HD-ZT-MED-0052 | [MEDIUM] Suspicious Network Beaconing - Suspicious IP check and payload fetch | 72 |
| HD-ZT-MED-0053 | [MEDIUM] Suspicious Network Beaconing - Object storage payload staging | 72 |

### T1106

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0020 | [HIGH] AMSI Bypass - Add-Type DllImport VirtualProtect | 90 |
| HD-AMSI-HIGH-0021 | [HIGH] AMSI Bypass - Delegate GetFunctionPointerForDelegate | 85 |
| HD-AMSI-HIGH-0022 | [HIGH] AMSI Bypass - UnsafeNativeMethods GetProcAddress | 88 |

### T1197

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0041 | [MEDIUM] Persistence - BITS job persistence or download | 76 |

### T1218.005

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0042 | [MEDIUM] Persistence - mshta remote script execution | 76 |

### T1218.009

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0044 | [MEDIUM] Persistence - installutil/regsvr32 LOLBin persistence | 76 |

### T1218.010

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0044 | [MEDIUM] Persistence - installutil/regsvr32 LOLBin persistence | 76 |

### T1218.011

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0043 | [MEDIUM] Persistence - rundll32 JavaScript or scriptlet proxy | 76 |

### T1486

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-CRIT-0001 | [CRITICAL] Shadow Copy / Recovery Destruction - vssadmin delete all shadows | 100 |
| HD-ZT-CRIT-0002 | [CRITICAL] Shadow Copy / Recovery Destruction - vssadmin resize shadowstorage tiny | 100 |
| HD-ZT-CRIT-0003 | [CRITICAL] Shadow Copy / Recovery Destruction - wmic shadowcopy delete | 100 |
| HD-ZT-CRIT-0004 | [CRITICAL] Shadow Copy / Recovery Destruction - PowerShell WMI shadow copy delete | 100 |
| HD-ZT-CRIT-0005 | [CRITICAL] Shadow Copy / Recovery Destruction - wbadmin backup catalog deletion | 100 |
| HD-ZT-CRIT-0006 | [CRITICAL] Shadow Copy / Recovery Destruction - diskshadow deletes all shadows | 100 |
| HD-ZT-CRIT-0007 | [CRITICAL] Shadow Copy / Recovery Destruction - bcdedit disables recovery | 100 |
| HD-ZT-CRIT-0008 | [CRITICAL] Shadow Copy / Recovery Destruction - reagentc disables WinRE | 100 |
| HD-ZT-CRIT-0009 | [CRITICAL] Shadow Copy / Recovery Destruction - PowerShell deletes restore points | 100 |
| HD-ZT-CRIT-0010 | [CRITICAL] Shadow Copy / Recovery Destruction - registry disables system restore | 100 |
| HD-ZT-CRIT-0011 | [CRITICAL] Shadow Copy / Recovery Destruction - VSS service stop or disable | 100 |
| HD-ZT-CRIT-0012 | [CRITICAL] Shadow Copy / Recovery Destruction - backup product service termination | 100 |
| HD-ZT-CRIT-0013 | [CRITICAL] Shadow Copy / Recovery Destruction - delete Windows backup files | 100 |
| HD-ZT-CRIT-0014 | [CRITICAL] Shadow Copy / Recovery Destruction - wevtutil clears logs pre-impact | 96 |
| HD-ZT-CRIT-0015 | [CRITICAL] Shadow Copy / Recovery Destruction - compound recovery sabotage chain | 100 |
| HD-ZT-HIGH-0016 | [HIGH] Ransomware IO Pattern - High-rate encrypted document writes | 88 |
| HD-ZT-HIGH-0017 | [HIGH] Ransomware IO Pattern - Mass rename to ransomware extensions | 88 |
| HD-ZT-HIGH-0018 | [HIGH] Ransomware IO Pattern - Intermittent encryption write-rename cadence | 90 |
| HD-ZT-HIGH-0019 | [HIGH] Ransomware IO Pattern - Partial overwrite of many user files | 88 |
| HD-ZT-HIGH-0020 | [HIGH] Ransomware IO Pattern - Ransom note fan-out | 86 |
| HD-ZT-HIGH-0021 | [HIGH] Ransomware IO Pattern - LockBit style extension and note | 90 |
| HD-ZT-HIGH-0022 | [HIGH] Ransomware IO Pattern - BlackCat/ALPHV extension and note | 90 |
| HD-ZT-MED-0023 | [MEDIUM] Ransomware IO Pattern - Mass office file rewrites | 78 |
| HD-ZT-MED-0024 | [MEDIUM] Ransomware IO Pattern - Mass source-code file rewrites | 76 |
| HD-ZT-MED-0025 | [MEDIUM] Ransomware IO Pattern - High entropy writes after archive staging | 80 |
| HD-ZT-MED-0026 | [MEDIUM] Ransomware IO Pattern - Rapid delete after unknown extension create | 78 |

### T1489

| Rule ID | Rule | Score |
|---|---|---:|
| HD-SAN-HIGH-0041 | [HIGH] Process protection disable attempt | 90 |

### T1490

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-CRIT-0001 | [CRITICAL] Shadow Copy / Recovery Destruction - vssadmin delete all shadows | 100 |
| HD-ZT-CRIT-0002 | [CRITICAL] Shadow Copy / Recovery Destruction - vssadmin resize shadowstorage tiny | 100 |
| HD-ZT-CRIT-0003 | [CRITICAL] Shadow Copy / Recovery Destruction - wmic shadowcopy delete | 100 |
| HD-ZT-CRIT-0004 | [CRITICAL] Shadow Copy / Recovery Destruction - PowerShell WMI shadow copy delete | 100 |
| HD-ZT-CRIT-0005 | [CRITICAL] Shadow Copy / Recovery Destruction - wbadmin backup catalog deletion | 100 |
| HD-ZT-CRIT-0006 | [CRITICAL] Shadow Copy / Recovery Destruction - diskshadow deletes all shadows | 100 |
| HD-ZT-CRIT-0007 | [CRITICAL] Shadow Copy / Recovery Destruction - bcdedit disables recovery | 100 |
| HD-ZT-CRIT-0008 | [CRITICAL] Shadow Copy / Recovery Destruction - reagentc disables WinRE | 100 |
| HD-ZT-CRIT-0009 | [CRITICAL] Shadow Copy / Recovery Destruction - PowerShell deletes restore points | 100 |
| HD-ZT-CRIT-0010 | [CRITICAL] Shadow Copy / Recovery Destruction - registry disables system restore | 100 |
| HD-ZT-CRIT-0011 | [CRITICAL] Shadow Copy / Recovery Destruction - VSS service stop or disable | 100 |
| HD-ZT-CRIT-0012 | [CRITICAL] Shadow Copy / Recovery Destruction - backup product service termination | 100 |
| HD-ZT-CRIT-0013 | [CRITICAL] Shadow Copy / Recovery Destruction - delete Windows backup files | 100 |
| HD-ZT-CRIT-0014 | [CRITICAL] Shadow Copy / Recovery Destruction - wevtutil clears logs pre-impact | 96 |
| HD-ZT-CRIT-0015 | [CRITICAL] Shadow Copy / Recovery Destruction - compound recovery sabotage chain | 100 |

### T1543.003

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0040 | [MEDIUM] Persistence - service creation for persistence | 76 |

### T1546.003

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0037 | [MEDIUM] Persistence - WMI event filter persistence | 76 |

### T1547.001

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0039 | [MEDIUM] Persistence - Startup folder dropped script | 76 |

### T1560

| Rule ID | Rule | Score |
|---|---|---:|
| HD-ZT-MED-0025 | [MEDIUM] Ransomware IO Pattern - High entropy writes after archive staging | 80 |

### T1562.001

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-CRIT-0001 | [CRITICAL] AMSI Bypass - AmsiUtils reflection type lookup | 100 |
| HD-AMSI-CRIT-0002 | [CRITICAL] AMSI Bypass - amsiInitFailed static field flip | 100 |
| HD-AMSI-CRIT-0003 | [CRITICAL] AMSI Bypass - AmsiScanBuffer export resolution | 98 |
| HD-AMSI-CRIT-0004 | [CRITICAL] AMSI Bypass - AmsiOpenSession patch target | 96 |
| HD-AMSI-CRIT-0005 | [CRITICAL] AMSI Bypass - AmsiContext or AmsiSession corruption | 96 |
| HD-AMSI-CRIT-0006 | [CRITICAL] AMSI Bypass - VirtualProtect against AMSI region | 100 |
| HD-AMSI-CRIT-0007 | [CRITICAL] AMSI Bypass - Marshal Copy AMSI memory patch | 100 |
| HD-AMSI-CRIT-0008 | [CRITICAL] AMSI Bypass - NonPublic Static GetField reflection | 98 |
| HD-AMSI-CRIT-0009 | [CRITICAL] AMSI Bypass - SetValue null true AMSI flip | 96 |
| HD-AMSI-CRIT-0010 | [CRITICAL] AMSI Bypass - LoadLibrary amsi.dll | 96 |
| HD-AMSI-CRIT-0011 | [CRITICAL] AMSI Bypass - GetProcAddress AmsiScanBuffer | 98 |
| HD-AMSI-CRIT-0012 | [CRITICAL] AMSI Bypass - AMSI E_INVALIDARG patch bytes | 100 |
| HD-AMSI-CRIT-0025 | [CRITICAL] AMSI Bypass - Hardware breakpoint AMSI bypass | 96 |
| HD-AMSI-HIGH-0013 | [HIGH] AMSI Bypass - Byte array return clean patch | 90 |
| HD-AMSI-HIGH-0014 | [HIGH] AMSI Bypass - ScriptBlockAst manipulation | 88 |
| HD-AMSI-HIGH-0016 | [HIGH] AMSI Bypass - Cached group policy logging suppression | 90 |
| HD-AMSI-HIGH-0017 | [HIGH] AMSI Bypass - Script block logging disabled | 88 |
| HD-AMSI-HIGH-0020 | [HIGH] AMSI Bypass - Add-Type DllImport VirtualProtect | 90 |
| HD-AMSI-HIGH-0022 | [HIGH] AMSI Bypass - UnsafeNativeMethods GetProcAddress | 88 |
| HD-AMSI-HIGH-0023 | [HIGH] AMSI Bypass - WriteInt32 amsiContext overwrite | 92 |
| HD-AMSI-HIGH-0024 | [HIGH] AMSI Bypass - PtrToStructure amsi context manipulation | 88 |
| HD-AMSI-HIGH-0026 | [HIGH] AMSI Bypass - AmsiX64/AmsiX32 patch helper | 90 |
| HD-AMSI-HIGH-0027 | [HIGH] AMSI Bypass - AMSI provider nulling | 90 |
| HD-AMSI-HIGH-0028 | [HIGH] AMSI Bypass - CLR amsi scan patcher | 90 |
| HD-AMSI-HIGH-0029 | [HIGH] AMSI Bypass - Concatenated AmsiUtils string | 86 |
| HD-AMSI-HIGH-0031 | [HIGH] AMSI Bypass - ScanBuffer forced clean/invalid return | 90 |
| HD-AMSI-HIGH-0034 | [HIGH] AMSI Bypass - Reflection BindingFlags NonPublic Static | 86 |
| HD-AMSI-HIGH-0035 | [HIGH] AMSI Bypass - AppDomain assembly enumeration for AMSI | 86 |
| HD-AMSI-HIGH-0038 | [HIGH] AMSI Bypass - AMSI.fail generated bypass markers | 94 |
| HD-AMSI-MED-0037 | [MEDIUM] AMSI Bypass - PowerShell Defender preference disable | 82 |
| HD-SAN-CRIT-0001 | [CRITICAL] Direct Syscall Trampoline - Hell's Gate x64 mov-r10 syscall ret | 100 |
| HD-SAN-CRIT-0002 | [CRITICAL] Direct Syscall Trampoline - Hell's Gate syscall without ret | 100 |
| HD-SAN-CRIT-0003 | [CRITICAL] Direct Syscall Trampoline - mov eax syscall ret shellcode stub | 100 |
| HD-SAN-CRIT-0004 | [CRITICAL] Direct Syscall Trampoline - raw syscall ret gadget outside ntdll | 100 |
| HD-SAN-CRIT-0005 | [CRITICAL] Direct Syscall Trampoline - syscall ret immediate gadget | 100 |
| HD-SAN-CRIT-0006 | [CRITICAL] Direct Syscall Trampoline - legacy int2e syscall replacement | 100 |
| HD-SAN-CRIT-0007 | [CRITICAL] Direct Syscall Trampoline - sysenter replacement stub | 100 |
| HD-SAN-CRIT-0008 | [CRITICAL] Direct Syscall Trampoline - SysWhispers3 r11 jumper | 100 |
| HD-SAN-CRIT-0009 | [CRITICAL] Direct Syscall Trampoline - SysWhispers3 r10-r11 trampoline | 100 |
| HD-SAN-CRIT-0010 | [CRITICAL] Direct Syscall Trampoline - mov rax immediate jmp rax | 100 |
| HD-SAN-CRIT-0011 | [CRITICAL] Direct Syscall Trampoline - RIP-relative indirect syscall jmp | 100 |
| HD-SAN-CRIT-0012 | [CRITICAL] Direct Syscall Trampoline - near-jump hook into syscall gadget | 100 |
| HD-SAN-CRIT-0013 | [CRITICAL] Direct Syscall Trampoline - service id load followed by near jump | 100 |
| HD-SAN-CRIT-0014 | [CRITICAL] Direct Syscall Trampoline - LEA/JMP dynamically resolved gate | 100 |
| HD-SAN-CRIT-0015 | [CRITICAL] Direct Syscall Trampoline - clustered direct syscall stubs | 100 |
| HD-SAN-CRIT-0016 | [CRITICAL] Direct Syscall Trampoline - FreshyCalls unhooked syscall harvest | 100 |
| HD-SAN-CRIT-0017 | [CRITICAL] Direct Syscall Trampoline - BouncyGate-style indirect transfer | 100 |
| HD-SAN-CRIT-0018 | [CRITICAL] Direct Syscall Trampoline - WoW64 far transition syscall gate | 100 |
| HD-SAN-CRIT-0037 | [CRITICAL] Unsigned driver load through Native API | 100 |
| HD-SAN-CRIT-0038 | [CRITICAL] Kernel callback tamper DeviceIoControl burst | 100 |
| HD-SAN-HIGH-0039 | [HIGH] ETW Threat Intelligence provider patch | 90 |
| HD-SAN-HIGH-0040 | [HIGH] AMSI module memory patch from native telemetry | 90 |
| HD-SAN-HIGH-0041 | [HIGH] Process protection disable attempt | 90 |
| HD-SAN-HIGH-0043 | [HIGH] Hardware breakpoint EDR bypass setup | 90 |
| HD-SAN-HIGH-0044 | [HIGH] Hook bypass by restoring ntdll text | 90 |
| HD-ZT-HIGH-0030 | [HIGH] Credential Dumping - nanodump/ppldump LSASS | 90 |

### T1562.006

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0018 | [HIGH] AMSI Bypass - ETW EventWrite tamper from script | 92 |
| HD-SAN-HIGH-0039 | [HIGH] ETW Threat Intelligence provider patch | 90 |

### T1562.010

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0032 | [HIGH] AMSI Bypass - PowerShell v2 downgrade | 86 |

### T1620

| Rule ID | Rule | Score |
|---|---|---:|
| HD-AMSI-HIGH-0019 | [HIGH] AMSI Bypass - .NET Assembly.Load from Base64 | 88 |
| HD-AMSI-HIGH-0039 | [HIGH] AMSI Bypass - Reflection Emit shellcode loader | 88 |

## Consolidation Notes

- `sanctum_syscall_rules_fixed.yaml` owns direct/indirect syscall, shellcode trampoline, injection chain, kernel tamper, and process ghosting/herpaderping detections.
- `amsi_detection_rules_fixed.yaml` owns AMSI and PowerShell/.NET content detections, with wildcard and regex patterns evaluated against captured AMSI samples.
- `zero_trust_behavior_rules_fixed.yaml` owns ransomware IO, recovery inhibition, credential access, persistence, and suspicious beaconing rules.
- `behavior_rules_fixed.yaml` includes the consolidated files so the existing rule loader sees the expanded hierarchy.
