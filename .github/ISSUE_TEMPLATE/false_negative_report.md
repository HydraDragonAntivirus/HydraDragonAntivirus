---
name: False Negative Report
about: Report a malicious file that bypassed HydraDragon
title: '[FN] '
labels: false negative
assignees: ''
---

**Note: False Negative Reports**
Please use this template ONLY for reporting malware, ransomware, or malicious activity that HydraDragonAntivirus failed to detect or block.

**⚠️ IMPORTANT: Check Logs First ⚠️**
Before reporting a false negative, **please verify if the file was actually bypassed** by HydraDragonAntivirus. 
Check the logs in the following locations to confirm whether it was quietly blocked or logged:
- `C:\ProgramData\HydraDragonAntivirus\`
- `C:\Program Files\HydraDragonAntivirus\`
- Windows Event Viewer
- HydraDragon Notifications folder

**Malware Information**
- Malware Family / Type (if known): 
- SHA256 Hash: 
- Download Link (Password protected ZIP, e.g., 'infected' in your GitHub malware-samples repo): 

**Which component should have blocked it?**
- [ ] HydraDragonAV (C++ Engine with ClamAV and YARA rules)
- [ ] Owlyshield Ransomware Filter
- [ ] Sanctum
- [ ] Python Engine
- [ ] HydraDragonFirewall
- [ ] OpenEDR
- [ ] MBRFilter
- [ ] SimplePYASProtection
- [ ] TinyAntivirus

**Describe the bypass**
Explain how the malware was executed and what actions it took that were not prevented.

**VirusTotal Link**
Provide a link to the VirusTotal analysis for this file:

**Environment:**
 - OS: [e.g. Win 10 1909]
 - Version/Commit: [e.g. 0.1]

**Additional context**
Add any other context about the malware here.
