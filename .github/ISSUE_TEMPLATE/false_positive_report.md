---
name: False Positive Report
about: Report a clean file that was incorrectly blocked by HydraDragon
title: '[FP] '
labels: false positive
assignees: ''
---

**Note: False Positive Reports**
Please use this template ONLY for reporting clean files that were flagged, blocked, or quarantined by HydraDragonAntivirus.

**⚠️ IMPORTANT: Check Logs First ⚠️**
Before reporting a false positive, **please verify if the file was actually flagged** by HydraDragonAntivirus. 
Check the logs in the following locations to confirm:
- `C:\ProgramData\HydraDragonAntivirus\`
- `C:\Program Files\HydraDragonAntivirus\`
- Windows Event Viewer
- Windows Notifcations

**File Information**
- Filename: 
- SHA256 Hash: 
- Download Link (if applicable): 
- Software Name / Publisher: 

**Which component blocked it?**
- [ ] HydraDragonAV (C++ Engine with ClamAV and YARA rules)
- [ ] Owlyshield Ransomware Filter
- [ ] Sanctum
- [ ] Python Engine
- [ ] HydraDragonFirewall
- [ ] OpenEDR
- [ ] MBRFilter
- [ ] SimplePYASProtection (Self-Defense Driver)
- [ ] TinyAntivirus
- [ ] DetectItEasy (Crypter Signatures)

**Describe the False Positive**
A clear description of what the software does and why it is benign.

**VirusTotal Link**
Provide a link to the VirusTotal analysis for this file (if uploaded):

**Additional context**
Add any other context about the file or detection here.
