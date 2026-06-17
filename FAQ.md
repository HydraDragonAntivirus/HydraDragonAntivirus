# Frequently Asked Questions (FAQ)

### Q: Why it doesn't detect Non-Windows viruses?
- I removed almost every non Windows malware signatures to improve performance.

### Q: Why is this repository still mostly YARA?
- This is mainly because auto-generated YARA rules produced through machine learning have not been archived. As a result, the repository still contains a large number of manually created rules.
- Additionally, the archived rules remain substantial in size because, for many years, malware analysts heavily relied on signature-based detection methods. While effective in certain scenarios, this approach is now considered less optimal compared to more modern techniques.
- As you may notice, with the introduction of OpenEDR, the proportion of YARA has decreased significantly, and C++ has become the second most prominent language in the repository.

### Q: Does the program collect data and is there a cloud-based detection?
- OpenEDR sends telemetry to Valkyrie to detect more malware (valkyrie.comodo.com).
- **Note on Trust**: We provide a granular trust policy. In our YAML rules, you can set `should_trust_comodo_cloud: true` to honor Comodo's Valkyrie static analysis results (FLS v7 protocol). We've implemented a high-performance, non-blocking telemetry pipeline that synchronizes cloud verdicts (0: Malware, 1: Safe, 2: Unrecognized, 3: Unknown) with the IPC layer for sub-millisecond heuristic bypass. However, dynamic analysis results are never trusted blindly, as malware can evade cloud sandboxes; therefore, local behavioral heuristics always take precedence for active execution.
- **The Process Hollowing Problem**: We do **not** send a "Safe" signal to the firewall based on static or cloud analysis. This is because of *Process Hollowing* (where a legitimate process is hijacked or its memory replaced with malicious code). If we marked a process as "Safe" and stopped monitoring, a hollowed process could bypass security. By maintaining Owlyshield as the central controller, we ensure that even "Trusted" processes are continuously monitored for suspicious behavioral deviations.

### Q: How do I use it?
- Just run the shortcut from the desktop (if not started yet). Note that there is **no manual "Scan" button** in the main interface (except for the experimental scan in Sanctum, which is a PoC and not fully effective for all file types). 
- **Focus on Zero-Days**: This project is designed as a proactive behavioral engine. It focuses on detecting **Zero-day threats when they are in action**. Instead of scanning static files, it monitors process behavior, IRP operations, and network activity in real-time, leveraging OpenEDR cloud telemetry to verify active processes.
- **Architectural Complexity**: Maintaining this level of protection across multiple EDR/XDR components involves massive complexity—over millons of lines specialized logic across Rust, C++, and driver code—to ensure the system remains resilient and context-aware.

### Q: How good is it?
- It's very good at every type of analysis and it balances everything with allowing you configure more aggressive or less aggressive.

### Q: Why does my antivirus detect this as malware?
- It's a false positive. It's contains the WinDivert (Vulnerable driver), website, HIPS signatures without obfuscation. It's a fully open source executable analysis product.

### Q: Why is it 2GB+?
- Because of website signatures, Ghidra, ClamAV and Java Development Kit. Website signatures are not very effective but they can detect old and new viruses. I can remove them if you want. Ghidra is for decompiling but takes too much space. Java Development Kit is for Ghidra. That's 1GB+ Note that it's a completely local (except update database) and professional open source antivirus.

### Q: Why does the antivirus.exe application take too long to run?
- Sometimes you may have to wait 5+ minutes (or less) the first time you run the programme as a lot of things load.

### Q: Which Windows versions are supported?
- Windows 10 no longer offically supported. Switch to Windows 11 25H2.

### Q: What are the minimum RAM and disk space requirements?
- A minimum of 4 GB of RAM is required (thanks to optimizations, it generally use less than 1GB) but 8 GB is recommended.

### Q: Any sponsors or supporters?
- Yes, there are supporters for this project. Xcitium (Comodo) has expressed interest in supporting this project by providing malware samples, and Cisco Talos ClamAV community projects. But it's still a one man project.

### Q: Are you using leaked YARA rules?
- No we don't but if you have proof please create issue we can remove it.

### Q: Why don't you use NictaSoft, GridinSoft and Bitdefender cloud?
- It could significantly boost my antivirus. However, there are some problems. These services are not open source unless you pay. We're not only focused on detection, but also committed to maintaining open-source principles.

### Q: Other related things?
- I used yarGen to create machinelearning_*.yar.

### Q: Why you make this open source? Isn't security through obscurity better?
- If I don't make this project open source then I can't use other open source tools and it will make him shit like other too new and unknown closed source AVs. If you able to protect your source like Kaspersky (only leaked once from 2008 version, other leaks are fake also latest version has anti tamper protection from kernel so it's protects his source well.) but not like others Bitdefender (API + signatures solveable) Norton (Leaked his source once) Malwarebytes (leaked his source four times) Zemana (Cloud solveable and C# but currently his cloud is down) Windows Defender (DefenderYARA converted rules to YARA) and many other bad examples... in short if you able to protect your source code then why not to make closed source right? For extra security you can do that.
- So I'm not againist closed source if you able to protect source code without false alarms from other AVs. But since I want to make better with open source tools and want open source community support I made them open source. That's of course have huge disadvantages and advantages. But I can't spend my time to create everything from scratch and protect my source code well withotu false alarms, it will take forever.

### Q: How many repositories did you look at for this project?
- For YARA and website signatures, I looked at many projects-possibly more than 1,000.

### Q: Why doesn't the program open?
- Your installation might be broken. You can check the logs to determine the issue, because if the connection was lost during installation, it can affect the installation significantly. Try reinstalling to fix the problem.
