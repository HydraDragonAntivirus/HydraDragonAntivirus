# Hydra Dragon Antivirus
<p align="center">
<img src="assets/HydraDragonAntivirus.png" width= 400px>
</p>
<p align="center">
<img src="assets/HydraDragonAntivirusGUI.png" width= 800px>
</p>
Dynamic and Static Analysis with Sandboxie for Windows with ClamAV, YARA-X and my machine learning AI module also Snort
# Download Machine Learning Malware And Benign Database
- Malware Database: https://drive.google.com/file/d/1QwdxdwX_nH-oF-5hVTkbTuFkrwUfR0-h
- Benign Database: https://drive.google.com/file/d/1ynUPnLLm3O6QrlCpDz7A0h1QqjIK3Icc
- Notice: Only contains PE files.
- Password: infected
# Guide
Notice: You must create DefaultBox at Sandboxie by running them once at random application also please clean C:\Sandbox folder items.
Just wait 1-2 minute if you open this application after 6 hours because it is updating ClamAV definitions. It's not well tested. If you find an issue, please create issue.  Antiviruses might be triggered by website signatures because they are not obfuscated so exclude C:\Program Files\HydraDragonAntivirus folder. Please only use in VM as you can only use this for deep analysis of a file. There is no analysis time for a file. 
### FAQ: 
+ Does this collect data?
- No.
+ How do I use it?
- Just run a shortcut from the desktop, then run advanced dynamic and static analysis on a file.
+ How good is it?
- It's so good at static analysis. It's better than Dr.Web and Comodo, but Norton and Kaspersky are better than my product at static analysis. In dynamic analysis it is so good at detecting unknown malware and clearly better than ClamAV in static analysis and ClamAV doesn't have dynamic analysis. It's the best Turkish and open-source malware analysis product but it's so aggressive.
+ Why does my antivirus detect this as malware?
- It's a false positive and it's a one-file compiled Nuitka file, also it contains website signatures without obfuscation. It's a completely open source product.
+ Why is it 300MB?
- Because of website signatures. They are not very effective, but they can detect old viruses. If you want, I can remove them.
+ I get unexcepted errors when using compiled YARA-X rules.
- I don't usually get this problem, but with CollabVM I did.
+ Supported Windows versions?
- Windows 10 64-bit and Windows 11 only (you can run ClamAV but you can't run HydraDragonAntivirus on Windows 8.1 and it's not supported) but if you want I can create 32-bit version for Windows 10 32-bit but (I faced some problems) ClamAV have limitations on 32-bit so it's problematic. On Windows 8.1 ClamAV doesn't support it because it's an outdated Windows. You will get api-ms-win-crt-runtime-l1-1-0.dll error. Even if you add this dll you will get another error application failed to start properly 0xc000007b then install this: https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist?view=msvc-170  After running C:\Program Files\ClamAV\freshclam.exe and clamd.exe with clamd --install, the setup is complete, but you can't run HydraDragonAntivirus on Windows 8.1 because you get an ImportError on line nine, due to PySide6.
+ Minimum RAM?
- 4 GB RAM is the minimum.
+ Any sponsors or supporters?
- Yes, there are supporters of this project. Xcitium (Comodo) says we will support this project by sending malware samples and Cisco Talos ClamAV community projects. 