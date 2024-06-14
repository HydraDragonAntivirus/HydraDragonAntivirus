# Hydra Dragon Antivirus
<p align="center">
<img src="assets/HydraDragonAntivirus.png" width= 400px>
</p>
<p align="center">
<img src="assets/HydraDragonAntivirusGUI.png" width= 800px>
</p>
Cross-platform antivirus GUI for ClamAV, YARA and my machine learning AI module also Snort.
Guide:
Please install ClamAV based on your platform and enter database directory and please run clamd
Please copy the database folder signatures into your ClamAV database folder and copy freshclam.conf into your ClamAV config folder.
Also do the update definitions yourself, it's just a cross-platform interface for ClamAV and Hydra Dragon Antivirus.
Don't forget to install the modules via pip with requriements.txt and don't forget to compile the python script yourself.
Please don't use hash signatures as they are easily bypassed and take up too much space.
Also, don't forget to add ClamAV's clamdscan to the console so that the program can be run with just the clamdscan command on Windows, Linux, MacOS, FreeBSD, etc.
compiled_rule.yrc source code: https://sourceforge.net/p/xylent/git/ci/master/tree/backend/rules/yara I have just compiled the largest file or you can look at compiled_rule.yar.
I recommend killing malicious processes first, then using quarantine, delete or something. For Windows, first install clamav from clamav.net/downloads.
Then add C:\Program Files\ClamAV to the terminal, as this script uses ClamAV directly from the terminal, then run the script to use it. 
Also install Python from python.org Note: If you can't add ClamAV to the console on Windows etc, then copy it to the ClamAV folder
For Windows you also need download https://npcap.com/#download for scapy and netsh advfirewall reset for reset firewall settings
For Snort download at there: https://www.snort.org/downloads and add to console
If you want run web signatures then you need load website signatures by button
HIPS folder things should be add Snort rules folder also config things
If you want do scan, you first need enable it by button
You need stop clamd manually after close this program
For more protection for Windows please install MBRFilter at mbrfilter folder
Don't quarantine any files during the scan or delete.
To avoid crashes pause or stop scan while scan is running at scan manager screen.
Don't forget clean temp files older than 24 hours.
Just comment Example in clamd.conf.sample and rename it with clamd.conf then copy to config folder of ClamAV.
# Snort Notes
Notes
Snort on Windows does not like SO rules - that is why they are disabled.

If Snort can't find blacklists, whitelists and other files - an error will be thrown. They need to be presented, even if empty.

Current files that you must create: C:\Snort\rules\black.list and C:\Snort\rules\white.list. If you want to use different files - you must modify the configuration file manually.

Also the configuration presumes that your installation is C:\Snort, if it is different, then change it manually from the config file.

https://rules.emergingthreats.net/open/ Download Rules From There

Don't forget to check all boxes at npcap also if you get this warning then ignore it. Wireshark is not required:  https://ask.wireshark.org/question/33483/why-do-i-get-this-wireshark-is-installed-but-cannot-read-manuf-when-i-use-wireshark/

# Download Machine Learnin Malware And Benign Database
- Malware Database: https://mega.nz/file/1CcGTRoQ#Chp5oNpk2ExhcCjrlY1Q_n0w9ToF5ozGdyn5hjfmQdk
- Benign Database: https://mega.nz/file/wOVmTJTS#qywYEZWYBKmvc8z6CtLNxJh4L9MBcvQIY9Mb7pQapik
- Notice: Only contains PE files.

# Hydra Dragon Antivirus AI Generated Text
Overview
Hydra Dragon Antivirus is a cross-platform antivirus GUI that integrates ClamAV, YARA, a machine learning AI module, and Snort to provide comprehensive security solutions. This policy outlines the security measures, practices, and guidelines for users to follow when using Hydra Dragon Antivirus to ensure optimal protection and system stability.

Installation and Setup
ClamAV Installation:

Install ClamAV based on your operating system (Windows, Linux, MacOS, FreeBSD).
Configure the database directory and run clamd.
Copy the provided database folder signatures into your ClamAV database folder.
Copy freshclam.conf into your ClamAV config folder.
Update the definitions manually.
Python Environment:

Install required Python modules via pip using the requirements.txt file.
Compile the Python script yourself.
Command Line Configuration:

Add clamdscan to the system path for easy access to ClamAV functionalities.
On Windows, add C:\Program Files\ClamAV to the terminal path.
Additional Software:

Download and install npcap for Scapy support: Npcap Download.
Reset firewall settings using netsh advfirewall reset.
Download and configure Snort: Snort Downloads.
Install MBRFilter from the mbrfilter folder for enhanced protection.
Usage Guidelines
Malicious Process Handling:

Kill malicious processes before performing quarantine or delete operations.
ClamAV and ClamDScan:

Ensure ClamAV is added to the console path.
Manually stop clamd after closing the program to free system resources.
Snort Configuration:

Snort on Windows does not support SO rules; ensure they are disabled.
Create necessary files such as C:\Snort\rules\black.list and C:\Snort\rules\white.list, even if they are empty.
Adjust the Snort configuration file if your installation directory is different from C:\Snort.
Signature and Rule Management:

Avoid using hash signatures as they can be easily bypassed and are space-consuming.
For web signatures, use the appropriate button to load them.
Add HIPS folder contents to the Snort rules folder, including configuration files.
Scanning Practices:

Enable scanning via the designated button before starting a scan.
Do not quarantine or delete files during an active scan to avoid system crashes.
Pause or stop scans using the scan manager screen if necessary.
Clean temporary files older than 24 hours to maintain system performance.

Maintenance and Updates
Regularly update ClamAV definitions and Snort rules to ensure the latest protection.
Follow best practices for security updates and patch management.
Contact Information
For any security concerns or issues, please contact the Hydra Dragon Antivirus support team.