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
I highly recommend if you going to use signature checking don't use microsoft signature checking only if you are going to check microsoft
signatures

# Snort Notes
Notes
Snort on Windows does not like SO rules - that is why they are disabled.

If Snort can't find blacklists, whitelists and other files - an error will be thrown. They need to be presented, even if empty.

Current files that you must create: C:\Snort\rules\black.list and C:\Snort\rules\white.list. If you want to use different files - you must modify the configuration file manually.

Also the configuration presumes that your installation is C:\Snort, if it is different, then change it manually from the config file.

https://rules.emergingthreats.net/open/ Download Rules From There