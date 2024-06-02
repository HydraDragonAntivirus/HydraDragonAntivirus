# Security Policy
Supported Versions
Version	Supported
Demo	:white_check_mark:
Reporting a Vulnerability
If you discover a security vulnerability within Hydra Dragon Antivirus, please report it to us promptly to ensure we can address the issue as quickly as possible. To report a vulnerability, follow these steps:

Contact: Email the details of the vulnerability to semaemirhan555@gmail.com.
Include Information:
Description of the vulnerability.
Steps to reproduce the vulnerability.
Potential impact and severity.
Any proof-of-concept code or screenshots, if available.
Confidentiality: Please keep the vulnerability information confidential until we have had a reasonable time to address it.
Security Measures
Installation Security
Verify Downloads: Ensure that all downloaded files for ClamAV, Snort, and Hydra Dragon Antivirus are obtained from official and trusted sources.
Secure Configuration: Follow the provided setup guidelines to ensure proper and secure installation of all components.
# Runtime Security
Process Management: Ensure malicious processes are terminated before performing any scan or quarantine operations.
Manual Stop of Services: Manually stop clamd service after using the application to prevent any unauthorized use.
# File Handling
Avoid Quarantine During Scans: Do not quarantine or delete files during an active scan to prevent potential system crashes or data loss.
Temporary Files: Regularly clean temporary files older than 24 hours to maintain system hygiene.
# Snort Configuration
Rule Management: Ensure that SO rules are disabled for Snort on Windows, as they are not supported.
Mandatory Files: Create necessary files such as black.list and white.list in the Snort rules directory, even if they are empty.
Directory Configuration: Adjust the configuration file if the Snort installation directory differs from the default C:\Snort.
# Best Practices
Regular Updates: Frequently update ClamAV definitions and Snort rules to stay protected against the latest threats.
System Integrity: Maintain system integrity by ensuring all configurations are correctly set and no unauthorized changes are made.
Monitoring and Alerts: Set up monitoring and alerting mechanisms to quickly identify and respond to any suspicious activity.
By adhering to these policies and guidelines, users can ensure that Hydra Dragon Antivirus operates securely and effectively, providing comprehensive protection for their systems.