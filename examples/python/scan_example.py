import os
import sys
import json
from openedr_sdk import OpenEdrScanner

def main():
    portable_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "OpenMalwareScannerPortable"))
    dll_path = os.path.join(portable_dir, "openedr_static.dll")

    print(f"[*] Initializing OpenEDR Engine from: {portable_dir}")
    scanner = OpenEdrScanner(dll_path=dll_path, rules_dir=portable_dir)
    print("[+] Engine initialized successfully!\n")

    # 1. Scan File
    target_file = dll_path
    print(f"--- 1. File Scan: {os.path.basename(target_file)} ---")
    report = scanner.scan_file(target_file)
    print(f"Verdict : {report.get('verdict')}")
    print(f"SHA-256 : {report.get('sha256')}")
    signer = report.get('signer_info') or {}
    print(f"Signer  : trusted={signer.get('is_trusted')} status={signer.get('status')} "
          f"name={signer.get('signer_name')} catalog={signer.get('is_catalog_signed')}")
    print(f"Detections ({len(report.get('detections', []))}):")
    for det in report.get('detections', []):
        print(f"  - [{det.get('layer')}] {det.get('name')} (score: {det.get('score')})")
    print()

    # 2. Scan URL
    target_url = "http://phishing-paypal-security-update.com/login.php"
    print(f"--- 2. URL Scan: {target_url} ---")
    url_report = scanner.scan_url(target_url)
    print(f"Verdict : {url_report.get('verdict')}")
    print(f"Malware Probability : {url_report.get('malware_probability', 0.0) * 100:.2f}%")
    print()

    # 3. Check Registry
    reg_key = r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run\SuspiciousApp"
    print(f"--- 3. Registry Rule Check: {reg_key} ---")
    reg_report = scanner.check_registry(reg_key)
    print(f"Result : {json.dumps(reg_report, indent=2)}")

if __name__ == "__main__":
    main()
