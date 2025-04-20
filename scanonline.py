import os
import argparse
import hashlib
import requests
import re
import time
from functools import lru_cache

# Selenium imports for automatic upload
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options

@lru_cache(maxsize=1024)
def query_sha256_online_sync(sha256_hash):
    """
    Queries the GridinSoft online scanner by SHA-256 and returns a tuple:
        (status, virus_name)

    - If the HTTP status is 404: returns ("Unknown", "")
    - On any other non-200: returns ("Unknown (API error)", "")
    - If the page contains "Clean File": returns ("Benign", "")
    - If the page contains "Removal": extracts the token before "Removal" as the virus name,
      strips any HTML tags, and returns ("Malware", virus_name)
    - Otherwise: returns ("Unknown", "")
    """
    try:
        h = sha256_hash.lower()
        url = f"https://gridinsoft.com/online-virus-scanner/id/{h}"
        resp = requests.get(url)

        if resp.status_code == 404:
            return ("Unknown", "")
        if resp.status_code != 200:
            return ("Unknown (API error)", "")

        body = resp.text

        if "Clean File" in body:
            return ("Benign", "")

        if "Removal" in body:
            idx = body.find("Removal")
            before = body[:idx].strip().split()
            virus_name = before[-1] if before else ""
            virus_name = re.sub(r'<.*?>', '', virus_name)
            return ("Malware", virus_name)

        return ("Unknown", "")

    except Exception as ex:
        return (f"Error: {ex}", "")


def sha256_of_file(path):
    """Compute the SHA-256 hash of a file."""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def upload_file_for_analysis(path, sha256_hash):
    """
    When the scan result is Unknown, automatically upload the file
    to the gridinsoft form (id="file-input") on the same hash URL.
    """
    h = sha256_hash.lower()
    url = f"https://gridinsoft.com/online-virus-scanner/id/{h}"

    # Configure headless Chrome
    chrome_opts = Options()
    chrome_opts.add_argument('--headless')
    chrome_opts.add_argument('--no-sandbox')
    driver = webdriver.Chrome(options=chrome_opts)

    try:
        driver.get(url)
        # Wait for the file input to load
        time.sleep(2)
        file_input = driver.find_element(By.ID, "file-input")
        # Send the local file path to the input to trigger upload
        file_input.send_keys(os.path.abspath(path))
        # Allow some time for the upload to process
        time.sleep(5)
    finally:
        driver.quit()


def scan_file(path):
    """Compute hash, query online, handle unknown by uploading, and print the result for a single file."""
    h = sha256_of_file(path)
    status, virus_name = query_sha256_online_sync(h)

    # If still unknown, upload for further analysis and flag as New file
    if status == "Unknown":
        upload_file_for_analysis(path, h)
        status = "New file"

    # Print results
    if virus_name:
        print(f"[FILE] {path}\n       ➔ {status}  ({virus_name})")
    else:
        print(f"[FILE] {path}\n       ➔ {status}")


def scan_folder(folder_path):
    """Recursively scan every file in a folder."""
    for root, dirs, files in os.walk(folder_path):
        for fname in files:
            full_path = os.path.join(root, fname)
            scan_file(full_path)


def main():
    parser = argparse.ArgumentParser(description="Scan a file or folder via SHA-256 online lookup and auto-upload unknowns.")
    parser.add_argument('target', help='Path to a file or folder to scan')
    args = parser.parse_args()
    target = args.target

    if os.path.isdir(target):
        scan_folder(target)
    elif os.path.isfile(target):
        scan_file(target)
    else:
        print(f"Path not found: {target}")


if __name__ == "__main__":
    main()
