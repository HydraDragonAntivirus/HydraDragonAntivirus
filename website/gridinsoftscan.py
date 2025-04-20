import requests
import csv
import re
import html
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

GRIDINSOFT_URL = "https://gridinsoft.com/online-virus-scanner/url/"
CSV_FILE = "DomainScanResults.csv"
MAX_THREADS = 100

# Regex patterns
REVIEW_RE = re.compile(
    r'<h1[^>]*class="[^"]*bCheckId__title[^"]*"[^>]*>'
    r'.*?<span[^>]*class="[^"]*small[^"]*"[^>]*>\s*(.*?)\s*</span>',
    re.IGNORECASE | re.DOTALL
)
POINTS_RE = re.compile(
    r'<div[^>]*id="bScalePoints"[^>]*data-points\s*=\s*"(\d+)"',
    re.IGNORECASE
)
ITEM_RE = re.compile(
    r'<div[^>]*class="[^"]*bScalePoints__item[^"]*"[^>]*>\s*(.*?)\s*</div>',
    re.IGNORECASE | re.DOTALL
)

csv_lock = threading.Lock()

def extract_review_and_risk(html_text: str) -> tuple[str, str]:
    m = REVIEW_RE.search(html_text)
    review = html.unescape(m.group(1).strip()) if m else ""

    risk = "Unknown"
    pm = POINTS_RE.search(html_text)
    items = ITEM_RE.findall(html_text)
    if pm and items:
        dp = int(pm.group(1))
        idx = round(dp * (len(items) - 1) / 100)
        risk = html.unescape(items[idx].strip())

    return review, risk

def scan_and_write(domain: str, writer, file_obj):
    slug = domain.replace(".", "-")
    url = f"{GRIDINSOFT_URL}{slug}"

    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404 or "gridinsoft.com/410" in resp.url:
            result = (domain, "", "Unknown")
        else:
            review, risk = extract_review_and_risk(resp.text)
            result = (domain, review, risk)
    except requests.RequestException:
        result = (domain, "", "Unknown")

    # Write safely from multiple threads
    with csv_lock:
        writer.writerow(result)
        file_obj.flush()

def load_domains(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def main():
    domains = load_domains("BenignDomains.txt")

    with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "ReviewLabel", "RiskLevel"])

        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(scan_and_write, domain, writer, f) for domain in domains]
            for _ in as_completed(futures):
                pass  # we don't print; just wait for them to finish

if __name__ == "__main__":
    main()
