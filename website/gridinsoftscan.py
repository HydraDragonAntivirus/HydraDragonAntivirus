import requests
import csv
import re
import html

GRIDINSOFT_URL = "https://gridinsoft.com/online-virus-scanner/url/"

# Regex patterns
REVIEW_RE = re.compile(
    r'<h1[^>]*\bclass\s*=\s*"[^"]*\bbCheckId__title\b[^"]*"[^>]*>'
    r'.*?<span[^>]*\bclass\s*=\s*"[^"]*\bsmall\b[^"]*"[^>]*>\s*(.*?)\s*</span>',
    re.IGNORECASE | re.DOTALL
)
POINTS_RE = re.compile(
    r'<div[^>]*\bid\s*=\s*"bScalePoints"[^>]*\bdata-points\s*=\s*"(\d+)"',
    re.IGNORECASE
)
ITEM_RE = re.compile(
    r'<div[^>]*\bclass\s*=\s*"[^"]*\bbScalePoints__item\b[^"]*"[^>]*>\s*(.*?)\s*</div>',
    re.IGNORECASE | re.DOTALL
)

def extract_review_and_risk(html_text: str) -> tuple[str, str]:
    # 1) Website Review label
    m = REVIEW_RE.search(html_text)
    raw_review = m.group(1).strip() if m else ""
    review_label = html.unescape(raw_review)

    # 2) Risk level via data-points + items
    risk_level = "Unknown"
    pm = POINTS_RE.search(html_text)
    items = ITEM_RE.findall(html_text)
    if pm and items:
        dp = int(pm.group(1))
        idx = round(dp * (len(items) - 1) / 100)
        raw_risk = items[idx].strip()
        risk_level = html.unescape(raw_risk)

    return review_label, risk_level

def scan_domain(domain: str) -> tuple[str, str]:
    slug = domain.replace(".", "-")
    url = f"{GRIDINSOFT_URL}{slug}"
    try:
        resp = requests.get(url, timeout=10)
        if resp.status_code == 404 or "gridinsoft.com/410" in resp.url:
            return "", "Unknown"
        return extract_review_and_risk(resp.text)
    except requests.RequestException:
        return "", "Unknown"

def load_domains(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

def write_csv(results: list[tuple[str, str, str]], path: str = "DomainScanResults.csv") -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Domain", "ReviewLabel", "RiskLevel"])
        writer.writerows(results)

def main():
    domains = load_domains("BenignDomains.txt")
    results = []
    for d in domains:
        review, risk = scan_domain(d)
        print(f"{d}: Review='{review}', Risk='{risk}'")
        results.append((d, review, risk))
    write_csv(results)

if __name__ == "__main__":
    main()
