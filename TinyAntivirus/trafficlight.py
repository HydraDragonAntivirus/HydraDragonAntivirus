import time
import requests
import urllib.parse
import urllib3
from requests.exceptions import ConnectionError, Timeout, HTTPError

# === Configuration ===
CLOUD_HOST       = "nimbus.bitdefender.net"
URL_STATUS_PATH  = "/url/status"
CLIENT_ID_HEADER = "X-Nimbus-ClientId"
CLIENT_ID        = "a4c35c82-b0b5-46c3-b641-41ed04075269"

# Known anycast IPs for nimbus.bitdefender.net
NIMBUS_IPS = [
    "34.117.254.173",
    "34.120.243.77",
    "34.98.122.109",
]

# Suppress only the single InsecureRequestWarning from requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def _make_request_with_retries(method, url, **kwargs):
    backoff = 1
    for attempt in range(4):
        try:
            return requests.request(method, url, timeout=10, **kwargs)
        except (ConnectionError, Timeout) as e:
            if attempt < 3:
                print(f"[!] Network error ({e}), retrying in {backoff}s…")
                time.sleep(backoff)
                backoff *= 2
            else:
                raise

def scan_url_direct(url: str) -> dict:
    """
    Try each known Nimbus IP in turn, sending Host: header so we
    reach nimbus.bitdefender.net without needing DNS, and
    disable hostname checking on the cert.
    """
    params  = {"url": url}
    headers = {
        CLIENT_ID_HEADER: CLIENT_ID,
        "Host": CLOUD_HOST,
    }

    for ip in NIMBUS_IPS:
        endpoint = f"https://{ip}{URL_STATUS_PATH}"
        print(f"[i] Trying {ip}…")
        try:
            # verify=False skips hostname check and cert validity
            resp = _make_request_with_retries(
                "GET",
                endpoint,
                params=params,
                headers=headers,
                verify=False
            )
            resp.raise_for_status()
            return resp.json()
        except HTTPError as he:
            print(f"[!] HTTP error from {ip}: {he} - {he.response.text}")
        except Exception as e:
            print(f"[!] Failed at {ip}: {e}")

    # If we get here, none of the IPs worked
    raise ConnectionError(f"All Nimbus IPs failed: {NIMBUS_IPS}")

if __name__ == "__main__":
    test_url = "http://www.example.com"
    print(f"Scanning single URL: {test_url}")
    try:
        result = scan_url_direct(test_url)
        print("Result:", result)
    except Exception as e:
        print(f"[ERR] Unable to scan URL: {e}")
