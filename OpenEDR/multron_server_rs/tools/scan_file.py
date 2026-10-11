"""Scan one file with a running multron_server over its WebSocket (protocol 3).

    pip install websockets
    python scan_file.py C:\\path\\sample.vir
    python scan_file.py sample.vir --url ws://127.0.0.1:5306/ws --token SECRET

Sends the file with rescan=true (the shared verdict cache is skipped) and prints the
verdict, threat and engine detail. Exit code: 0 clean, 1 suspicious/malicious,
2 error / the server closed the connection (e.g. it crashed while scanning).
"""
import argparse
import asyncio
import hashlib
import json
import os
import sys
import time

try:
    import websockets
except ImportError:
    sys.exit("pip install websockets")

CHUNK = 256 * 1024


async def scan(url: str, path: str, token: str, timeout: float) -> int:
    data = open(path, "rb").read()
    sha = hashlib.sha256(data).hexdigest().upper()
    name = os.path.basename(path)
    print(f"file   {name}  {len(data):,} bytes  sha256 {sha.lower()}")
    t0 = time.time()
    async with websockets.connect(url, max_size=None, ping_interval=20, open_timeout=15) as ws:
        await ws.send(json.dumps({"type": "hello", "version": 3, "client": "scan_file.py", "token": token}))
        hello = json.loads(await asyncio.wait_for(ws.recv(), 15))
        if hello.get("type") != "hello_ok":
            print("server:", hello)
            return 2
        print(f"server {hello.get('engine')}  limit {hello.get('maxMB')} MB")
        await ws.send(json.dumps({"type": "scan", "id": 1, "name": name, "size": len(data), "sha256": sha, "rescan": True}))
        while True:
            msg = json.loads(await asyncio.wait_for(ws.recv(), timeout))
            kind = msg.get("type")
            if kind == "send_file":
                print("upload ...")
                for i in range(0, len(data), CHUNK):
                    await ws.send(data[i:i + CHUNK])
                print(f"uploaded in {time.time() - t0:.1f} s, waiting for the engine ...")
            elif kind == "result":
                print(f"result {msg.get('verdict')}  {msg.get('threat') or ''}  ({time.time() - t0:.1f} s)")
                if msg.get("detail"):
                    print("detail", msg["detail"])
                return 1 if msg.get("verdict") in ("malicious", "suspicious") else 0
            elif kind == "error":
                print("error", msg.get("message"))
                return 2
            # anything else (need_upload, progress, ...) is informational


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file")
    ap.add_argument("--url", default="ws://127.0.0.1:5306/ws")
    ap.add_argument("--token", default="")
    ap.add_argument("--timeout", type=float, default=600, help="seconds to wait for the result")
    a = ap.parse_args()
    try:
        code = asyncio.run(scan(a.url, a.file, a.token, a.timeout))
    except (OSError, asyncio.TimeoutError, websockets.ConnectionClosed) as e:
        print(f"connection lost / no answer: {e!r}  (did the server crash? check its console)")
        code = 2
    sys.exit(code)


if __name__ == "__main__":
    main()
