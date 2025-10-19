#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import pathlib

for path in pathlib.Path(".").rglob("*.py"):
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        text = path.read_text(encoding="latin-1")  # fallback for odd encodings

    new_text = re.sub(
        r"threading\.Thread\s*\((?![^)]*daemon\s*=)",
        "threading.Thread(daemon=True, ",
        text
    )

    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        print(f"Updated {path}")