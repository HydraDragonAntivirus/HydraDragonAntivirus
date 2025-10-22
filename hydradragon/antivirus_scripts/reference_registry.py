#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pathlib import Path
from typing import Dict, Optional

# -----------------------
# ReferenceRegistry
# -----------------------
class ReferenceRegistry:
    """Map reference strings -> small integer IDs"""

    VERSION = 1

    def __init__(self):
        self.ref_to_id: Dict[str, int] = {}
        self.id_to_ref: Dict[int, str] = {}
        self.next_id = 0

    def register(self, ref: str) -> Optional[int]:
        key = ref.strip()
        if not key:
            return None
        if key not in self.ref_to_id:
            rid = self.next_id
            self.ref_to_id[key] = rid
            self.id_to_ref[rid] = key
            self.next_id += 1
            return rid
        return self.ref_to_id[key]

    def save_text(self, path: Path):
        with path.open("w", encoding="utf-8") as f:
            for rid in sorted(self.id_to_ref.keys()):
                f.write(f"{rid}\t{self.id_to_ref[rid]}\n")
