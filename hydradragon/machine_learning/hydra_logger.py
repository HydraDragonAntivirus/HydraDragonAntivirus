#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from logly import logger
from .path_and_variables import script_dir

log_directory = os.path.join(script_dir, "log")
os.makedirs(log_directory, exist_ok=True)
application_log_file = os.path.join(log_directory, "antivirus.log")

# -------------------------------
# Logger configuration (Logly v0.1.6+ safe)
# -------------------------------

try:
    # Logly now auto-adds a console sink, so no need to check or re-add manually.
    # Just ensure a file sink exists.
    logger.add(
        application_log_file,
        rotation="daily",
        retention=7,
        date_enabled=True,
        async_write=True,
    )

    # Configure logging style
    logger.configure(
        level="DEBUG",
        color=True,
        show_time=True,
        json=False,
    )

    logger.info("Logger initialized (console + file sinks)")

except Exception as e:
    # Fallback: simple console output if Logly misbehaves
    print(f"[LoggerInitError] {e}", file=sys.stderr)
