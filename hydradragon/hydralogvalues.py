#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging

logging.getLogger('comtypes').setLevel(logging.WARNING)

script_dir = os.getcwd()
log_directory = os.path.join(script_dir, "log")
os.makedirs(log_directory, exist_ok=True)
application_log_file = os.path.join(log_directory, "antivirus.log")

# Create a named logger
logger = logging.getLogger("HydraDragonAntivirus")
logger.setLevel(logging.DEBUG)

# Ensure UTF-8 encoding for the log file
file_handler = logging.FileHandler(application_log_file, encoding="utf-8")
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
file_handler.setFormatter(formatter)

if not logger.handlers:
    logger.addHandler(file_handler)
