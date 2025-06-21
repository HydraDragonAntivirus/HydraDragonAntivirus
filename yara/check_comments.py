#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import re
from optparse import OptionParser

def build_cli_parser():
    parser = OptionParser()
    parser.add_option("-f", "--file", dest="file_path",
                      help="Path to YARA file", metavar="FILE")
    return parser

def is_line_only_marker(line, marker):
    return re.fullmatch(r'\s*' + re.escape(marker) + r'\s*', line) is not None

def find_unclosed_comment_blocks(filepath, threshold=300):
    with open(filepath, encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()

    closes = [i for i, line in enumerate(lines) if is_line_only_marker(line.strip(), '*/')]
    unclosed = []

    for i, line in enumerate(lines):
        if is_line_only_marker(line.strip(), '/*'):
            # 300 satır içinde kapanış var mı kontrol et
            closed = False
            for close_idx in closes:
                if i < close_idx <= i + threshold:
                    closed = True
                    break
            if not closed:
                # Kapanış yok veya 300 satırdan uzun açık kalmış
                unclosed.append((i + 1, line.strip()))

    return unclosed

def main():
    parser = build_cli_parser()
    opts, _ = parser.parse_args()
    if not opts.file_path:
        parser.error("Missing --file argument")
    if not os.path.isfile(opts.file_path):
        parser.error(f"File not found: {opts.file_path}")

    unclosed_blocks = find_unclosed_comment_blocks(opts.file_path, threshold=300)

    if unclosed_blocks:
        print("Unclosed /* comment blocks (300+ lines or never closed):")
        for lineno, text in unclosed_blocks:
            print(f"  /* at line {lineno}: {text}")

if __name__ == "__main__":
    main()
