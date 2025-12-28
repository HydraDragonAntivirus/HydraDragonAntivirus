#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os

MAX_BYTES = 7 * 1024  # 7 KB

def truncate_description_line(line, max_bytes=MAX_BYTES):
    line_stripped = line.lstrip()
    if line_stripped.startswith("description"):
        start_quote = line.find('"')
        end_quote = line.rfind('"')
        if start_quote != -1 and end_quote != -1 and end_quote > start_quote:
            desc = line[start_quote+1:end_quote]
            encoded = desc.encode("utf-8")
            if len(encoded) > max_bytes:
                truncated_bytes = encoded[:max_bytes]
                truncated_str = truncated_bytes.decode("utf-8", errors="ignore")
                if ' ' in truncated_str:
                    truncated_str = truncated_str.rsplit(' ', 1)[0] + "..."
                else:
                    truncated_str += "..."
                line = line[:start_quote+1] + truncated_str + line[end_quote:]
    return line

def process_yara_file(filepath):
    temp_file = filepath + ".tmp"
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f_in, \
         open(temp_file, "w", encoding="utf-8", errors="ignore") as f_out:
        for line in f_in:
            f_out.write(truncate_description_line(line))
    os.replace(temp_file, filepath)
    print(f"Processed: {filepath}")

def process_directory(directory):
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".yar") or file.endswith(".yara"):
                filepath = os.path.join(root, file)
                process_yara_file(filepath)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python truncate_yara_desc.py <yara_directory>")
        sys.exit(1)

    yara_dir = sys.argv[1]
    if not os.path.isdir(yara_dir):
        print(f"Error: {yara_dir} is not a valid directory")
        sys.exit(1)

    process_directory(yara_dir)
    print("All YARA files processed.")
