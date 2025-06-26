import os
import re
import tempfile
import shutil

def safe_write_file(original_path, content):
    dir_name = os.path.dirname(original_path) or "."
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=dir_name) as tmp:
        tmp.write(content)
        temp_path = tmp.name
    shutil.move(temp_path, original_path)

def parse_original_names(results_path):
    """
    Parse original rule names from results.txt.
    """
    original_names = set()
    with open(results_path, "r", encoding="utf-8") as f:
        for line in f:
            match = re.search(r'duplicated identifier\s+"([^"]+)"', line)
            if match:
                original_names.add(match.group(1))
    return original_names

def restore_renamed_rules(yar_path, original_names):
    with open(yar_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    changed = False
    # Find rule lines with _ren or _ren<number> suffixes
    pattern = re.compile(r'^\s*rule\s+([a-zA-Z0-9_]+_ren\d*)\b')

    for i, line in enumerate(lines):
        match = pattern.match(line)
        if match:
            renamed_name = match.group(1)
            # Strip off _ren or _ren<number> suffix to get original name
            orig_name = re.sub(r'_ren\d*$', '', renamed_name)
            if orig_name in original_names:
                print(f"[+] Restoring '{renamed_name}' → '{orig_name}' at line {i+1}")
                lines[i] = line.replace(renamed_name, orig_name)
                changed = True
            else:
                print(f"[!] '{renamed_name}' at line {i+1} has no matching original in results.txt, skipping.")

    if changed:
        safe_write_file(yar_path, "".join(lines))
        print("[*] Updated yaraold.yar file, restored original rule names.")
    else:
        print("[*] No '_ren' suffixed rules found to restore.")

def main():
    results_path = "results.txt"
    yara_path = "yaraold.yar"

    if not os.path.exists(results_path):
        print(f"[!] {results_path} not found.")
        return

    if not os.path.exists(yara_path):
        print(f"[!] {yara_path} not found.")
        return

    original_names = parse_original_names(results_path)

    if not original_names:
        print("[*] No duplicate identifiers found in results.txt.")
        return

    restore_renamed_rules(yara_path, original_names)

if __name__ == "__main__":
    main()
