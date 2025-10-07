import os
import re
import tempfile
import shutil
import threading

DUPLICATE_RE = re.compile(r'duplicated identifier\s+"([^"]+)"')
LOCK = threading.Lock()

def parse_duplicates(korna_path):
    with open(korna_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    
    rule_names = []
    for line in lines:
        match = DUPLICATE_RE.search(line)
        if match:
            rule_names.append(match.group(1))
    
    return rule_names

def safe_write_file(original_path, content):
    dir_name = os.path.dirname(original_path)
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=dir_name) as tmp:
        tmp.write(content)
        temp_path = tmp.name
    shutil.move(temp_path, original_path)

def generate_unique_name(base_name, used_set):
    if base_name + "_ren" not in used_set:
        return base_name + "_ren"
    
    for i in range(1, 1000):
        candidate = f"{base_name}_ren{i}"
        if candidate not in used_set:
            return candidate
    
    raise ValueError(f"Too many duplicates of {base_name}")

def rename_second_rule(file_path, original_name, used_names):
    with LOCK:
        with open(file_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        
        # Regex pattern that captures everything around the rule name to preserve { and } characters
        rule_pattern = re.compile(rf'(\s*rule\s+){re.escape(original_name)}(\b|(?=[:\s{{}}]))')
        match_count = 0
        new_name = None
        
        for i, line in enumerate(lines):
            if rule_pattern.search(line):
                match_count += 1
                if match_count == 2:
                    new_name = generate_unique_name(original_name, used_names)
                    # Replace only the rule name, preserve all surrounding characters including { and }
                    lines[i] = rule_pattern.sub(rf'\g<1>{new_name}\g<2>', line)
                    print(f"[+] Renamed second rule '{original_name}' → '{new_name}' at line {i+1}")
                    break
        
        if new_name:
            safe_write_file(file_path, "".join(lines))
            used_names.add(new_name)
        else:
            print(f"[!] Only one or no occurrence of rule '{original_name}' found — skipping.")

def main():
    korna_path = "results.txt"
    yar_path = "yaraold.yar"
    
    if not os.path.exists(korna_path):
        print(f"[!] results.txt not found")
        return
    
    if not os.path.exists(yar_path):
        print(f"[!] yaraold.yar not found")
        return
    
    duplicate_names = parse_duplicates(korna_path)
    used_names = set(duplicate_names)
    
    threads = []
    for name in duplicate_names:
        t = threading.Thread(daemon=True, target=rename_second_rule, args=(yar_path, name, used_names))
        t.start()
        threads.append(t)
    
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()