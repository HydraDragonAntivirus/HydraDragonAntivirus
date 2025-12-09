import sys
import time
import shutil
import hashlib
import ctypes
import json
import os
from pathlib import Path


def safe_print(text):
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode('utf-8', errors='replace').decode('utf-8', errors='replace'))


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def is_jar_file(file_path):
    try:
        return file_path.lower().endswith('.jar')
    except Exception:
        return False


def compute_md5(file_path, chunk_size=8192):
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None


def load_existing_hashes(folder):
    existing = set()
    if not os.path.isdir(folder):
        return existing
    
    safe_print(f"Loading existing files from '{folder}'...")
    count = 0
    for fp in Path(folder).rglob('*'):
        if not fp.is_file():
            continue
        h = compute_md5(str(fp))
        if h:
            existing.add(h)
            count += 1
    
    safe_print(f"Loaded {count} existing file hashes from '{folder}'")
    return existing


def load_md5_from_cache(cache_file="md5_cache.json"):
    existing = set()
    if not os.path.isfile(cache_file):
        safe_print(f"Cache file '{cache_file}' not found.")
        return existing
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            existing = set(data.get('hashes', []))
        safe_print(f"Loaded {len(existing)} hashes from cache file '{cache_file}'")
    except Exception as e:
        safe_print(f"Error loading cache file: {e}")
    
    return existing


def save_md5_cache(hashes, cache_file="md5_cache.json"):
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'hashes': list(hashes)}, f, indent=2)
        safe_print(f"Saved {len(hashes)} hashes to cache file '{cache_file}'")
    except Exception as e:
        safe_print(f"Error saving cache file: {e}")


def scan_directory(root_dir, max_size_mb=50, existing_hashes=None):
    if existing_hashes is None:
        existing_hashes = set()
    
    max_size = max_size_mb * 1024 * 1024
    found = []
    seen_hashes = set()
    total_scanned = 0
    skipped_duplicates = 0

    safe_print(f"\nScanning '{root_dir}' for JAR files <= {max_size_mb}MB...")
    start = time.time()

    for dirpath, dirs, files in os.walk(root_dir, onerror=lambda e: None):
        for fname in files:
            full = os.path.join(dirpath, fname)
            total_scanned += 1
            
            if total_scanned % 1000 == 0:
                safe_print(f"[Progress] Scanned {total_scanned} files, found {len(found)} new JAR files so far...")
            
            try:
                size = os.path.getsize(full)
            except:
                continue

            if size == 0 or size > max_size:
                continue

            if not is_jar_file(full):
                continue

            md5 = compute_md5(full)
            if not md5:
                continue
            
            if md5 in existing_hashes:
                skipped_duplicates += 1
                continue
            
            if md5 in seen_hashes:
                continue

            seen_hashes.add(md5)
            entry = {
                'path': full,
                'size': size,
                'size_mb': round(size / (1024*1024), 2),
                'md5': md5
            }
            found.append(entry)
            safe_print(f"({len(found)}) [NEW] {full} ({entry['size_mb']} MB) MD5={md5}")

    elapsed = time.time() - start
    safe_print(f"\nScan complete:")
    safe_print(f"  - {len(found)} new unique JAR files found")
    safe_print(f"  - {skipped_duplicates} duplicates skipped (already in data2)")
    safe_print(f"  - {total_scanned} total files scanned ({elapsed:.2f}s)")
    return found


def save_results(found, out_file="jar_scan_results.txt"):
    try:
        with open(out_file, 'w', encoding='utf-8', errors='replace') as f:
            f.write("JAR Files Found (New, not in data2):\n")
            f.write("="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB ({e['size']} bytes)\nMD5: {e['md5']}\n")
                f.write("-"*20 + "\n")
        safe_print(f"Results saved to '{out_file}'")
    except Exception as e:
        safe_print(f"Failed to save results: {e}")


def copy_to_folder(found, dest):
    os.makedirs(dest, exist_ok=True)

    count = 0
    for e in found:
        try:
            src_path = e['path']
            filename = os.path.basename(src_path)
            dest_path = os.path.join(dest, filename)
            
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_path):
                    new_filename = f"{base} ({counter}){ext}"
                    dest_path = os.path.join(dest, new_filename)
                    counter += 1
                safe_print(f"Renaming due to conflict: {filename} -> {os.path.basename(dest_path)}")
            
            shutil.copy2(src_path, dest_path)
            count += 1
            safe_print(f"Copied: {src_path} -> {dest_path}")
        except:
            continue

    safe_print(f"\nCopied {count} new files to '{dest}'")


def mode_1_recalc_and_scan():
    safe_print("\n=== MODE 1: Recalculate MD5 and Scan for JAR Files ===\n")
    
    dest = input("Enter data2 folder path [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    existing_hashes = load_existing_hashes(dest)
    save_md5_cache(existing_hashes)

    root = input("\nDirectory to scan for JAR files: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = input("Max file size in MB [50]: ").strip() or "50"
    try:
        max_mb = int(max_mb)
    except:
        max_mb = 50
    
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new JAR files found.")
        return
    
    save_results(found)
    
    choice = input(f"\nCopy {len(found)} new files to '{dest}'? (y/n): ").lower()
    if choice in ('y', 'yes'):
        copy_to_folder(found, dest)


def mode_2_recalc_only():
    safe_print("\n=== MODE 2: Recalculate MD5 Only ===\n")
    
    dest = input("Enter data2 folder path [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    if not os.path.isdir(dest):
        safe_print(f"Directory '{dest}' does not exist.")
        return
    
    existing_hashes = load_existing_hashes(dest)
    cache_file = input("Enter cache file name [md5_cache.json]: ").strip() or "md5_cache.json"
    save_md5_cache(existing_hashes, cache_file)
    
    safe_print("\nMD5 recalculation complete!")


def mode_3_use_cache():
    safe_print("\n=== MODE 3: Use Existing MD5 Cache and Scan for JAR Files ===\n")
    
    cache_file = input("Enter cache file name [md5_cache.json]: ").strip() or "md5_cache.json"
    existing_hashes = load_md5_from_cache(cache_file)
    
    if not existing_hashes:
        safe_print("No hashes loaded. Run Mode 2 first.")
        return
    
    root = input("\nDirectory to scan for JAR files: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = input("Max file size in MB [50]: ").strip() or "50"
    try:
        max_mb = int(max_mb)
    except:
        max_mb = 50
    
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new JAR files found.")
        return
    
    save_results(found)
    
    dest = input("\nEnter destination folder for new files [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    choice = input(f"\nCopy {len(found)} new files to '{dest}'? (y/n): ").lower()
    if choice in ('y', 'yes'):
        copy_to_folder(found, dest)
        
        update_cache = input("\nUpdate cache with new hashes? (y/n): ").lower()
        if update_cache in ('y', 'yes'):
            new_hashes = {e['md5'] for e in found}
            existing_hashes.update(new_hashes)
            save_md5_cache(existing_hashes, cache_file)
            safe_print("Cache updated.")


def main():
    if not is_admin():
        safe_print("WARNING: Not running as administrator!")
        safe_print("Some directories may be inaccessible.")
        choice = input("Continue? (y/n): ").lower()
        if choice not in ('y', 'yes'):
            sys.exit(1)
        safe_print("")
    
    safe_print("=" * 60)
    safe_print("JAR File Scanner - Multi-Mode Operation")
    safe_print("=" * 60)
    safe_print("\nSelect Mode:")
    safe_print("1) Recalculate MD5 (data2) and scan folder for JAR files")
    safe_print("2) Recalculate MD5 only")
    safe_print("3) Use MD5 cache and scan folder")
    safe_print("")
    
    mode = input("Enter mode (1/2/3): ").strip()
    
    if mode == '1':
        mode_1_recalc_and_scan()
    elif mode == '2':
        mode_2_recalc_only()
    elif mode == '3':
        mode_3_use_cache()
    else:
        safe_print("Invalid mode selected.")
        sys.exit(1)


if __name__ == '__main__':
    main()
