import os
import sys
import time
import shutil
import hashlib
import pefile
import ctypes
import json
from pathlib import Path


def safe_print(text):
    """
    Print text with Unicode error handling.
    """
    try:
        print(text)
    except UnicodeEncodeError:
        # Replace problematic characters with safe representation
        print(text.encode('utf-8', errors='replace').decode('utf-8', errors='replace'))


def is_admin():
    """
    Check if the script is running with administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def is_pe_file(file_path):
    """
    Check if the file at the specified path is a valid Portable Executable (PE) file.
    """
    try:
        pefile.PE(file_path, fast_load=True)
        return True
    except pefile.PEFormatError:
        return False
    except Exception:
        return False


def compute_md5(file_path, chunk_size=8192):
    """
    Compute and return the MD5 hash of the given file.
    """
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None


def load_existing_hashes(folder):
    """
    Load MD5 hashes of all files in the specified folder by recalculating them.
    Returns a set of MD5 hashes.
    """
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
    """
    Load MD5 hashes from a JSON cache file.
    Returns a set of MD5 hashes.
    """
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
    """
    Save MD5 hashes to a JSON cache file.
    """
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'hashes': list(hashes)}, f, indent=2)
        safe_print(f"Saved {len(hashes)} hashes to cache file '{cache_file}'")
    except Exception as e:
        safe_print(f"Error saving cache file: {e}")


def scan_directory(root_dir, max_size_mb=10, existing_hashes=None):
    """
    Recursively scan the directory for unique PE files under a size threshold,
    ignoring access-denied errors and files that already exist in data2.
    Returns a list of dicts with path, size(bytes), size_mb, md5.
    """
    if existing_hashes is None:
        existing_hashes = set()
    
    max_size = max_size_mb * 1024 * 1024
    found = []
    seen_hashes = set()
    total_scanned = 0
    skipped_duplicates = 0

    safe_print(f"\nScanning '{root_dir}' for PE files <= {max_size_mb}MB (ignoring access errors)...")
    start = time.time()

    for dirpath, dirs, files in os.walk(root_dir, onerror=lambda e: None):
        for fname in files:
            full = os.path.join(dirpath, fname)
            total_scanned += 1
            
            # Show progress every 1000 files
            if total_scanned % 1000 == 0:
                safe_print(f"[Progress] Scanned {total_scanned} files, found {len(found)} new PE files so far...")
            
            try:
                size = os.path.getsize(full)
            except (OSError, PermissionError):
                continue

            if size == 0 or size > max_size:
                continue

            if not is_pe_file(full):
                continue

            md5 = compute_md5(full)
            if not md5:
                continue
            
            # Check if already exists in data2
            if md5 in existing_hashes:
                skipped_duplicates += 1
                continue
            
            # Check if we've already found this in current scan
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
    safe_print(f"  - {len(found)} new unique PE files found")
    safe_print(f"  - {skipped_duplicates} duplicates skipped (already in data2)")
    safe_print(f"  - {total_scanned} total files scanned ({elapsed:.2f}s)")
    return found


def save_results(found, out_file="pe_scan_results.txt"):
    """
    Save scan results to a text file.
    """
    try:
        with open(out_file, 'w', encoding='utf-8', errors='replace') as f:
            f.write("PE Files Found (New, not in data2):\n")
            f.write("="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB ({e['size']} bytes)\nMD5: {e['md5']}\n")
                f.write("-"*20 + "\n")
        safe_print(f"Results saved to '{out_file}'")
    except Exception as e:
        safe_print(f"Failed to save results: {e}")


def copy_to_folder(found, dest):
    """
    Copy unique files to destination folder, renaming if file name already exists.
    """
    os.makedirs(dest, exist_ok=True)

    count = 0
    for e in found:
        try:
            src_path = e['path']
            filename = os.path.basename(src_path)
            dest_path = os.path.join(dest, filename)
            
            # If file name exists, rename with incrementing number in format (1), (2), etc.
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_path):
                    new_filename = f"{base} ({counter}){ext}"
                    dest_path = os.path.join(dest, new_filename)
                    counter += 1
                safe_print(f"Renaming to avoid conflict: {filename} -> {os.path.basename(dest_path)}")
            
            shutil.copy2(src_path, dest_path)
            count += 1
            safe_print(f"Copied: {src_path} -> {dest_path}")
        except (OSError, PermissionError) as ex:
            continue
        except Exception as ex:
            safe_print(f"Error copying {e['path']}: {ex}")

    safe_print(f"\nCopied {count} new files to '{dest}'")


def mode_1_recalc_and_scan():
    """
    Mode 1: Recalculate MD5 from data2 folder and scan a specific folder
    """
    safe_print("\n=== MODE 1: Recalculate MD5 and Scan Specific Folder ===\n")
    
    # Get data2 folder location
    dest = input("Enter data2 folder path [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    # Recalculate MD5 hashes from data2
    existing_hashes = load_existing_hashes(dest)
    
    # Save the recalculated hashes to cache
    cache_file = "md5_cache.json"
    save_md5_cache(existing_hashes, cache_file)
    
    # Get folder to scan
    root = input("\nDirectory to scan for PE files: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = input("Max file size in MB [10]: ").strip() or "10"
    try:
        max_mb = int(max_mb)
    except ValueError:
        max_mb = 10
    
    # Scan the specified folder
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new PE files found (all are duplicates or none match criteria).")
        return
    
    save_results(found)
    
    choice = input(f"\nCopy {len(found)} new files to '{dest}'? (y/n): ").lower()
    if choice in ('y', 'yes'):
        copy_to_folder(found, dest)
    else:
        safe_print("Copy skipped.")


def mode_2_recalc_only():
    """
    Mode 2: Only recalculate MD5 from data2 folder and save to cache
    """
    safe_print("\n=== MODE 2: Recalculate MD5 Only ===\n")
    
    # Get data2 folder location
    dest = input("Enter data2 folder path [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    if not os.path.isdir(dest):
        safe_print(f"Directory '{dest}' does not exist.")
        return
    
    # Recalculate MD5 hashes from data2
    existing_hashes = load_existing_hashes(dest)
    
    # Save to cache
    cache_file = input("Enter cache file name [md5_cache.json]: ").strip() or "md5_cache.json"
    save_md5_cache(existing_hashes, cache_file)
    
    safe_print("\nMD5 recalculation complete!")


def mode_3_use_cache():
    """
    Mode 3: Use existing MD5 list from cache and scan system
    """
    safe_print("\n=== MODE 3: Use Existing MD5 List and Scan System ===\n")
    
    # Load MD5 hashes from cache
    cache_file = input("Enter cache file name [md5_cache.json]: ").strip() or "md5_cache.json"
    existing_hashes = load_md5_from_cache(cache_file)
    
    if not existing_hashes:
        safe_print("No hashes loaded. Please run Mode 2 first to create a cache file.")
        return
    
    # Get folder to scan
    root = input("\nDirectory to scan for PE files: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = input("Max file size in MB [10]: ").strip() or "10"
    try:
        max_mb = int(max_mb)
    except ValueError:
        max_mb = 10
    
    # Scan the specified folder
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new PE files found (all are duplicates or none match criteria).")
        return
    
    save_results(found)
    
    # Get destination folder for copying
    dest = input("\nEnter destination folder for new files [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    choice = input(f"\nCopy {len(found)} new files to '{dest}'? (y/n): ").lower()
    if choice in ('y', 'yes'):
        copy_to_folder(found, dest)
        
        # Ask if user wants to update cache with new files
        update_cache = input("\nUpdate cache file with new hashes? (y/n): ").lower()
        if update_cache in ('y', 'yes'):
            new_hashes = {e['md5'] for e in found}
            existing_hashes.update(new_hashes)
            save_md5_cache(existing_hashes, cache_file)
            safe_print("Cache updated with new hashes.")
    else:
        safe_print("Copy skipped.")


def main():
    # Check for admin privileges
    if not is_admin():
        safe_print("WARNING: Not running as administrator!")
        safe_print("Some system directories may be inaccessible.")
        choice = input("Continue anyway? (y/n): ").lower()
        if choice not in ('y', 'yes'):
            safe_print("Exiting. Please run as administrator for full access.")
            sys.exit(1)
        safe_print("")
    
    safe_print("=" * 60)
    safe_print("PE File Scanner - Multi-Mode Operation")
    safe_print("=" * 60)
    safe_print("\nSelect Mode:")
    safe_print("1) Recalculate MD5 from data2 folder and scan specific folder")
    safe_print("2) Recalculate MD5 from data2 folder only (save to cache)")
    safe_print("3) Use existing MD5 cache and scan system")
    safe_print("")
    
    mode = input("Enter mode (1/2/3): ").strip()
    
    if mode == '1':
        mode_1_recalc_and_scan()
    elif mode == '2':
        mode_2_recalc_only()
    elif mode == '3':
        mode_3_use_cache()
    else:
        safe_print("Invalid mode selection.")
        sys.exit(1)


if __name__ == '__main__':
    main()
