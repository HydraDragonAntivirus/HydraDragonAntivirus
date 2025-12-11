import os
import sys
import time
import shutil
import hashlib
import pefile
import ctypes
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from typing import Set, List, Dict, Optional


# Thread-safe locks
print_lock = Lock()
progress_lock = Lock()


def safe_print(text):
    """
    Thread-safe print with Unicode error handling.
    """
    with print_lock:
        try:
            print(text)
        except UnicodeEncodeError:
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


def process_file_for_hash(file_path: str) -> Optional[str]:
    """
    Process a single file to compute its MD5 hash.
    Returns the MD5 hash or None if failed.
    """
    if not os.path.isfile(file_path):
        return None
    return compute_md5(file_path)


def load_existing_hashes(folder, max_workers=None):
    """
    Load MD5 hashes of all files in the specified folder using parallel processing.
    Returns a set of MD5 hashes.
    """
    existing = set()
    if not os.path.isdir(folder):
        return existing
    
    safe_print(f"Loading existing files from '{folder}' (parallel mode)...")
    
    # Collect all file paths first
    file_paths = []
    for fp in Path(folder).rglob('*'):
        if fp.is_file():
            file_paths.append(str(fp))
    
    if not file_paths:
        safe_print("No files found in folder.")
        return existing
    
    # Determine optimal number of workers
    if max_workers is None:
        max_workers = min(32, (os.cpu_count() or 1) * 4)
    
    safe_print(f"Processing {len(file_paths)} files with {max_workers} workers...")
    
    count = 0
    start_time = time.time()
    
    # Process files in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_path = {executor.submit(process_file_for_hash, fp): fp 
                          for fp in file_paths}
        
        for future in as_completed(future_to_path):
            h = future.result()
            if h:
                existing.add(h)
                count += 1
                
                # Progress update every 100 files
                if count % 100 == 0:
                    elapsed = time.time() - start_time
                    rate = count / elapsed if elapsed > 0 else 0
                    safe_print(f"Progress: {count}/{len(file_paths)} files ({rate:.1f} files/sec)")
    
    elapsed = time.time() - start_time
    safe_print(f"Loaded {count} existing file hashes from '{folder}' in {elapsed:.2f}s")
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


def process_single_file(args) -> Optional[Dict]:
    """
    Process a single file: check if it's a PE file, compute hash, etc.
    Returns a dict with file info if it's a new PE file, None otherwise.
    """
    full_path, max_size, existing_hashes, seen_hashes = args
    
    try:
        size = os.path.getsize(full_path)
    except (OSError, PermissionError):
        return None

    if size == 0 or size > max_size:
        return None

    if not is_pe_file(full_path):
        return None

    md5 = compute_md5(full_path)
    if not md5:
        return None
    
    # Check if already exists in data2 or already seen
    if md5 in existing_hashes or md5 in seen_hashes:
        return {'duplicate': True, 'md5': md5}
    
    entry = {
        'path': full_path,
        'size': size,
        'size_mb': round(size / (1024*1024), 2),
        'md5': md5,
        'duplicate': False
    }
    return entry


def scan_directory(root_dir, max_size_mb=10, existing_hashes=None, max_workers=None):
    """
    Recursively scan the directory for unique PE files using parallel processing.
    Returns a list of dicts with path, size(bytes), size_mb, md5.
    """
    if existing_hashes is None:
        existing_hashes = set()
    
    max_size = max_size_mb * 1024 * 1024
    found = []
    seen_hashes = set()
    seen_lock = Lock()
    total_scanned = 0
    skipped_duplicates = 0

    safe_print(f"\nScanning '{root_dir}' for PE files <= {max_size_mb}MB (parallel mode)...")
    start = time.time()

    # Collect all file paths first
    file_paths = []
    safe_print("Collecting file list...")
    for dirpath, dirs, files in os.walk(root_dir, onerror=lambda e: None):
        for fname in files:
            full = os.path.join(dirpath, fname)
            file_paths.append(full)
    
    safe_print(f"Found {len(file_paths)} files to scan...")
    
    # Determine optimal number of workers
    if max_workers is None:
        max_workers = min(32, (os.cpu_count() or 1) * 4)
    
    safe_print(f"Using {max_workers} worker threads...")
    
    # Process files in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all tasks
        future_to_path = {}
        for fp in file_paths:
            args = (fp, max_size, existing_hashes, seen_hashes)
            future = executor.submit(process_single_file, args)
            future_to_path[future] = fp
        
        # Process results as they complete
        for future in as_completed(future_to_path):
            total_scanned += 1
            
            # Show progress every 500 files
            if total_scanned % 500 == 0:
                elapsed = time.time() - start
                rate = total_scanned / elapsed if elapsed > 0 else 0
                safe_print(f"[Progress] Scanned {total_scanned}/{len(file_paths)} files, "
                          f"found {len(found)} new PE files ({rate:.1f} files/sec)")
            
            result = future.result()
            if result is None:
                continue
            
            if result.get('duplicate'):
                skipped_duplicates += 1
                continue
            
            # Thread-safe addition to results
            with seen_lock:
                md5 = result['md5']
                if md5 not in seen_hashes:
                    seen_hashes.add(md5)
                    found.append(result)
                    safe_print(f"({len(found)}) [NEW] {result['path']} "
                              f"({result['size_mb']} MB) MD5={md5}")

    elapsed = time.time() - start
    rate = total_scanned / elapsed if elapsed > 0 else 0
    safe_print(f"\nScan complete:")
    safe_print(f"  - {len(found)} new unique PE files found")
    safe_print(f"  - {skipped_duplicates} duplicates skipped (already in data2)")
    safe_print(f"  - {total_scanned} total files scanned in {elapsed:.2f}s ({rate:.1f} files/sec)")
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


def copy_single_file(args):
    """
    Copy a single file to destination with conflict handling.
    Returns tuple: (success: bool, message: str)
    """
    entry, dest = args
    try:
        src_path = entry['path']
        filename = os.path.basename(src_path)
        dest_path = os.path.join(dest, filename)
        
        # If file name exists, rename with incrementing number
        if os.path.exists(dest_path):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(dest_path):
                new_filename = f"{base} ({counter}){ext}"
                dest_path = os.path.join(dest, new_filename)
                counter += 1
            msg = f"Renamed: {filename} -> {os.path.basename(dest_path)}"
        else:
            msg = f"Copied: {src_path} -> {dest_path}"
        
        shutil.copy2(src_path, dest_path)
        return (True, msg)
    except (OSError, PermissionError):
        return (False, f"Permission denied: {entry['path']}")
    except Exception as ex:
        return (False, f"Error copying {entry['path']}: {ex}")


def copy_to_folder(found, dest, max_workers=None):
    """
    Copy unique files to destination folder in parallel.
    """
    os.makedirs(dest, exist_ok=True)

    if max_workers is None:
        max_workers = min(16, (os.cpu_count() or 1) * 2)
    
    safe_print(f"\nCopying files with {max_workers} worker threads...")
    
    count = 0
    start_time = time.time()
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_entry = {executor.submit(copy_single_file, (e, dest)): e 
                          for e in found}
        
        for future in as_completed(future_to_entry):
            success, msg = future.result()
            if success:
                count += 1
                safe_print(msg)
            
            # Progress update
            if count % 10 == 0:
                safe_print(f"Progress: {count}/{len(found)} files copied...")
    
    elapsed = time.time() - start_time
    safe_print(f"\nCopied {count}/{len(found)} files to '{dest}' in {elapsed:.2f}s")


def mode_1_recalc_and_scan():
    """
    Mode 1: Recalculate MD5 from data2 folder and scan a specific folder
    """
    safe_print("\n=== MODE 1: Recalculate MD5 and Scan Specific Folder ===\n")
    
    dest = input("Enter data2 folder path [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    existing_hashes = load_existing_hashes(dest)
    
    cache_file = "md5_cache.json"
    save_md5_cache(existing_hashes, cache_file)
    
    root = input("\nDirectory to scan for PE files: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = input("Max file size in MB [10]: ").strip() or "10"
    try:
        max_mb = int(max_mb)
    except ValueError:
        max_mb = 10
    
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
    """
    Mode 3: Use existing MD5 list from cache and scan system
    """
    safe_print("\n=== MODE 3: Use Existing MD5 List and Scan System ===\n")
    
    cache_file = input("Enter cache file name [md5_cache.json]: ").strip() or "md5_cache.json"
    existing_hashes = load_md5_from_cache(cache_file)
    
    if not existing_hashes:
        safe_print("No hashes loaded. Please run Mode 2 first to create a cache file.")
        return
    
    root = input("\nDirectory to scan for PE files: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = input("Max file size in MB [10]: ").strip() or "10"
    try:
        max_mb = int(max_mb)
    except ValueError:
        max_mb = 10
    
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new PE files found (all are duplicates or none match criteria).")
        return
    
    save_results(found)
    
    dest = input("\nEnter destination folder for new files [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    choice = input(f"\nCopy {len(found)} new files to '{dest}'? (y/n): ").lower()
    if choice in ('y', 'yes'):
        copy_to_folder(found, dest)
        
        update_cache = input("\nUpdate cache file with new hashes? (y/n): ").lower()
        if update_cache in ('y', 'yes'):
            new_hashes = {e['md5'] for e in found}
            existing_hashes.update(new_hashes)
            save_md5_cache(existing_hashes, cache_file)
            safe_print("Cache updated with new hashes.")
    else:
        safe_print("Copy skipped.")


def main():
    if not is_admin():
        safe_print("WARNING: Not running as administrator!")
        safe_print("Some system directories may be inaccessible.")
        choice = input("Continue anyway? (y/n): ").lower()
        if choice not in ('y', 'yes'):
            safe_print("Exiting. Please run as administrator for full access.")
            sys.exit(1)
        safe_print("")
    
    safe_print("=" * 60)
    safe_print("PE File Scanner - Multi-Mode Operation (PARALLEL)")
    safe_print("=" * 60)
    safe_print(f"Using up to {min(32, (os.cpu_count() or 1) * 4)} threads for I/O operations")
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
