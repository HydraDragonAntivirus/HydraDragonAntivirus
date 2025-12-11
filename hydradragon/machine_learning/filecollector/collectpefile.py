import os
import sys
import time
import shutil
import hashlib
import pefile
import ctypes
import json
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from multiprocessing import Manager, cpu_count
from typing import Set, List, Dict, Optional


def safe_print(text):
    """Print text with Unicode error handling."""
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode('utf-8', errors='replace').decode('utf-8', errors='replace'), flush=True)


def is_admin():
    """Check if the script is running with administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def is_pe_file(file_path):
    """Check if the file is a valid PE file."""
    try:
        pefile.PE(file_path, fast_load=True)
        return True
    except:
        return False


def compute_md5(file_path, chunk_size=65536):
    """Compute MD5 hash with larger chunk size for better performance."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None


def process_file_for_hash(file_path):
    """Process single file for hash - worker function for ProcessPool."""
    if not os.path.isfile(file_path):
        return None
    return compute_md5(file_path)


def process_batch_for_hash(file_paths):
    """Process batch of files for hash computation."""
    results = []
    for fp in file_paths:
        h = compute_md5(fp)
        if h:
            results.append(h)
    return results


def load_existing_hashes(folder, max_workers=None):
    """Load MD5 hashes using ProcessPoolExecutor for true parallelism."""
    existing = set()
    if not os.path.isdir(folder):
        return existing
    
    safe_print(f"Loading existing files from '{folder}' (multiprocessing mode)...")
    
    # Collect all file paths
    file_paths = [str(fp) for fp in Path(folder).rglob('*') if fp.is_file()]
    
    if not file_paths:
        safe_print("No files found in folder.")
        return existing
    
    if max_workers is None:
        max_workers = cpu_count()
    
    safe_print(f"Processing {len(file_paths)} files with {max_workers} processes...")
    
    # Split files into batches for better performance
    batch_size = max(1, len(file_paths) // (max_workers * 4))
    batches = [file_paths[i:i + batch_size] for i in range(0, len(file_paths), batch_size)]
    
    start_time = time.time()
    processed = 0
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_batch_for_hash, batch): batch for batch in batches}
        
        for future in as_completed(futures):
            hashes = future.result()
            existing.update(hashes)
            processed += len(futures[future])
            
            if processed % 500 == 0 or processed == len(file_paths):
                elapsed = time.time() - start_time
                rate = processed / elapsed if elapsed > 0 else 0
                safe_print(f"Progress: {processed}/{len(file_paths)} files ({rate:.1f} files/sec)")
    
    elapsed = time.time() - start_time
    safe_print(f"Loaded {len(existing)} hashes in {elapsed:.2f}s ({len(existing)/elapsed:.1f} files/sec)")
    return existing


def load_md5_from_cache(cache_file="md5_cache.json"):
    """Load MD5 hashes from cache file."""
    existing = set()
    if not os.path.isfile(cache_file):
        safe_print(f"Cache file '{cache_file}' not found.")
        return existing
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            existing = set(data.get('hashes', []))
        safe_print(f"Loaded {len(existing)} hashes from cache")
    except Exception as e:
        safe_print(f"Error loading cache: {e}")
    
    return existing


def save_md5_cache(hashes, cache_file="md5_cache.json"):
    """Save MD5 hashes to cache file."""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'hashes': list(hashes)}, f, indent=2)
        safe_print(f"Saved {len(hashes)} hashes to cache")
    except Exception as e:
        safe_print(f"Error saving cache: {e}")


def process_file_batch(args):
    """Process a batch of files - worker for ProcessPool."""
    file_batch, max_size, existing_hashes = args
    results = []
    
    for full_path in file_batch:
        try:
            size = os.path.getsize(full_path)
            if size == 0 or size > max_size:
                continue
            
            if not is_pe_file(full_path):
                continue
            
            md5 = compute_md5(full_path)
            if not md5 or md5 in existing_hashes:
                continue
            
            results.append({
                'path': full_path,
                'size': size,
                'size_mb': round(size / (1024*1024), 2),
                'md5': md5
            })
        except:
            continue
    
    return results


def scan_directory(root_dir, max_size_mb=10, existing_hashes=None, max_workers=None):
    """Scan directory using ProcessPoolExecutor for CPU-intensive PE validation."""
    if existing_hashes is None:
        existing_hashes = set()
    
    max_size = max_size_mb * 1024 * 1024
    
    safe_print(f"\nScanning '{root_dir}' for PE files <= {max_size_mb}MB (multiprocessing)...")
    start = time.time()

    # Collect all file paths
    safe_print("Collecting file list...")
    file_paths = []
    for dirpath, dirs, files in os.walk(root_dir, onerror=lambda e: None):
        for fname in files:
            file_paths.append(os.path.join(dirpath, fname))
    
    safe_print(f"Found {len(file_paths)} files to scan...")
    
    if max_workers is None:
        max_workers = cpu_count()
    
    safe_print(f"Using {max_workers} processes...")
    
    # Split into batches
    batch_size = max(1, len(file_paths) // (max_workers * 4))
    batches = [file_paths[i:i + batch_size] for i in range(0, len(file_paths), batch_size)]
    
    found = []
    seen_hashes = set()
    processed = 0
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_file_batch, (batch, max_size, existing_hashes)): batch 
                   for batch in batches}
        
        for future in as_completed(futures):
            batch_results = future.result()
            
            for entry in batch_results:
                md5 = entry['md5']
                if md5 not in seen_hashes:
                    seen_hashes.add(md5)
                    found.append(entry)
                    safe_print(f"({len(found)}) [NEW] {entry['path']} ({entry['size_mb']} MB)")
            
            processed += len(futures[future])
            if processed % 1000 == 0:
                elapsed = time.time() - start
                rate = processed / elapsed if elapsed > 0 else 0
                safe_print(f"[Progress] {processed}/{len(file_paths)} files ({rate:.1f} files/sec)")

    elapsed = time.time() - start
    rate = len(file_paths) / elapsed if elapsed > 0 else 0
    safe_print(f"\nScan complete: {len(found)} new PE files found in {elapsed:.2f}s ({rate:.1f} files/sec)")
    return found


def save_results(found, out_file="pe_scan_results.txt"):
    """Save scan results to file."""
    try:
        with open(out_file, 'w', encoding='utf-8', errors='replace') as f:
            f.write("PE Files Found (New):\n" + "="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB\nMD5: {e['md5']}\n" + "-"*20 + "\n")
        safe_print(f"Results saved to '{out_file}'")
    except Exception as e:
        safe_print(f"Failed to save results: {e}")


def copy_to_folder(found, dest):
    """Copy files using ThreadPoolExecutor (I/O bound)."""
    os.makedirs(dest, exist_ok=True)
    
    max_workers = min(16, cpu_count() * 2)
    safe_print(f"\nCopying files with {max_workers} threads...")
    
    def copy_file(entry):
        try:
            src = entry['path']
            filename = os.path.basename(src)
            dest_path = os.path.join(dest, filename)
            
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(dest, f"{base} ({counter}){ext}")
                    counter += 1
            
            shutil.copy2(src, dest_path)
            return (True, f"Copied: {filename}")
        except Exception as ex:
            return (False, f"Error: {filename}")
    
    count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(copy_file, e) for e in found]
        for future in as_completed(futures):
            success, msg = future.result()
            if success:
                count += 1
                if count % 10 == 0:
                    safe_print(f"Copied {count}/{len(found)} files...")
    
    safe_print(f"\nCopied {count} files to '{dest}'")


def mode_1_recalc_and_scan():
    safe_print("\n=== MODE 1: Recalculate MD5 and Scan ===\n")
    dest = input("Enter data2 folder [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    existing_hashes = load_existing_hashes(dest)
    save_md5_cache(existing_hashes)
    
    root = input("\nDirectory to scan: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = int(input("Max file size in MB [10]: ").strip() or "10")
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new PE files found.")
        return
    
    save_results(found)
    if input(f"\nCopy {len(found)} files to '{dest}'? (y/n): ").lower() in ('y', 'yes'):
        copy_to_folder(found, dest)


def mode_2_recalc_only():
    safe_print("\n=== MODE 2: Recalculate MD5 Only ===\n")
    dest = input("Enter data2 folder [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    if not os.path.isdir(dest):
        safe_print("Directory does not exist.")
        return
    
    existing_hashes = load_existing_hashes(dest)
    cache_file = input("Cache file name [md5_cache.json]: ").strip() or "md5_cache.json"
    save_md5_cache(existing_hashes, cache_file)
    safe_print("\nComplete!")


def mode_3_use_cache():
    safe_print("\n=== MODE 3: Use MD5 Cache and Scan ===\n")
    cache_file = input("Cache file [md5_cache.json]: ").strip() or "md5_cache.json"
    existing_hashes = load_md5_from_cache(cache_file)
    
    if not existing_hashes:
        safe_print("No hashes loaded. Run Mode 2 first.")
        return
    
    root = input("\nDirectory to scan: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid directory.")
        return
    
    max_mb = int(input("Max size in MB [10]: ").strip() or "10")
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new PE files found.")
        return
    
    save_results(found)
    dest = input("\nDestination folder [./data2]: ").strip() or "./data2"
    
    if input(f"Copy {len(found)} files to '{dest}'? (y/n): ").lower() in ('y', 'yes'):
        copy_to_folder(found, dest)
        if input("\nUpdate cache? (y/n): ").lower() in ('y', 'yes'):
            existing_hashes.update(e['md5'] for e in found)
            save_md5_cache(existing_hashes, cache_file)


def main():
    if not is_admin():
        safe_print("WARNING: Not running as administrator!")
        if input("Continue? (y/n): ").lower() not in ('y', 'yes'):
            sys.exit(1)
    
    safe_print("=" * 60)
    safe_print("PE Scanner - Multiprocessing Mode")
    safe_print("=" * 60)
    safe_print(f"Using {cpu_count()} CPU cores\n")
    safe_print("1) Recalculate MD5 and scan")
    safe_print("2) Recalculate MD5 only")
    safe_print("3) Use cache and scan\n")
    
    mode = input("Mode (1/2/3): ").strip()
    
    if mode == '1':
        mode_1_recalc_and_scan()
    elif mode == '2':
        mode_2_recalc_only()
    elif mode == '3':
        mode_3_use_cache()
    else:
        safe_print("Invalid mode.")


if __name__ == '__main__':
    main()
