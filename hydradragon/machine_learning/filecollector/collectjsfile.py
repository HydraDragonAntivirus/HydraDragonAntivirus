import os
import sys
import time
import shutil
import hashlib
import ctypes
import json
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count


def safe_print(text):
    """Print text with Unicode error handling."""
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode('utf-8', errors='replace').decode('utf-8', errors='replace'), flush=True)


def is_admin():
    """Check if running as administrator."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def is_js_file(file_path):
    """Check if file is JavaScript."""
    try:
        return file_path.lower().endswith('.js')
    except:
        return False


def compute_md5(file_path, chunk_size=65536):
    """Compute MD5 with larger chunks."""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None


def process_batch_for_hash(file_paths):
    """Process batch of files for hash computation."""
    results = []
    for fp in file_paths:
        h = compute_md5(fp)
        if h:
            results.append(h)
    return results


def load_existing_hashes(folder, max_workers=None):
    """Load hashes using multiprocessing."""
    existing = set()
    if not os.path.isdir(folder):
        return existing
    
    safe_print(f"Loading files from '{folder}' (multiprocessing)...")
    
    file_paths = [str(fp) for fp in Path(folder).rglob('*') if fp.is_file()]
    if not file_paths:
        safe_print("No files found.")
        return existing
    
    if max_workers is None:
        max_workers = cpu_count()
    
    safe_print(f"Processing {len(file_paths)} files with {max_workers} processes...")
    
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
                safe_print(f"Progress: {processed}/{len(file_paths)} ({rate:.1f} files/sec)")
    
    elapsed = time.time() - start_time
    safe_print(f"Loaded {len(existing)} hashes in {elapsed:.2f}s ({len(existing)/elapsed:.1f} files/sec)")
    return existing


def load_md5_from_cache(cache_file="md5_cache.json"):
    """Load hashes from cache."""
    existing = set()
    if not os.path.isfile(cache_file):
        safe_print(f"Cache '{cache_file}' not found.")
        return existing
    
    try:
        with open(cache_file, 'r', encoding='utf-8') as f:
            data = json.load(f)
            existing = set(data.get('hashes', []))
        safe_print(f"Loaded {len(existing)} hashes")
    except Exception as e:
        safe_print(f"Error: {e}")
    return existing


def save_md5_cache(hashes, cache_file="md5_cache.json"):
    """Save hashes to cache."""
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump({'hashes': list(hashes)}, f, indent=2)
        safe_print(f"Saved {len(hashes)} hashes")
    except Exception as e:
        safe_print(f"Error: {e}")


def process_file_batch(args):
    """Process batch of files."""
    file_batch, max_size, existing_hashes = args
    results = []
    
    for full_path in file_batch:
        try:
            size = os.path.getsize(full_path)
            if size == 0 or size > max_size:
                continue
            
            if not is_js_file(full_path):
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
    """Scan using multiprocessing."""
    if existing_hashes is None:
        existing_hashes = set()
    
    max_size = max_size_mb * 1024 * 1024
    safe_print(f"\nScanning '{root_dir}' for JS files <= {max_size_mb}MB (multiprocessing)...")
    start = time.time()

    safe_print("Collecting files...")
    file_paths = [str(p) for p in Path(root_dir).rglob('*') if p.is_file()]
    
    safe_print(f"Found {len(file_paths)} files...")
    
    if max_workers is None:
        max_workers = cpu_count()
    
    safe_print(f"Using {max_workers} processes...")
    
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
                safe_print(f"[Progress] {processed}/{len(file_paths)} ({rate:.1f} files/sec)")

    elapsed = time.time() - start
    rate = len(file_paths) / elapsed if elapsed > 0 else 0
    safe_print(f"\nComplete: {len(found)} new JS files in {elapsed:.2f}s ({rate:.1f} files/sec)")
    return found


def save_results(found, out_file="js_scan_results.txt"):
    """Save results."""
    try:
        with open(out_file, 'w', encoding='utf-8', errors='replace') as f:
            f.write("JS Files Found:\n" + "="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB\nMD5: {e['md5']}\n" + "-"*20 + "\n")
        safe_print(f"Saved to '{out_file}'")
    except Exception as e:
        safe_print(f"Error: {e}")


def copy_to_folder(found, dest):
    """Copy files using threads."""
    os.makedirs(dest, exist_ok=True)
    max_workers = min(16, cpu_count() * 2)
    safe_print(f"\nCopying with {max_workers} threads...")
    
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
            return (True, filename)
        except:
            return (False, filename)
    
    count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(copy_file, e) for e in found]
        for future in as_completed(futures):
            success, _ = future.result()
            if success:
                count += 1
                if count % 10 == 0:
                    safe_print(f"Copied {count}/{len(found)}...")
    
    safe_print(f"\nCopied {count} files")


def mode_1_recalc_and_scan():
    safe_print("\n=== MODE 1 ===\n")
    dest = input("data2 folder [./data2]: ").strip() or "./data2"
    dest = os.path.abspath(dest)
    
    existing_hashes = load_existing_hashes(dest)
    save_md5_cache(existing_hashes)
    
    root = input("\nScan directory: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid.")
        return
    
    max_mb = int(input("Max MB [10]: ").strip() or "10")
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new files.")
        return
    
    save_results(found)
    if input(f"\nCopy {len(found)} files? (y/n): ").lower() in ('y', 'yes'):
        copy_to_folder(found, dest)


def mode_2_recalc_only():
    safe_print("\n=== MODE 2 ===\n")
    dest = input("data2 folder [./data2]: ").strip() or "./data2"
    if not os.path.isdir(dest):
        safe_print("Invalid.")
        return
    
    existing_hashes = load_existing_hashes(dest)
    cache = input("Cache file [md5_cache.json]: ").strip() or "md5_cache.json"
    save_md5_cache(existing_hashes, cache)


def mode_3_use_cache():
    safe_print("\n=== MODE 3 ===\n")
    cache = input("Cache [md5_cache.json]: ").strip() or "md5_cache.json"
    existing_hashes = load_md5_from_cache(cache)
    
    if not existing_hashes:
        safe_print("No hashes. Run Mode 2.")
        return
    
    root = input("\nScan: ").strip()
    if not os.path.isdir(root):
        safe_print("Invalid.")
        return
    
    max_mb = int(input("Max MB [10]: ").strip() or "10")
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        safe_print("\nNo new files.")
        return
    
    save_results(found)
    dest = input("\nDest [./data2]: ").strip() or "./data2"
    
    if input(f"Copy {len(found)}? (y/n): ").lower() in ('y', 'yes'):
        copy_to_folder(found, dest)
        if input("\nUpdate cache? (y/n): ").lower() in ('y', 'yes'):
            existing_hashes.update(e['md5'] for e in found)
            save_md5_cache(existing_hashes, cache)


def main():
    if not is_admin():
        safe_print("WARNING: Not admin!")
        if input("Continue? (y/n): ").lower() not in ('y', 'yes'):
            sys.exit(1)
    
    safe_print("=" * 60)
    safe_print("JS Scanner - Multiprocessing")
    safe_print("=" * 60)
    safe_print(f"CPUs: {cpu_count()}\n")
    safe_print("1) Recalc + scan")
    safe_print("2) Recalc only")
    safe_print("3) Cache + scan\n")
    
    mode = input("Mode: ").strip()
    
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
