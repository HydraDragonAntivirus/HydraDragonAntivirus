import os
import sys
import time
import shutil
import hashlib
import json
import ctypes
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count, Manager

# Try to import external libs; warn if missing
try:
    import pefile
except ImportError:
    print("Error: 'pefile' is missing. Install it: pip install pefile")
    sys.exit(1)

try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' is missing. Install it: pip install tqdm")
    sys.exit(1)

# --- CONFIGURATION ---
chunk_size = 1024 * 1024  # 1MB Buffer (Sweet spot for speed/stability)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# --- OPTIMIZED WORKER FUNCTIONS ---

def get_md5_fast(path):
    """Compute MD5 with efficient buffering."""
    hash_md5 = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except:
        return None

def fast_pe_check(path):
    """
    1. Checks file size.
    2. Checks first 2 bytes for 'MZ' header (Instant).
    3. Only THEN loads pefile (Slow).
    """
    try:
        # 1. Byte check (Extremely fast filter)
        with open(path, 'rb') as f:
            if f.read(2) != b'MZ':
                return False
        
        # 2. Structure check
        pe = pefile.PE(path, fast_load=True)
        pe.close()
        return True
    except:
        return False

def worker_scan_file(args):
    """
    The worker process. 
    Receives: (filepath, max_size_bytes, existing_hashes_set)
    """
    path, max_bytes, existing_hashes = args
    result = None
    
    try:
        # Fast OS stat
        stat = os.stat(path)
        size = stat.st_size
        
        # Filter Size
        if size == 0 or size > max_bytes:
            return None

        # Filter: Is it a PE file?
        if not fast_pe_check(path):
            return None

        # Filter: Hash Check
        md5 = get_md5_fast(path)
        if not md5:
            return None
            
        if md5 in existing_hashes:
            return None

        # If we get here, it's a new file
        result = {
            'path': path,
            'size_mb': round(size / (1024 * 1024), 2),
            'md5': md5
        }
    except Exception:
        return None
        
    return result

def worker_load_hash(path):
    """Worker just for calculating hash of existing files."""
    return get_md5_fast(path)

# --- FILE ENUMERATION ---

def discover_files(root_dir):
    """
    Fastest way to list all files using os.scandir recursively.
    Returns a list of all file paths.
    """
    file_paths = []
    print(f"Index: Scanning file system structure of '{root_dir}'...")
    
    # os.walk is robust and efficient enough for listing
    for root, _, files in os.walk(root_dir):
        for file in files:
            file_paths.append(os.path.join(root, file))
            
    print(f"Index: Found {len(file_paths)} files total.")
    return file_paths

# --- MAIN LOGIC BLOCKS ---

def load_existing_hashes_tqdm(folder):
    existing = set()
    if not os.path.isdir(folder):
        return existing

    files = discover_files(folder)
    if not files:
        return existing

    print("Hashing existing files...")
    # Using ample workers for hashing as it's CPU intensive
    max_workers = cpu_count()
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        # Map returns an iterator that maintains order, but we use tqdm on it
        results = list(tqdm(executor.map(worker_load_hash, files), total=len(files), unit="file"))
        
    # Filter out Nones
    for h in results:
        if h:
            existing.add(h)
            
    print(f"Loaded {len(existing)} unique hashes.")
    return existing

def scan_with_tqdm(root_dir, max_mb, existing_hashes):
    max_bytes = max_mb * 1024 * 1024
    
    # 1. Get list of files first (Fast)
    all_files = discover_files(root_dir)
    
    if not all_files:
        print("No files found to scan.")
        return []

    found_entries = []
    
    # 2. Prepare arguments for workers
    # We pass existing_hashes. Note: If this set is HUGE (millions), 
    # passing it to every worker is slow. But for <100k files, it's fine.
    # We pack arguments into tuples.
    tasks = [(f, max_bytes, existing_hashes) for f in all_files]

    print(f"Scanning content with {cpu_count()} cores...")
    
    # 3. Execute with Progress Bar
    with ProcessPoolExecutor(max_workers=cpu_count()) as executor:
        # Submit all tasks
        futures = [executor.submit(worker_scan_file, t) for t in tasks]
        
        # Monitor with TQDM
        for future in tqdm(as_completed(futures), total=len(futures), unit="file"):
            res = future.result()
            if res:
                found_entries.append(res)
                # Optional: Live print found files (can mess up progress bar visual)
                # tqdm.write(f"Found: {res['path']}")

    print(f"\nScan Complete. Found {len(found_entries)} new PE files.")
    return found_entries

# --- UTILITIES ---

def save_cache(hashes, filename="md5_cache.json"):
    try:
        with open(filename, 'w') as f:
            json.dump({'hashes': list(hashes)}, f)
        print("Cache saved.")
    except Exception as e:
        print(f"Error saving cache: {e}")

def load_cache(filename="md5_cache.json"):
    if not os.path.exists(filename):
        return set()
    try:
        with open(filename, 'r') as f:
            return set(json.load(f).get('hashes', []))
    except:
        return set()

def save_report(found, filename="scan_results.txt"):
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Scan Results - {time.ctime()}\n============================\n")
            for entry in found:
                f.write(f"{entry['md5']} | {entry['size_mb']}MB | {entry['path']}\n")
        print(f"Report saved to {filename}")
    except Exception as e:
        print(f"Error saving report: {e}")

def copy_files_tqdm(found_entries, dest_folder):
    if not found_entries:
        return

    os.makedirs(dest_folder, exist_ok=True)
    print(f"Copying {len(found_entries)} files to {dest_folder}...")

    # Copying is Disk I/O bound, standard loop or ThreadPool is fine. 
    # ProcessPool is bad for copying.
    
    count = 0
    for entry in tqdm(found_entries, unit="copy"):
        try:
            src = entry['path']
            filename = os.path.basename(src)
            dest_path = os.path.join(dest_folder, filename)
            
            # Handle duplicates
            if os.path.exists(dest_path):
                name, ext = os.path.splitext(filename)
                c = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(dest_folder, f"{name}_{c}{ext}")
                    c += 1
            
            shutil.copy2(src, dest_path)
            count += 1
        except Exception as e:
            tqdm.write(f"Error copying {src}: {e}")

# --- MENUS ---

def main():
    if not is_admin():
        print("WARNING: Not running as Admin. System files will be skipped.")
        time.sleep(2)

    while True:
        print("\n=== STABLE PE SCANNER (TQDM) ===")
        print("1. Recalculate Hashes & Scan & Copy")
        print("2. Recalculate Hashes Only (Update Cache)")
        print("3. Use Cache & Scan")
        print("4. Exit")
        
        mode = input("\nSelect Mode: ").strip()

        if mode == '1':
            data2 = input("Enter Data2 folder path: ").strip()
            scan_dir = input("Enter Directory to Scan: ").strip()
            
            existing = load_existing_hashes_tqdm(data2)
            save_cache(existing)
            
            found = scan_with_tqdm(scan_dir, 10, existing)
            save_report(found)
            
            if found:
                if input("Copy files? (y/n): ").lower() == 'y':
                    copy_files_tqdm(found, data2)

        elif mode == '2':
            data2 = input("Enter Data2 folder path: ").strip()
            existing = load_existing_hashes_tqdm(data2)
            save_cache(existing)

        elif mode == '3':
            scan_dir = input("Enter Directory to Scan: ").strip()
            existing = load_cache()
            
            if not existing:
                print("Cache empty. Run Mode 2 first.")
                continue
                
            found = scan_with_tqdm(scan_dir, 10, existing)
            save_report(found)
            
            if found:
                data2 = input("Copy to where? (Enter path): ").strip()
                if input("Copy files? (y/n): ").lower() == 'y':
                    copy_files_tqdm(found, data2)
                    
        elif mode == '4':
            sys.exit()

if __name__ == '__main__':
    main()
