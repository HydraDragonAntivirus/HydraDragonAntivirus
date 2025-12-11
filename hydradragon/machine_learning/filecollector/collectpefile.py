import os
import sys
import time
import shutil
import hashlib
import pefile
import ctypes
import json
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed
from multiprocessing import cpu_count, Manager

# --- CONFIGURATION FOR MAXIMUM AGGRESSION ---
# Launch 2x workers per core to mask I/O latency
FORCE_WORKER_COUNT = int(cpu_count() * 2)  
# Read 8MB at a time to keep CPU busy hashing
HASH_CHUNK_SIZE = 8 * 1024 * 1024  
# Batch size for process submission
BATCH_SIZE = 2000

def safe_print(text):
    """Print text with Unicode error handling."""
    try:
        print(text, flush=True)
    except UnicodeEncodeError:
        print(text.encode('utf-8', errors='replace').decode('utf-8', errors='replace'), flush=True)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# --- OPTIMIZED WORKER FUNCTIONS ---

def compute_md5_aggressive(file_path):
    """
    Highly optimized MD5 hasher.
    Reads large chunks to maximize CPU time vs Disk Seek time.
    """
    hash_md5 = hashlib.md5()
    try:
        # 8MB Buffer size forces CPU to work harder per read
        with open(file_path, 'rb', buffering=HASH_CHUNK_SIZE) as f:
            while True:
                chunk = f.read(HASH_CHUNK_SIZE)
                if not chunk:
                    break
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def is_pe_file_fast(file_path):
    """Check if valid PE file (CPU Intensive parsing)."""
    try:
        # Fast load only reads headers, but it still burns CPU parsing structures
        pe = pefile.PE(file_path, fast_load=True)
        pe.close()
        return True
    except:
        return False

def worker_process_batch(file_batch, max_size, existing_hashes):
    """
    Worker process designed to burn CPU.
    Iterates through a batch of files, checks PE, and Hashes.
    """
    results = []
    
    for full_path in file_batch:
        try:
            # 1. Quick size check (OS stat is fast)
            stat = os.stat(full_path)
            size = stat.st_size
            if size == 0 or size > max_size:
                continue
            
            # 2. PE Check (CPU Bound)
            if not is_pe_file_fast(full_path):
                continue
            
            # 3. MD5 Hash (CPU + I/O Bound)
            # We do this AFTER PE check to avoid wasting I/O on text files
            md5 = compute_md5_aggressive(full_path)
            
            if not md5 or md5 in existing_hashes:
                continue
            
            results.append({
                'path': full_path,
                'size': size,
                'size_mb': round(size / (1024*1024), 2),
                'md5': md5
            })
        except Exception:
            continue
    
    return results

def worker_hash_only(file_batch):
    """Worker for just hashing (Mode 2/Initialization)."""
    hashes = []
    for fp in file_batch:
        h = compute_md5_aggressive(fp)
        if h:
            hashes.append(h)
    return hashes

# --- AGGRESSIVE FILE DISCOVERY ---

def get_files_fast(root_dir):
    """
    Generator that uses os.walk (faster than pathlib) and yields batches.
    """
    batch = []
    for root, dirs, files in os.walk(root_dir):
        for name in files:
            batch.append(os.path.join(root, name))
            if len(batch) >= BATCH_SIZE:
                yield batch
                batch = []
    if batch:
        yield batch

# --- MAIN LOGIC ---

def load_existing_hashes_aggressive(folder):
    existing = set()
    if not os.path.isdir(folder):
        return existing
    
    safe_print(f"Loading existing files from '{folder}' using {FORCE_WORKER_COUNT} processes...")
    start_time = time.time()
    
    total_processed = 0

    with ProcessPoolExecutor(max_workers=FORCE_WORKER_COUNT) as executor:
        futures = []
        # Quickly dispatch all batches
        for batch in get_files_fast(folder):
            futures.append(executor.submit(worker_hash_only, batch))
        
        safe_print(f"Queued {len(futures)} batches. Waiting for workers...")
        
        for future in as_completed(futures):
            batch_hashes = future.result()
            existing.update(batch_hashes)
            total_processed += len(batch_hashes)
            
            # Minimal printing to reduce I/O lock
            if len(futures) > 100 and total_processed % 10000 == 0:
                 print(f"Processed {total_processed} files...", end='\r')

    elapsed = time.time() - start_time
    safe_print(f"\nLoaded {len(existing)} hashes in {elapsed:.2f}s")
    return existing

def scan_directory_aggressive(root_dir, max_size_mb, existing_hashes):
    max_size = max_size_mb * 1024 * 1024
    safe_print(f"\nScanning '{root_dir}' (AGGRESSIVE MODE)")
    safe_print(f"Workers: {FORCE_WORKER_COUNT} | Batch Size: {BATCH_SIZE} | Read Buffer: {HASH_CHUNK_SIZE//1024}KB")
    
    start_time = time.time()
    found = []
    seen_hashes = set()
    total_processed = 0
    
    # We load existing_hashes into a Manager dict? No, passing large sets to processes is slow (pickling).
    # Since existing_hashes is read-only, passing it as an arg is standard, 
    # but for massive sets, the IPC overhead is high.
    # We will pass it normally; OS copy-on-write (Linux) helps, Windows copies it.
    
    with ProcessPoolExecutor(max_workers=FORCE_WORKER_COUNT) as executor:
        futures = {}
        
        # 1. FILL THE QUEUE FAST
        print("Discovering files and dispatching workers...")
        batch_count = 0
        for batch in get_files_fast(root_dir):
            future = executor.submit(worker_process_batch, batch, max_size, existing_hashes)
            futures[future] = len(batch)
            batch_count += 1
            if batch_count % 100 == 0:
                print(f"Queued {batch_count} batches...", end='\r')

        print(f"\nAll {batch_count} batches queued. Workers are crunching...")
        
        # 2. COLLECT RESULTS
        for future in as_completed(futures):
            results = future.result()
            count = futures[future]
            total_processed += count
            
            for entry in results:
                if entry['md5'] not in seen_hashes:
                    seen_hashes.add(entry['md5'])
                    found.append(entry)
                    print(f"[FOUND] {entry['path']} ({entry['size_mb']} MB)")
            
            if total_processed % 5000 == 0:
                 print(f"Progress: {total_processed} files scanned...", end='\r')

    elapsed = time.time() - start_time
    safe_print(f"\nScan complete: {len(found)} new PE files in {elapsed:.2f}s")
    return found

# --- UTILS ---

def save_results(found, out_file="pe_scan_results.txt"):
    try:
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write(f"PE Files Found (New) - {time.ctime()}\n" + "="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB\nMD5: {e['md5']}\n" + "-"*20 + "\n")
        safe_print(f"Results saved to '{out_file}'")
    except Exception as e:
        safe_print(f"Failed save: {e}")

def copy_to_folder(found, dest):
    if not found: return
    os.makedirs(dest, exist_ok=True)
    # I/O bound, so use threads, but aggressive count
    max_workers = 32 
    safe_print(f"\nCopying files with {max_workers} threads...")
    
    def copy_task(entry):
        try:
            src = entry['path']
            fname = os.path.basename(src)
            dst = os.path.join(dest, fname)
            if os.path.exists(dst):
                base, ext = os.path.splitext(fname)
                c = 1
                while os.path.exists(dst):
                    dst = os.path.join(dest, f"{base} ({c}){ext}")
                    c += 1
            shutil.copy2(src, dst)
            return True
        except:
            return False

    count = 0
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = [ex.submit(copy_task, e) for e in found]
        for f in as_completed(futures):
            if f.result(): count += 1
            if count % 50 == 0: print(f"Copied {count}...", end='\r')
    safe_print(f"\nCopied {count} files.")

# --- CACHE UTILS ---
def load_cache(f="md5_cache.json"):
    if os.path.exists(f):
        try:
            with open(f) as fp: return set(json.load(fp)['hashes'])
        except: pass
    return set()

def save_cache(hashes, f="md5_cache.json"):
    try:
        with open(f, 'w') as fp: json.dump({'hashes': list(hashes)}, fp)
    except: pass

# --- MENUS ---

def run():
    if not is_admin():
        print("WARNING: Not Admin. Some files may be skipped.")
    
    print(f"=== ULTRA AGGRESSIVE PE SCANNER ===")
    print(f"Physical Cores: {cpu_count()}")
    print(f"Forced Workers: {FORCE_WORKER_COUNT}")
    print("===================================\n")
    
    print("1. Scan & Copy (Full)")
    print("2. Recalc Only")
    print("3. Use Cache & Scan")
    
    m = input("Mode: ").strip()
    
    if m == '1':
        d2 = input("Data2 (Destination): ").strip() or "./data2"
        root = input("Scan Dir: ").strip()
        mx = int(input("Max MB [10]: ").strip() or "10")
        
        exist = load_existing_hashes_aggressive(d2)
        save_cache(exist)
        found = scan_directory_aggressive(root, mx, exist)
        save_results(found)
        if found: copy_to_folder(found, d2)
        
    elif m == '2':
        d2 = input("Data2: ").strip() or "./data2"
        exist = load_existing_hashes_aggressive(d2)
        save_cache(exist)
        print("Cache updated.")
        
    elif m == '3':
        root = input("Scan Dir: ").strip()
        mx = int(input("Max MB [10]: ").strip() or "10")
        exist = load_cache()
        if not exist:
            print("Cache empty. Run mode 2.")
            return
        
        found = scan_directory_aggressive(root, mx, exist)
        save_results(found)
        if found:
            d2 = input("Copy to: ").strip() or "./data2"
            copy_to_folder(found, d2)

if __name__ == "__main__":
    # Required for Windows Multiprocessing
    run()
