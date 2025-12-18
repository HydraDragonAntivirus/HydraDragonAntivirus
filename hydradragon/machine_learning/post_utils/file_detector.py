import os
import shutil
import hashlib
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import cpu_count
import time
from tqdm import tqdm

def get_file_hash(filepath):
    """Calculate MD5 hash of file for duplicate detection."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def hash_file(filepath):
    """Hash a single file and return result."""
    try:
        file_hash = get_file_hash(filepath)
        return {
            'filepath': filepath,
            'hash': file_hash,
            'size': os.path.getsize(filepath)
        }
    except Exception as e:
        return {
            'filepath': filepath,
            'hash': None,
            'error': str(e)
        }

def get_unique_filename(dest_dir, filename):
    """Generate unique filename if file exists."""
    base_path = dest_dir / filename
    if not base_path.exists():
        return filename
    
    name = base_path.stem
    ext = base_path.suffix
    counter = 1
    
    while (dest_dir / f"{name} ({counter}){ext}").exists():
        counter += 1
    
    return f"{name} ({counter}){ext}"

def scan_directory_fast(directory):
    """Fast directory scan."""
    files = []
    try:
        for root, dirs, filenames in os.walk(directory):
            for filename in filenames:
                files.append(os.path.join(root, filename))
    except Exception as e:
        print(f"Error scanning {directory}: {e}")
    return files

def batch_hash(file_batch):
    """Hash a batch of files."""
    results = []
    for filepath in file_batch:
        results.append(hash_file(filepath))
    return results

def check_malicious_files():
    """Check data2 files against malicious dataset and move matches."""
    start_time = time.time()
    
    # Define directories
    data2 = Path(r"F:\data2")
    malicious_dataset = Path(r"F:\datamaliciousorder")
    duplicate_files = Path(r"F:\duplicate_files")
    
    # Create duplicate_files directory if it doesn't exist
    duplicate_files.mkdir(parents=True, exist_ok=True)
    
    # Check if directories exist
    if not data2.exists():
        print(f"❌ F:\\data2 does not exist!")
        return
    
    if not malicious_dataset.exists():
        print(f"❌ F:\\datamaliciousorder does not exist!")
        return
    
    num_workers = cpu_count()
    print(f"Using {num_workers} worker processes\n")
    
    # Phase 1: Hash all files in malicious dataset
    print("="*60)
    print("Phase 1: Building malicious file database...")
    print("="*60)
    
    print("Scanning malicious dataset directory...")
    malicious_files = scan_directory_fast(malicious_dataset)
    print(f"Found {len(malicious_files):,} files in malicious dataset\n")
    
    if len(malicious_files) == 0:
        print("No files found in malicious dataset. Exiting.")
        return
    
    print("Hashing malicious files...")
    malicious_hashes = set()
    
    batch_size = max(1, len(malicious_files) // (num_workers * 4))
    batches = [malicious_files[i:i + batch_size] for i in range(0, len(malicious_files), batch_size)]
    
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(batch_hash, batch) for batch in batches]
        
        with tqdm(total=len(malicious_files), desc="Hashing malicious dataset", 
                 unit="files", smoothing=0.1) as pbar:
            for future in as_completed(futures):
                results = future.result()
                for result in results:
                    if result['hash']:
                        malicious_hashes.add(result['hash'])
                pbar.update(len(results))
    
    print(f"✓ Built database with {len(malicious_hashes):,} unique malicious file hashes\n")
    
    # Phase 2: Hash all files in data2
    print("="*60)
    print("Phase 2: Scanning F:\\data2...")
    print("="*60)
    
    print("Scanning data2 directory...")
    data2_files = scan_directory_fast(data2)
    print(f"Found {len(data2_files):,} files in data2\n")
    
    if len(data2_files) == 0:
        print("No files found in data2. Exiting.")
        return
    
    print("Hashing and checking data2 files...")
    
    batch_size = max(1, len(data2_files) // (num_workers * 4))
    batches = [data2_files[i:i + batch_size] for i in range(0, len(data2_files), batch_size)]
    
    data2_hashed = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(batch_hash, batch) for batch in batches]
        
        with tqdm(total=len(data2_files), desc="Hashing data2", 
                 unit="files", smoothing=0.1) as pbar:
            for future in as_completed(futures):
                results = future.result()
                data2_hashed.extend(results)
                pbar.update(len(results))
    
    print(f"✓ Hashing complete\n")
    
    # Phase 3: Find and move malicious files
    print("="*60)
    print("Phase 3: Checking for malicious files...")
    print("="*60)
    
    malicious_found = []
    for result in data2_hashed:
        if result['hash'] and result['hash'] in malicious_hashes:
            malicious_found.append(result['filepath'])
    
    if len(malicious_found) == 0:
        print("✓ No malicious files found in data2!")
    else:
        print(f"⚠ Found {len(malicious_found):,} malicious files in data2")
        print("Moving to F:\\duplicate_files...\n")
        
        moved_count = 0
        error_count = 0
        
        with tqdm(total=len(malicious_found), desc="Moving malicious files", unit="files") as pbar:
            for filepath in malicious_found:
                try:
                    src_path = Path(filepath)
                    filename = src_path.name
                    dest_path = duplicate_files / get_unique_filename(duplicate_files, filename)
                    shutil.move(str(src_path), str(dest_path))
                    moved_count += 1
                    pbar.set_postfix_str(f"Moved: {filename[:30]}")
                except Exception as e:
                    tqdm.write(f"⚠ Error moving {filename}: {e}")
                    error_count += 1
                pbar.update(1)
        
        print(f"\n✓ Moved {moved_count:,} malicious files to duplicate_files")
        if error_count > 0:
            print(f"⚠ Errors: {error_count:,}")
    
    # Print summary
    elapsed = time.time() - start_time
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Malicious dataset files:  {len(malicious_files):,}")
    print(f"Unique malicious hashes:  {len(malicious_hashes):,}")
    print(f"Data2 files scanned:      {len(data2_files):,}")
    print(f"Malicious files found:    {len(malicious_found):,}")
    print(f"Files moved:              {moved_count if malicious_found else 0:,}")
    print(f"Total processing time:    {elapsed:.1f}s ({elapsed/60:.1f} min)")
    total_files = len(malicious_files) + len(data2_files)
    if total_files > 0:
        print(f"Average speed:            {total_files/elapsed:.1f} files/sec")
    print("="*60)

if __name__ == "__main__":
    print("="*60)
    print("Malicious Files Checker & Remover")
    print("="*60)
    print("\nThis script will:")
    print("1. Hash all files in F:\\datamaliciousorder (malicious dataset)")
    print("2. Hash all files in F:\\data2")
    print("3. Find files in data2 that match malicious dataset")
    print("4. Move matching files to F:\\duplicate_files")
    print("\n" + "="*60 + "\n")
    
    try:
        check_malicious_files()
    except KeyboardInterrupt:
        print("\n\n⚠ Process interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
