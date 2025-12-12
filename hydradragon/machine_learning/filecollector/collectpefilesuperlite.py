import os
import sys
import time
import shutil
import hashlib
import json
import ctypes
import logging
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor, as_completed

# Try to import tqdm
try:
    from tqdm import tqdm
except ImportError:
    print("Error: 'tqdm' is missing. Install it: pip install tqdm")
    sys.exit(1)

# --- CONFIGURATION ---
CHUNK_SIZE = 1024 * 1024  # 1MB Buffer
MAX_FILE_SIZE_MB = 10
CACHE_FILE = "md5_cache.json"
REPORT_FILE = "scan_results.txt"

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pe_scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


def is_admin():
    """Check if script is running with admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


# --- OPTIMIZED WORKER FUNCTIONS ---
def get_md5_fast(path):
    """Compute MD5 with efficient buffering."""
    hash_md5 = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except (IOError, OSError) as e:
        logger.debug(f"Cannot read {path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error hashing {path}: {e}")
        return None


def is_mz_file(path):
    """
    Fast check: Read first 2 bytes for 'MZ' header.
    This is enough to identify PE/EXE/DLL files.
    """
    try:
        with open(path, 'rb') as f:
            return f.read(2) == b'MZ'
    except (IOError, OSError):
        return False
    except Exception as e:
        logger.debug(f"MZ check failed for {path}: {e}")
        return False


def worker_scan_file(args):
    """
    Worker process for scanning a single file.
    Returns file info if it's a new MZ file, None otherwise.
    """
    path, max_bytes = args
    
    try:
        # Fast OS stat
        stat = os.stat(path)
        size = stat.st_size
        
        # Filter: Size check
        if size == 0 or size > max_bytes:
            return None
        
        # Filter: Is it an MZ file?
        if not is_mz_file(path):
            return None
        
        # Calculate hash
        md5 = get_md5_fast(path)
        if not md5:
            return None
        
        # Return result (hash filtering happens in main process)
        return {
            'path': path,
            'size_mb': round(size / (1024 * 1024), 2),
            'md5': md5
        }
    except (IOError, OSError) as e:
        logger.debug(f"Cannot access {path}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error scanning {path}: {e}")
        return None


def worker_load_hash(path):
    """Worker for calculating hash of existing files."""
    return get_md5_fast(path)


# --- FILE ENUMERATION ---
def discover_files(root_dir):
    """
    List all files using os.walk recursively.
    Returns a list of all file paths.
    """
    if not os.path.isdir(root_dir):
        logger.error(f"Directory does not exist: {root_dir}")
        return []
    
    file_paths = []
    logger.info(f"Scanning file system structure of '{root_dir}'...")
    
    try:
        for root, _, files in os.walk(root_dir):
            for file in files:
                file_paths.append(os.path.join(root, file))
    except Exception as e:
        logger.error(f"Error walking directory {root_dir}: {e}")
        return []
    
    logger.info(f"Found {len(file_paths)} files total.")
    return file_paths


# --- MAIN LOGIC BLOCKS ---
def load_existing_hashes_parallel(folder):
    """Load hashes from existing files using parallel processing."""
    existing = set()
    
    if not os.path.isdir(folder):
        logger.warning(f"Folder does not exist: {folder}")
        return existing
    
    files = discover_files(folder)
    if not files:
        logger.info("No files found in existing folder.")
        return existing
    
    logger.info("Hashing existing files...")
    
    # Use optimal worker count
    max_workers = max(1, os.cpu_count() - 1)
    
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        results = list(tqdm(
            executor.map(worker_load_hash, files, chunksize=50),
            total=len(files),
            unit="file",
            desc="Hashing"
        ))
    
    # Filter out Nones
    for h in results:
        if h:
            existing.add(h)
    
    logger.info(f"Loaded {len(existing)} unique hashes.")
    return existing


def scan_with_parallel(root_dir, max_mb, existing_hashes):
    """Scan directory for MZ files using parallel processing."""
    max_bytes = max_mb * 1024 * 1024
    
    # 1. Get list of files first
    all_files = discover_files(root_dir)
    if not all_files:
        logger.warning("No files found to scan.")
        return []
    
    found_entries = []
    
    # 2. Prepare arguments for workers (don't pass existing_hashes)
    tasks = [(f, max_bytes) for f in all_files]
    
    # 3. Use optimal worker count
    max_workers = max(1, os.cpu_count() - 1)
    logger.info(f"Scanning with {max_workers} worker processes...")
    logger.info(f"Processing {len(tasks)} files (max size: {max_mb}MB)...")
    
    # 4. Execute with Progress Bar - Process in batches to avoid memory issues
    batch_size = 10000  # Process 10k files at a time
    
    try:
        with ProcessPoolExecutor(max_workers=max_workers) as executor:
            for i in range(0, len(tasks), batch_size):
                batch = tasks[i:i + batch_size]
                logger.info(f"Processing batch {i//batch_size + 1}/{(len(tasks)//batch_size) + 1}")
                
                # Submit batch
                futures = [executor.submit(worker_scan_file, t) for t in batch]
                
                # Monitor with TQDM
                for future in tqdm(as_completed(futures), total=len(futures), unit="file", desc=f"Batch {i//batch_size + 1}"):
                    try:
                        res = future.result(timeout=1200)  # 1200 second timeout per file
                        if res:
                            # Filter by hash in main process (avoids passing large set to workers)
                            if res['md5'] not in existing_hashes:
                                found_entries.append(res)
                                tqdm.write(f"✓ Found: {res['path']}")
                    except TimeoutError:
                        logger.warning(f"Worker timeout - file took too long")
                        continue
                    except Exception as e:
                        # Log individual file errors but continue
                        logger.debug(f"Worker error: {e}")
                        continue
    except KeyboardInterrupt:
        logger.warning("Scan interrupted by user.")
        return found_entries
    except Exception as e:
        logger.error(f"Error during scan: {e}", exc_info=True)
        return found_entries
    
    logger.info(f"Scan complete. Found {len(found_entries)} new MZ files.")
    return found_entries


# --- CACHE MANAGEMENT ---
def save_cache(hashes, filename=CACHE_FILE):
    """Save hash cache using JSON."""
    try:
        with open(filename, 'w') as f:
            json.dump({
                'hashes': list(hashes), 
                'timestamp': time.time(),
                'count': len(hashes)
            }, f, indent=2)
        logger.info(f"Cache saved to {filename} ({len(hashes)} hashes)")
    except Exception as e:
        logger.error(f"Error saving cache: {e}")


def load_cache(filename=CACHE_FILE):
    """Load hash cache from JSON file."""
    if not os.path.exists(filename):
        logger.info("No cache file found.")
        return set()
    
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            hashes = set(data.get('hashes', []))
            timestamp = data.get('timestamp', 0)
            age_hours = (time.time() - timestamp) / 3600
            logger.info(f"Loaded {len(hashes)} hashes from cache (age: {age_hours:.1f} hours)")
            return hashes
    except json.JSONDecodeError as e:
        logger.error(f"Cache file corrupted: {e}")
        return set()
    except Exception as e:
        logger.error(f"Error loading cache: {e}")
        return set()


def save_report(found, filename=REPORT_FILE):
    """Save scan results to a report file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"MZ File Scanner Report - {time.ctime()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(f"Total files found: {len(found)}\n\n")
            
            # Sort by size descending
            found_sorted = sorted(found, key=lambda x: x['size_mb'], reverse=True)
            
            for entry in found_sorted:
                f.write(f"Hash: {entry['md5']}\n")
                f.write(f"Size: {entry['size_mb']} MB\n")
                f.write(f"Path: {entry['path']}\n")
                f.write("-" * 80 + "\n")
        
        logger.info(f"Report saved to {filename}")
    except Exception as e:
        logger.error(f"Error saving report: {e}")


def copy_files_parallel(found_entries, dest_folder):
    """Copy files using thread pool for better I/O performance."""
    if not found_entries:
        logger.info("No files to copy.")
        return
    
    try:
        os.makedirs(dest_folder, exist_ok=True)
    except Exception as e:
        logger.error(f"Cannot create destination folder: {e}")
        return
    
    logger.info(f"Copying {len(found_entries)} files to {dest_folder}...")
    
    def copy_single_file(entry):
        """Copy a single file with duplicate handling."""
        try:
            src = entry['path']
            filename = os.path.basename(src)
            dest_path = os.path.join(dest_folder, filename)
            
            # Handle duplicates
            if os.path.exists(dest_path):
                name, ext = os.path.splitext(filename)
                counter = 1
                while os.path.exists(dest_path):
                    dest_path = os.path.join(dest_folder, f"{name}_{counter}{ext}")
                    counter += 1
            
            shutil.copy2(src, dest_path)
            return True
        except Exception as e:
            logger.error(f"Error copying {entry['path']}: {e}")
            return False
    
    # Use ThreadPoolExecutor for I/O-bound copying
    success_count = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(copy_single_file, entry) for entry in found_entries]
        
        for future in tqdm(as_completed(futures), total=len(futures), unit="file", desc="Copying"):
            if future.result():
                success_count += 1
    
    logger.info(f"Successfully copied {success_count}/{len(found_entries)} files.")


# --- USER INTERFACE ---
def get_valid_path(prompt):
    """Get and validate a directory path from user."""
    while True:
        path = input(prompt).strip().strip('"').strip("'")
        if os.path.isdir(path):
            return path
        print(f"Error: '{path}' is not a valid directory. Try again.")


def confirm_action(prompt):
    """Get yes/no confirmation from user."""
    while True:
        response = input(prompt).strip().lower()
        if response in ['y', 'yes']:
            return True
        if response in ['n', 'no']:
            return False
        print("Please enter 'y' or 'n'.")


def main():
    """Main program loop."""
    if not is_admin():
        logger.warning("⚠ Not running as Admin. System files may be skipped.")
        time.sleep(2)
    
    while True:
        print("\n" + "=" * 50)
        print("MZ FILE SCANNER - Optimized (MZ Header Only)")
        print("=" * 50)
        print("1. Full Scan (Recalculate Hashes → Scan → Copy)")
        print("2. Update Cache Only (Recalculate Hashes)")
        print("3. Quick Scan (Use Cached Hashes)")
        print("4. View Cache Info")
        print("5. Exit")
        print("=" * 50)
        
        mode = input("\nSelect option [1-5]: ").strip()
        
        try:
            if mode == '1':
                # Full workflow
                data2 = get_valid_path("Enter Data2 folder path: ")
                scan_dir = get_valid_path("Enter directory to scan: ")
                
                existing = load_existing_hashes_parallel(data2)
                save_cache(existing)
                
                found = scan_with_parallel(scan_dir, MAX_FILE_SIZE_MB, existing)
                save_report(found)
                
                if found and confirm_action(f"Copy {len(found)} files to {data2}? (y/n): "):
                    copy_files_parallel(found, data2)
            
            elif mode == '2':
                # Update cache only
                data2 = get_valid_path("Enter Data2 folder path: ")
                existing = load_existing_hashes_parallel(data2)
                save_cache(existing)
            
            elif mode == '3':
                # Quick scan using cache
                existing = load_cache()
                if not existing:
                    logger.warning("Cache is empty. Run option 2 first to build cache.")
                    continue
                
                scan_dir = get_valid_path("Enter directory to scan: ")
                found = scan_with_parallel(scan_dir, MAX_FILE_SIZE_MB, existing)
                save_report(found)
                
                if found:
                    data2 = get_valid_path("Enter destination folder for copying: ")
                    if confirm_action(f"Copy {len(found)} files? (y/n): "):
                        copy_files_parallel(found, data2)
            
            elif mode == '4':
                # View cache info
                existing = load_cache()
                print(f"\n📊 Cache contains {len(existing)} unique hashes")
                if os.path.exists(CACHE_FILE):
                    size_kb = os.path.getsize(CACHE_FILE) / 1024
                    print(f"📁 Cache file size: {size_kb:.2f} KB")
            
            elif mode == '5':
                logger.info("Exiting...")
                sys.exit(0)
            
            else:
                print("Invalid option. Please select 1-5.")
        
        except KeyboardInterrupt:
            print("\n\nOperation cancelled by user.")
            if confirm_action("Exit program? (y/n): "):
                sys.exit(0)
        except Exception as e:
            logger.error(f"Unexpected error: {e}")


if __name__ == '__main__':
    main()
