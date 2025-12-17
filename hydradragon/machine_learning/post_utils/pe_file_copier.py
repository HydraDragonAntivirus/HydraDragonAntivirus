import os
import shutil
import hashlib
import pefile
from pathlib import Path
from concurrent.futures import ProcessPoolExecutor, as_completed, ThreadPoolExecutor
from multiprocessing import cpu_count
import time
from tqdm import tqdm

def get_file_hash(filepath):
    """Calculate MD5 hash of file for duplicate detection."""
    hash_md5 = hashlib.md5()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):  # Larger chunks
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception:
        return None

def is_valid_pe(filepath):
    """Check if file is a valid PE file - quick method."""
    try:
        with open(filepath, "rb") as f:
            # Read DOS header
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b'MZ':
                return False
            
            # Get PE header offset
            pe_offset = int.from_bytes(dos_header[60:64], 'little')
            if pe_offset > 1024 or pe_offset < 0:  # Sanity check
                return False
            
            # Read PE signature
            f.seek(pe_offset)
            pe_sig = f.read(4)
            return pe_sig == b'PE\x00\x00'
    except Exception:
        return False

def validate_file(filepath):
    """Validate if file is PE and get its hash."""
    try:
        is_pe = is_valid_pe(filepath)
        file_hash = get_file_hash(filepath) if is_pe else None
        return {
            'filepath': filepath,
            'is_pe': is_pe,
            'hash': file_hash,
            'size': os.path.getsize(filepath) if is_pe else 0
        }
    except Exception as e:
        return {
            'filepath': filepath,
            'is_pe': False,
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
    
    while (dest_dir / f"{name}_{counter}{ext}").exists():
        counter += 1
    
    return f"{name}_{counter}{ext}"

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

def batch_validate(file_batch):
    """Validate a batch of files."""
    results = []
    for filepath in file_batch:
        results.append(validate_file(filepath))
    return results

def process_files():
    """Main function to process and copy files with parallel processing."""
    start_time = time.time()
    
    # Define directories
    source2 = Path(r"F:\data3\data2")
    dest = Path(r"F:\data2")
    problematic = Path(r"F:\problematic_files")
    duplicates_dir = Path(r"F:\duplicate_files")
    
    # Create directories if they don't exist
    problematic.mkdir(parents=True, exist_ok=True)
    duplicates_dir.mkdir(parents=True, exist_ok=True)
    
    # Determine number of workers
    num_workers = cpu_count()
    print(f"Using {num_workers} worker processes\n")
    
    # Phase 1: Scan and validate F:\data2
    print("="*60)
    print("Phase 1: Scanning F:\\data2...")
    print("="*60)
    
    hash_to_files = {}
    data2_files = []
    
    if dest.exists():
        print("Scanning directory structure...")
        data2_files = scan_directory_fast(dest)
        print(f"Found {len(data2_files):,} files. Validating in batches...\n")
        
        # Create batches for better performance
        batch_size = max(1, len(data2_files) // (num_workers * 4))
        batches = [data2_files[i:i + batch_size] for i in range(0, len(data2_files), batch_size)]
        
        with ProcessPoolExecutor(max_workers=num_workers) as executor:
            futures = [executor.submit(batch_validate, batch) for batch in batches]
            
            with tqdm(total=len(data2_files), desc="Validating F:\\data2", unit="files", 
                     smoothing=0.1) as pbar:
                for future in as_completed(futures):
                    results = future.result()
                    for result in results:
                        if result['is_pe'] and result['hash']:
                            file_hash = result['hash']
                            if file_hash not in hash_to_files:
                                hash_to_files[file_hash] = []
                            hash_to_files[file_hash].append(result['filepath'])
                    pbar.update(len(results))
        
        print(f"✓ Found {len(hash_to_files):,} unique PE files\n")
    
    # Find duplicates within F:\data2
    duplicates_in_data2 = {h: files for h, files in hash_to_files.items() if len(files) > 1}
    moved_duplicates = 0
    
    if duplicates_in_data2:
        total_dups = sum(len(files) - 1 for files in duplicates_in_data2.values())
        print(f"Found {len(duplicates_in_data2):,} sets of duplicates ({total_dups:,} files)")
        print("Moving to F:\\duplicate_files...\n")
        
        with tqdm(total=total_dups, desc="Moving duplicates", unit="files") as pbar:
            for file_hash, file_list in duplicates_in_data2.items():
                # Keep first file as original, move rest with (1), (2), etc.
                original_name = Path(file_list[0]).name
                base_name = Path(original_name).stem
                ext = Path(original_name).suffix
                
                for idx, filepath in enumerate(file_list[1:], start=1):
                    try:
                        src_path = Path(filepath)
                        # Generate name with (1), (2), (3) format
                        dup_name = f"{base_name} ({idx}){ext}"
                        dest_dup = duplicates_dir / get_unique_filename(duplicates_dir, dup_name)
                        shutil.move(str(src_path), str(dest_dup))
                        moved_duplicates += 1
                        hash_to_files[file_hash].remove(filepath)
                    except Exception as e:
                        tqdm.write(f"⚠ Error: {e}")
                    pbar.update(1)
        
        print(f"✓ Moved {moved_duplicates:,} duplicates\n")
    else:
        print("No duplicates found\n")
    
    # Update existing_hashes
    existing_hashes = {h: files[0] for h, files in hash_to_files.items() if files}
    
    # Phase 2: Process source directory
    if not source2.exists():
        print(f"Source directory {source2} does not exist.")
        return
    
    print("="*60)
    print("Phase 2: Scanning F:\\data3\\data2...")
    print("="*60)
    
    print("Scanning directory structure...")
    source_files = scan_directory_fast(source2)
    print(f"Found {len(source_files):,} files. Validating in batches...\n")
    
    # Validate source files
    batch_size = max(1, len(source_files) // (num_workers * 4))
    batches = [source_files[i:i + batch_size] for i in range(0, len(source_files), batch_size)]
    
    validated_files = []
    with ProcessPoolExecutor(max_workers=num_workers) as executor:
        futures = [executor.submit(batch_validate, batch) for batch in batches]
        
        with tqdm(total=len(source_files), desc="Validating source", unit="files",
                 smoothing=0.1) as pbar:
            for future in as_completed(futures):
                results = future.result()
                validated_files.extend(results)
                pbar.update(len(results))
    
    print(f"✓ Validation complete\n")
    
    # Phase 3: Process validated files
    print("="*60)
    print("Phase 3: Processing files...")
    print("="*60)
    
    stats = {
        'copied': 0,
        'duplicates': 0,
        'renamed': 0,
        'problematic': 0,
        'errors': 0,
        'data2_duplicates': moved_duplicates
    }
    
    # Use ThreadPoolExecutor for I/O operations
    with tqdm(total=len(validated_files), desc="Processing", unit="files", smoothing=0.1) as pbar:
        for result in validated_files:
            filepath = Path(result['filepath'])
            filename = filepath.name
            
            # Handle non-PE files
            if not result['is_pe']:
                try:
                    dest_problematic = problematic / get_unique_filename(problematic, filename)
                    shutil.move(str(filepath), str(dest_problematic))
                    stats['problematic'] += 1
                except Exception as e:
                    stats['errors'] += 1
                pbar.update(1)
                continue
            
            # Check for content duplicate
            if result['hash'] in existing_hashes:
                try:
                    filepath.unlink()
                    stats['duplicates'] += 1
                except Exception:
                    stats['errors'] += 1
                pbar.update(1)
                continue
            
            # Prepare destination path
            try:
                relative_path = filepath.relative_to(source2)
            except ValueError:
                relative_path = filepath.name
            
            dest_file = dest / relative_path
            
            # Handle name collision
            if dest_file.exists():
                new_name = get_unique_filename(dest_file.parent, filename)
                dest_file = dest_file.parent / new_name
                stats['renamed'] += 1
            
            # Copy and remove source
            try:
                dest_file.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(str(filepath), str(dest_file))
                filepath.unlink()
                existing_hashes[result['hash']] = str(dest_file)
                stats['copied'] += 1
            except Exception:
                stats['errors'] += 1
            
            pbar.update(1)
    
    # Print summary
    elapsed = time.time() - start_time
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"Duplicates in F:\\data2:  {stats['data2_duplicates']:,}")
    print(f"Files copied:             {stats['copied']:,}")
    print(f"Files renamed:            {stats['renamed']:,}")
    print(f"Duplicates from source:   {stats['duplicates']:,}")
    print(f"Problematic files:        {stats['problematic']:,}")
    print(f"Errors:                   {stats['errors']:,}")
    print(f"Total processing time:    {elapsed:.1f}s ({elapsed/60:.1f} min)")
    total_files = len(data2_files) + len(source_files)
    if total_files > 0:
        print(f"Average speed:            {total_files/elapsed:.1f} files/sec")
    print("="*60)

if __name__ == "__main__":
    print("="*60)
    print("PE File Copy & Validation Tool (Optimized)")
    print("="*60)
    print("\nOptimizations for large datasets:")
    print("- Fast PE validation (header check only)")
    print("- Batch processing for better CPU utilization")
    print("- Optimized file I/O with larger buffers")
    print("- os.walk() for faster directory scanning")
    print("\n" + "="*60 + "\n")
    
    try:
        process_files()
    except KeyboardInterrupt:
        print("\n\n⚠ Process interrupted by user")
    except Exception as e:
        print(f"\n❌ Fatal error: {e}")
        import traceback
        traceback.print_exc()
