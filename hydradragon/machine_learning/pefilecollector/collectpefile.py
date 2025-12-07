import os
import sys
import time
import shutil
import hashlib
import pefile
import ctypes
from pathlib import Path


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
    Load MD5 hashes of all files in the specified folder.
    Returns a set of MD5 hashes.
    """
    existing = set()
    if not os.path.isdir(folder):
        return existing
    
    print(f"Loading existing files from '{folder}'...")
    count = 0
    for fp in Path(folder).rglob('*'):
        if not fp.is_file():
            continue
        h = compute_md5(str(fp))
        if h:
            existing.add(h)
            count += 1
    
    print(f"Loaded {count} existing file hashes from '{folder}'")
    return existing


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

    print(f"\nScanning '{root_dir}' for PE files <= {max_size_mb}MB (ignoring access errors)...")
    start = time.time()

    for dirpath, dirs, files in os.walk(root_dir, onerror=lambda e: None):
        for fname in files:
            full = os.path.join(dirpath, fname)
            total_scanned += 1
            
            # Show progress every 1000 files
            if total_scanned % 1000 == 0:
                print(f"[Progress] Scanned {total_scanned} files, found {len(found)} new PE files so far...")
            
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
            print(f"({len(found)}) [NEW] {full} ({entry['size_mb']} MB) MD5={md5}")

    elapsed = time.time() - start
    print(f"\nScan complete:")
    print(f"  - {len(found)} new unique PE files found")
    print(f"  - {skipped_duplicates} duplicates skipped (already in data2)")
    print(f"  - {total_scanned} total files scanned ({elapsed:.2f}s)")
    return found


def save_results(found, out_file="pe_scan_results.txt"):
    """
    Save scan results to a text file.
    """
    try:
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write("PE Files Found (New, not in data2):\n")
            f.write("="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB ({e['size']} bytes)\nMD5: {e['md5']}\n")
                f.write("-"*20 + "\n")
        print(f"Results saved to '{out_file}'")
    except Exception as e:
        print(f"Failed to save results: {e}")


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
                print(f"Renaming to avoid conflict: {filename} -> {os.path.basename(dest_path)}")
            
            shutil.copy2(src_path, dest_path)
            count += 1
            print(f"Copied: {src_path} -> {dest_path}")
        except (OSError, PermissionError) as ex:
            continue
        except Exception as ex:
            print(f"Error copying {e['path']}: {ex}")

    print(f"\nCopied {count} new files to '{dest}'")


def main():
    # Check for admin privileges
    if not is_admin():
        print("WARNING: Not running as administrator!")
        print("Some system directories may be inaccessible.")
        choice = input("Continue anyway? (y/n): ").lower()
        if choice not in ('y', 'yes'):
            print("Exiting. Please run as administrator for full access.")
            sys.exit(1)
        print()

    root = input("Directory to scan for PE files: ").strip()
    if not os.path.isdir(root):
        print("Invalid directory.")
        sys.exit(1)

    max_mb = input("Max file size in MB [10]: ").strip() or "10"
    try:
        max_mb = int(max_mb)
    except ValueError:
        max_mb = 10

    # Load existing hashes from data2 folder
    dest = os.path.join(os.getcwd(), "data2")
    existing_hashes = load_existing_hashes(dest)

    # Scan directory, excluding files already in data2
    found = scan_directory(root, max_mb, existing_hashes)
    
    if not found:
        print("\nNo new PE files found (all are duplicates or none match criteria).")
        sys.exit(0)

    save_results(found)

    choice = input(f"\nCopy {len(found)} new files to '{dest}'? (y/n): ").lower()
    if choice in ('y','yes'):
        copy_to_folder(found, dest)
    else:
        print("Copy skipped.")


if __name__ == '__main__':
    main()
