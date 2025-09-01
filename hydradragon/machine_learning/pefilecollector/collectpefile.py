import os
import sys
import time
import shutil
import hashlib
import pefile
from pathlib import Path


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


def scan_directory(root_dir, max_size_mb=10):
    """
    Recursively scan the directory for unique PE files under a size threshold,
    ignoring access-denied errors.
    Returns a list of dicts with path, size(bytes), size_mb, md5.
    """
    max_size = max_size_mb * 1024 * 1024
    found = []
    seen_hashes = set()
    total_scanned = 0

    print(f"Scanning '{root_dir}' for PE files <= {max_size_mb}MB (ignoring access errors)...")
    start = time.time()

    for dirpath, dirs, files in os.walk(root_dir, onerror=lambda e: None):
        # skip system or hidden directories
        dirs[:] = [d for d in dirs if not d.startswith('$')]
        for fname in files:
            full = os.path.join(dirpath, fname)
            total_scanned += 1
            try:
                size = os.path.getsize(full)
            except (OSError, PermissionError):
                continue

            if size == 0 or size > max_size:
                continue

            if not is_pe_file(full):
                continue

            md5 = compute_md5(full)
            if not md5 or md5 in seen_hashes:
                continue

            seen_hashes.add(md5)
            entry = {
                'path': full,
                'size': size,
                'size_mb': round(size / (1024*1024), 2),
                'md5': md5
            }
            found.append(entry)
            print(f"[FOUND] {full} ({entry['size_mb']} MB) MD5={md5}")

    elapsed = time.time() - start
    print(f"\nScan complete: {len(found)} unique PE files found in {total_scanned} files scanned ({elapsed:.2f}s)")
    return found


def save_results(found, out_file="pe_scan_results.txt"):
    """
    Save scan results to a text file.
    """
    try:
        with open(out_file, 'w', encoding='utf-8') as f:
            f.write("PE Files Found:\n")
            f.write("="*40 + "\n")
            for e in found:
                f.write(f"Path: {e['path']}\nSize: {e['size_mb']} MB ({e['size']} bytes)\nMD5: {e['md5']}\n")
                f.write("-"*20 + "\n")
        print(f"Results saved to '{out_file}'")
    except Exception as e:
        print(f"Failed to save results: {e}")


def copy_to_folder(found, dest):
    """
    Copy unique files to destination folder, skipping duplicates and ignoring access errors.
    """
    os.makedirs(dest, exist_ok=True)
    existing = set()
    for fp in Path(dest).rglob('*'):
        if not fp.is_file():
            continue
        h = compute_md5(str(fp))
        if h:
            existing.add(h)

    count = 0
    for e in found:
        md5 = e['md5']
        if md5 in existing:
            print(f"Skipping duplicate in dest: {e['path']}")
            continue
        try:
            shutil.copy2(e['path'], dest)
            existing.add(md5)
            count += 1
            print(f"Copied: {e['path']} -> {dest}")
        except (OSError, PermissionError) as ex:
            continue
        except Exception as ex:
            print(f"Error copying {e['path']}: {ex}")

    print(f"\nCopied {count} new files to '{dest}'")


def main():
    root = input("Directory to scan for PE files: ").strip()
    if not os.path.isdir(root):
        print("Invalid directory.")
        sys.exit(1)

    max_mb = input("Max file size in MB [10]: ").strip() or "10"
    try:
        max_mb = int(max_mb)
    except ValueError:
        max_mb = 10

    found = scan_directory(root, max_mb)
    if not found:
        sys.exit(0)

    save_results(found)

    # Use 'data2' as the destination folder
    dest = os.path.join(os.getcwd(), "data2")
    choice = input(f"Copy files to '{dest}'? (y/n): ").lower()
    if choice in ('y','yes'):
        copy_to_folder(found, dest)
    else:
        print("Copy skipped.")


if __name__ == '__main__':
    main()
