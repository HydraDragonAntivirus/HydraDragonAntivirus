import os
import shutil
import hashlib
import pefile

def is_pe_file(file_path):
    """
    Check if the file at the specified path is a Portable Executable (PE) file.
    
    Parameters:
        file_path (str): The path to the file to check.
        
    Returns:
        bool: True if the file is a valid PE file, False otherwise.
    """
    if not os.path.exists(file_path):
        return False

    try:
        with open(file_path, 'rb') as file:
            # Attempt to parse the file as a PE file
            pefile.PE(data=file.read())
            return True
    except pefile.PEFormatError:
        return False
    except Exception as e:
        print(f"Error occurred while checking if file is PE: {e}")
        return False

def compute_md5(file_path, chunk_size=4096):
    """
    Compute the MD5 hash of the specified file.
    
    Parameters:
        file_path (str): The path to the file.
        chunk_size (int): The chunk size for reading the file.
        
    Returns:
        str or None: The MD5 hash as a hexadecimal string, or None if an error occurs.
    """
    md5 = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(chunk_size):
                md5.update(chunk)
        return md5.hexdigest()
    except Exception as e:
        print(f"Error computing MD5 for {file_path}: {e}")
        return None

def collect_pe_files(directory):
    """
    Recursively scan the specified directory (including subdirectories) for PE files.
    
    Parameters:
        directory (str): The root directory to scan.
    
    Returns:
        list: A list of file paths that are valid PE files.
    """
    pe_files = []
    
    if not os.path.isdir(directory):
        print("The specified path is not a directory.")
        return pe_files

    # Walk through the directory tree
    for root, _, files in os.walk(directory):
        for name in files:
            full_path = os.path.join(root, name)
            if os.path.isfile(full_path) and is_pe_file(full_path):
                pe_files.append(full_path)
    
    return pe_files

def load_existing_hashes(destination_folder):
    """
    Scan the destination folder for existing files and return a set of their MD5 hashes.
    
    Parameters:
        destination_folder (str): The folder where files have been copied.
    
    Returns:
        set: A set of MD5 hash strings for files already in the destination.
    """
    hashes = set()
    if os.path.isdir(destination_folder):
        for entry in os.listdir(destination_folder):
            full_path = os.path.join(destination_folder, entry)
            if os.path.isfile(full_path):
                file_hash = compute_md5(full_path)
                if file_hash:
                    hashes.add(file_hash)
    return hashes

def copy_pe_files(pe_files, destination_folder):
    """
    Copy the PE files to the destination folder, skipping duplicates based on MD5 hash.
    
    Parameters:
        pe_files (list): A list of file paths to be copied.
        destination_folder (str): The path to the destination folder.
    """
    # Create the destination folder if it doesn't exist
    if not os.path.exists(destination_folder):
        os.makedirs(destination_folder)
    
    # Load MD5 hashes of files already in the destination folder
    existing_hashes = load_existing_hashes(destination_folder)
    
    for file_path in pe_files:
        file_hash = compute_md5(file_path)
        if not file_hash:
            continue

        if file_hash in existing_hashes:
            print(f"Duplicate file skipped (MD5: {file_hash}): {file_path}")
            continue
        
        try:
            shutil.copy2(file_path, destination_folder)
            print(f"Copied: {file_path} -> {destination_folder}")
            existing_hashes.add(file_hash)
        except Exception as e:
            print(f"Failed to copy {file_path}: {e}")

if __name__ == "__main__":
    # Prompt the user for the root directory to scan for PE files.
    # Note: The destination folder will be created in the current working directory.
    directory_path = input("Enter the directory path to scan for PE files: ").strip()
    
    # Recursively collect PE files in the provided directory and its subdirectories
    found_pe_files = collect_pe_files(directory_path)
    
    if found_pe_files:
        print("Found the following PE files:")
        for pe_file in found_pe_files:
            print(pe_file)
        
        # Define the destination folder in the current working directory
        destination_subfolder = os.path.join(os.getcwd(), "collected_pe_files")
        
        # Copy unique PE files into the destination folder
        copy_pe_files(found_pe_files, destination_subfolder)
        print("Unique PE files have been copied into:", destination_subfolder)
    else:
        print("No PE files found in the specified directory.")
