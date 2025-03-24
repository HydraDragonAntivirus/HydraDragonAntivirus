#!/usr/bin/env python
import os
import sys
import glob
import time
import json
import pickle
import logging
import argparse
import subprocess
import numpy as np
from shutil import rmtree
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

# Hardcoded paths for sandbox environment data.
LOG_DIR = r"C:\sandbox_logs"
DUMP_DIR = r"C:\sandbox_dumps"
os.makedirs(LOG_DIR, exist_ok=True)
os.makedirs(DUMP_DIR, exist_ok=True)

# Hardcoded log file path.
log_file_path = os.path.join(LOG_DIR, "dynamictrain.log")

# Configure logging.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(log_file_path, mode='a', encoding='utf-8')
    ]
)

# Path to Sandboxie Start.exe (adjust if needed)
SANDBOXIE_PATH = r"C:\Program Files\Sandboxie\Start.exe"

def full_cleanup_sandbox():
    """
    Fully cleans up the Sandboxie environment using Sandboxie's termination commands.
    It issues:
      - Start.exe /terminate
      - Start.exe /box:DefaultBox /terminate
      - Start.exe /terminate_all
    with short delays between each command.
    """
    try:
        logging.info("Starting full sandbox cleanup using Start.exe termination commands...")
        cmd1 = [SANDBOXIE_PATH, "/terminate"]
        result1 = subprocess.run(cmd1, capture_output=True, text=True)
        if result1.returncode != 0:
            logging.error(f"Command {cmd1} failed: {result1.stderr}")
        else:
            logging.info(f"Command {cmd1} successful.")
        time.sleep(2)
        
        cmd2 = [SANDBOXIE_PATH, "/box:DefaultBox", "/terminate"]
        result2 = subprocess.run(cmd2, capture_output=True, text=True)
        if result2.returncode != 0:
            logging.error(f"Command {cmd2} failed: {result2.stderr}")
        else:
            logging.info(f"Command {cmd2} successful.")
        time.sleep(2)
        
        cmd3 = [SANDBOXIE_PATH, "/terminate_all"]
        result3 = subprocess.run(cmd3, capture_output=True, text=True)
        if result3.returncode != 0:
            logging.error(f"Command {cmd3} failed: {result3.stderr}")
        else:
            logging.info(f"Command {cmd3} successful.")
        time.sleep(1)
    except Exception as ex:
        logging.error(f"Full sandbox cleanup encountered an exception: {ex}")

def cleanup_old_sandbox_data():
    """
    Cleans up previous sandbox training data in the dump directory,
    excluding the baseline memory file.
    """
    try:
        logging.info("Cleaning up previous sandbox data in dump directory...")
        for fname in os.listdir(DUMP_DIR):
            if fname.lower() == "baseline_memory.bin":
                continue
            file_path = os.path.join(DUMP_DIR, fname)
            if os.path.isdir(file_path):
                rmtree(file_path, ignore_errors=True)
                logging.info(f"Removed old directory: {file_path}")
            else:
                os.remove(file_path)
                logging.info(f"Removed old file: {file_path}")
    except Exception as ex:
        logging.error(f"Failed to cleanup old sandbox data: {ex}")

def is_process_closed(process_name):
    """
    Checks if the given process (by image name) is closed.
    Returns True if not found in tasklist; otherwise, False.
    """
    try:
        cmd = ["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/NH"]
        output = subprocess.check_output(cmd, text=True)
        if "No tasks are running" in output or process_name.lower() not in output.lower():
            return True
        return False
    except Exception as ex:
        logging.error(f"Error checking process status for {process_name}: {ex}")
        return True

def run_in_sandbox(file_path):
    """
    Runs the given file in the Sandboxie environment using DefaultBox.
    """
    try:
        logging.info(f"Running {file_path} in sandbox (DefaultBox)...")
        subprocess.run([SANDBOXIE_PATH, "/box:DefaultBox", file_path], check=True)
        return True
    except subprocess.CalledProcessError as ex:
        logging.error(f"Sandboxie execution failed for {file_path}: {ex}")
        return False

def check_program_executed(file_path):
    """
    Waits for 10 seconds (auto termination period) then checks if the target process is closed.
    Returns True if the process has terminated; otherwise, False.
    """
    time.sleep(10)
    proc_name = os.path.basename(file_path)
    if is_process_closed(proc_name):
        logging.info(f"Process {proc_name} has terminated.")
        return True
    else:
        logging.warning(f"Process {proc_name} is still running.")
        return False

def scan_memory(file_path):
    """
    Simulates a dynamic memory scan by reading the file content as a byte array.
    """
    try:
        with open(file_path, "rb") as f:
            memory_dump = f.read()
        logging.info(f"Scanned memory from {file_path} (size: {len(memory_dump)} bytes)")
        return memory_dump
    except Exception as ex:
        logging.error(f"Memory scan failed for {file_path}: {ex}")
        return b""

def get_baseline_memory():
    """
    Retrieves the baseline (clean) memory state from a hardcoded file in the dump directory.
    """
    baseline_file = os.path.join(DUMP_DIR, "baseline_memory.bin")
    if os.path.exists(baseline_file):
        with open(baseline_file, "rb") as f:
            baseline = f.read()
        logging.info("Loaded baseline memory from file.")
    else:
        baseline = b"CLEAN_MEMORY_STATE" * 64
        with open(baseline_file, "wb") as f:
            f.write(baseline)
        logging.info("Created new baseline memory file.")
    return baseline

def extract_malicious_signature(baseline, current):
    """
    Compares the clean baseline memory with the current memory dump.
    Returns a dynamic dump signature composed of:
      - The total number of difference bytes
      - The hexadecimal representation of the first 16 bytes of the diff
    If no differences are found, returns "0".
    (No hashlib is used.)
    """
    common_length = min(len(baseline), len(current))
    diff = bytearray()
    for i in range(common_length):
        if baseline[i] != current[i]:
            diff.append(current[i])
    if len(current) > common_length:
        diff.extend(current[common_length:])
    
    if diff:
        signature = f"{len(diff)}-{diff[:16].hex()}"
        logging.info(f"Extracted dynamic dump signature: {signature}")
        return signature, diff
    else:
        logging.info("No malicious changes detected.")
        return "0", None

def extract_features_from_signature(signature):
    """
    Converts the dynamic dump signature string into a numerical feature vector.
    The signature is expected in the form "diffLength-hexPrefix". If signature is "0",
    returns a vector of zeros (length 64).
    """
    try:
        if signature == "0":
            return np.zeros(64, dtype=int)
        parts = signature.split('-')
        # We ignore the diff length and use the hexPrefix.
        diff_prefix = [int(parts[1][i:i+2], 16) for i in range(0, len(parts[1]), 2)]
        if len(diff_prefix) < 64:
            diff_prefix += [0] * (64 - len(diff_prefix))
        else:
            diff_prefix = diff_prefix[:64]
        return np.array(diff_prefix, dtype=int)
    except Exception as ex:
        logging.error(f"Feature extraction failed: {ex}")
        return None

def process_file(file_path):
    """
    Forces the file to run as an executable (renaming if needed), then runs it in the sandbox,
    performs a memory scan, compares the result with the baseline to extract the dynamic dump signature,
    and finally cleans up the sandbox.
    If malicious differences are found (i.e. signature != "0"), saves the current memory dump for that target.
    Returns a tuple (signature, original_file_name) or None on failure.
    """
    full_cleanup_sandbox()
    
    original_path = file_path
    if not file_path.lower().endswith(".exe"):
        file_path_exe = file_path + ".exe"
        try:
            os.rename(file_path, file_path_exe)
            logging.info(f"Renamed {original_path} to {file_path_exe}")
            file_path = file_path_exe
        except Exception as ex:
            logging.error(f"Failed to rename file {original_path} to .exe: {ex}")
            return None

    baseline = get_baseline_memory()

    if not run_in_sandbox(file_path):
        full_cleanup_sandbox()
        return None

    if not check_program_executed(file_path):
        logging.error(f"Program did not execute properly: {file_path}")
        full_cleanup_sandbox()
        return None

    current_memory = scan_memory(file_path)
    dynamic_signature, diff = extract_malicious_signature(baseline, current_memory)
    
    if dynamic_signature != "0":
        dump_file = os.path.join(DUMP_DIR, f"{os.path.basename(original_path)}_malicious_dump.bin")
        try:
            with open(dump_file, "wb") as f:
                f.write(current_memory)
            logging.info(f"Saved malicious memory dump to {dump_file}")
        except Exception as ex:
            logging.error(f"Failed to save malicious dump for {original_path}: {ex}")
    
    full_cleanup_sandbox()
    return dynamic_signature, os.path.basename(original_path)

def collect_dynamic_features(directory, label):
    """
    Processes all files in the given directory (for benign files).
    Returns a tuple (features, labels, file_names).
    """
    features = []
    labels = []
    file_names = []
    file_list = glob.glob(os.path.join(directory, "*"))
    logging.info(f"Found {len(file_list)} files in {directory}")
    for file_path in file_list:
        logging.info(f"Processing file: {file_path}")
        result = process_file(file_path)
        if result:
            signature, fname = result
            feat = extract_features_from_signature(signature)
            if feat is not None:
                if len(feat) < 64:
                    feat = np.pad(feat, (0, 64 - len(feat)), 'constant')
                else:
                    feat = feat[:64]
                features.append(feat)
                labels.append(label)
                file_names.append(fname)
    return features, labels, file_names

def collect_dynamic_features_malicious(directory):
    """
    Processes all files in the given malicious directory.
    Each malicious file is assigned a unique label (starting at 1).
    Returns a tuple (features, labels, file_names).
    """
    features = []
    labels = []
    file_names = []
    file_list = glob.glob(os.path.join(directory, "*"))
    logging.info(f"Found {len(file_list)} malicious files in {directory}")
    for idx, file_path in enumerate(file_list):
        logging.info(f"Processing malicious file: {file_path}")
        result = process_file(file_path)
        if result:
            signature, fname = result
            feat = extract_features_from_signature(signature)
            if feat is not None:
                if len(feat) < 64:
                    feat = np.pad(feat, (0, 64 - len(feat)), 'constant')
                else:
                    feat = feat[:64]
                features.append(feat)
                labels.append(idx + 1)  # Unique label starting at 1.
                file_names.append(fname)
    return features, labels, file_names

def train_model(features, labels):
    """
    Trains a Random Forest classifier using the extracted dynamic features.
    """
    X = np.array(features)
    y = np.array(labels)
    if X.shape[1] > 64:
        X = X[:, :64]
    elif X.shape[1] < 64:
        X = np.pad(X, ((0, 0), (0, 64 - X.shape[1])), 'constant')
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred)
    logging.info("Classification Report:\n" + report)
    model_path = os.path.join(DUMP_DIR, "dynamic_model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)
    logging.info(f"Model trained and saved as {model_path}")
    return clf

def save_databases(benign_names, benign_features, malicious_names, malicious_features):
    """
    Saves four JSON databases:
      - benign_database.json: mapping from index (starting at 1) to benign filename.
      - benign_features.json: mapping from index to benign feature vector (list).
      - malicious_database.json: mapping from index (starting at 1) to malicious filename.
      - malicious_features.json: mapping from index to malicious feature vector (list).
    """
    benign_db_path = os.path.join(DUMP_DIR, "benign_database.json")
    benign_features_path = os.path.join(DUMP_DIR, "benign_features.json")
    malicious_db_path = os.path.join(DUMP_DIR, "malicious_database.json")
    malicious_features_path = os.path.join(DUMP_DIR, "malicious_features.json")
    
    benign_mapping = {str(i+1): name for i, name in enumerate(benign_names)}
    with open(benign_db_path, "w") as f:
        json.dump(benign_mapping, f, indent=2)
    logging.info(f"Saved benign database to {benign_db_path}")
    
    benign_features_mapping = {str(i+1): feat.tolist() for i, feat in enumerate(benign_features)}
    with open(benign_features_path, "w") as f:
        json.dump(benign_features_mapping, f, indent=2)
    logging.info(f"Saved benign features mapping to {benign_features_path}")
    
    malicious_mapping = {str(i+1): name for i, name in enumerate(malicious_names)}
    with open(malicious_db_path, "w") as f:
        json.dump(malicious_mapping, f, indent=2)
    logging.info(f"Saved malicious database to {malicious_db_path}")
    
    malicious_features_mapping = {str(i+1): feat.tolist() for i, feat in enumerate(malicious_features)}
    with open(malicious_features_path, "w") as f:
        json.dump(malicious_features_mapping, f, indent=2)
    logging.info(f"Saved malicious features mapping to {malicious_features_path}")

def main():
    parser = argparse.ArgumentParser(description="Dynamic Analysis and Memory Difference Detection Engine (Multi-class)")
    parser.add_argument("--benign-dir", default="data2", help="Directory containing benign files")
    parser.add_argument("--malicious-dir", default="datamaliciousorder", help="Directory containing malicious files")
    args = parser.parse_args()

    # Optionally clean up old sandbox data.
    cleanup_old = True
    if cleanup_old:
        try:
            for fname in os.listdir(DUMP_DIR):
                if fname.lower() != "baseline_memory.bin":
                    file_path = os.path.join(DUMP_DIR, fname)
                    if os.path.isdir(file_path):
                        rmtree(file_path, ignore_errors=True)
                        logging.info(f"Removed old directory: {file_path}")
                    else:
                        os.remove(file_path)
                        logging.info(f"Removed old file: {file_path}")
        except Exception as ex:
            logging.error(f"Failed to cleanup old sandbox data: {ex}")

    benign_features, benign_labels, benign_names = collect_dynamic_features(args.benign_dir, label=0)
    malicious_features, malicious_labels, malicious_names = collect_dynamic_features_malicious(args.malicious_dir)

    all_features = benign_features + malicious_features
    all_labels = benign_labels + malicious_labels

    if not all_features:
        logging.error("No dynamic features extracted. Exiting.")
        return

    clf = train_model(all_features, all_labels)
    save_databases(benign_names, benign_features, malicious_names, malicious_features)

if __name__ == "__main__":
    main()
