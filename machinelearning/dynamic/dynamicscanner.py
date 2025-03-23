#!/usr/bin/env python
import os
import sys
import argparse
import pickle
import logging
import numpy as np
from dynamictrain import process_file, extract_features_from_signature, full_cleanup_sandbox

# Hardcoded dump directory (same as in dynamictrain.py)
DUMP_DIR = r"C:\sandbox_dumps"
MODEL_PATH = os.path.join(DUMP_DIR, "dynamic_model.pkl")

# Configure logging
LOG_FILE = r"C:\sandbox_logs\scanner.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode='a', encoding='utf-8')
    ]
)

def load_model(model_path):
    if not os.path.exists(model_path):
        logging.error(f"Model not found at {model_path}")
        sys.exit(1)
    with open(model_path, "rb") as f:
        model = pickle.load(f)
    logging.info("Model loaded successfully.")
    return model

def scan_file(file_path, model):
    """
    Processes the given file using the dynamic analysis pipeline
    to extract a dynamic dump signature and corresponding features.
    Then uses the trained model to classify the file.
    """
    # Ensure sandbox is clean before scanning
    full_cleanup_sandbox()
    
    result = process_file(file_path)
    if result is None:
        logging.error("Failed to process file in sandbox.")
        return None
    signature, fname = result
    features = extract_features_from_signature(signature)
    if features is None:
        logging.error("Failed to extract features from signature.")
        return None
    # Reshape for prediction
    features = features.reshape(1, -1)
    prediction = model.predict(features)[0]
    return prediction

def main():
    parser = argparse.ArgumentParser(description="Dynamic Scanner using Sandboxie-based analysis")
    parser.add_argument("file", help="Path to the file to scan")
    args = parser.parse_args()
    file_path = args.file
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    
    model = load_model(MODEL_PATH)
    prediction = scan_file(file_path, model)
    if prediction is None:
        logging.error("Scanning failed.")
        sys.exit(1)
    if prediction == 1:
        logging.info(f"File '{file_path}' is classified as MALICIOUS.")
    else:
        logging.info(f"File '{file_path}' is classified as CLEAN.")

if __name__ == "__main__":
    main()
