#!/usr/bin/env python
import os
import sys
import argparse
import pickle
import json
import logging
import numpy as np
from dynamictrain import process_file, extract_features_from_signature, full_cleanup_sandbox

# Hardcoded dump directory and model path.
DUMP_DIR = r"C:\sandbox_dumps"
MODEL_PATH = os.path.join(DUMP_DIR, "dynamic_model.pkl")
MALICIOUS_DB_PATH = os.path.join(DUMP_DIR, "malicious_database.json")
MALICIOUS_FEATURES_PATH = os.path.join(DUMP_DIR, "malicious_features.json")

# Hardcoded log file for scanner.
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

def load_json(db_path):
    if not os.path.exists(db_path):
        logging.error(f"File not found: {db_path}")
        return {}
    with open(db_path, "r") as f:
        data = json.load(f)
    return data

def cosine_similarity(v1, v2):
    v1 = np.array(v1)
    v2 = np.array(v2)
    norm1 = np.linalg.norm(v1)
    norm2 = np.linalg.norm(v2)
    if norm1 == 0 or norm2 == 0:
        return 0
    return np.dot(v1, v2) / (norm1 * norm2)

def scan_file(file_path, model, malicious_features):
    """
    Processes the given file using the dynamic analysis pipeline to extract a dynamic dump signature,
    converts the signature into a feature vector, and uses the trained model to classify the file.
    Additionally, if classified as malicious, computes cosine similarity against stored malicious features
    to determine the most similar virus sample.
    """
    full_cleanup_sandbox()
    result = process_file(file_path)
    if result is None:
        logging.error("Failed to process file in sandbox.")
        return None
    signature, fname = result
    feat = extract_features_from_signature(signature)
    if feat is None:
        logging.error("Failed to extract dynamic signature features.")
        return None
    if len(feat) < 64:
        feat = np.pad(feat, (0, 64 - len(feat)), 'constant')
    else:
        feat = feat[:64]
    feat = feat.reshape(1, -1)
    prediction = model.predict(feat)[0]
    if prediction == 0:
        return 0, None  # Clean file.
    else:
        # For a malicious file, compute cosine similarity with each stored malicious feature vector.
        best_sim = -1
        best_label = None
        for label, stored_feat in malicious_features.items():
            sim = cosine_similarity(feat.flatten(), np.array(stored_feat))
            if sim > best_sim:
                best_sim = sim
                best_label = label
        return prediction, (best_label, best_sim)

def main():
    parser = argparse.ArgumentParser(description="Dynamic Scanner using Sandboxie-based Multi-class analysis with Similarity")
    parser.add_argument("file", help="Path to the file to scan")
    args = parser.parse_args()
    file_path = args.file
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        sys.exit(1)
    
    model = load_model(MODEL_PATH)
    malicious_db = load_json(MALICIOUS_DB_PATH)
    malicious_features = load_json(MALICIOUS_FEATURES_PATH)
    
    prediction, sim_info = scan_file(file_path, model, malicious_features)
    if prediction is None:
        logging.error("Scanning failed.")
        sys.exit(1)
    if prediction == 0:
        logging.info(f"File '{file_path}' is classified as CLEAN.")
    else:
        virus_name = malicious_db.get(sim_info[0], "Unknown Virus") if sim_info else "Unknown Virus"
        similarity = sim_info[1] if sim_info else 0
        logging.info(f"File '{file_path}' is classified as MALICIOUS: {virus_name} (Similarity: {similarity:.4f})")

if __name__ == "__main__":
    main()
