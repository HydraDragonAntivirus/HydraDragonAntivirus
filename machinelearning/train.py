import sklearn
import json
import sys
import joblib
import os
import numpy as np
import pandas as pd
import pefile
from sklearn.ensemble import RandomForestClassifier

sys.modules["sklearn.tree.tree"] = sklearn.tree
sys.modules["sklearn.ensemble.weight_boosting"] = sklearn.ensemble
sys.modules["sklearn.ensemble.forest"] = sklearn.ensemble
sys.modules["sklearn.svm.classes"] = sklearn.svm
sys.modules["sklearn.neighbors.classification"] = sklearn.neighbors
sys.modules['sklearn.externals.joblib'] = joblib

def extract_infos(file_path, rank=None):
    """Extract information about file"""
    file_name = os.path.basename(file_path)
    if rank is not None:
        return {'file_name': file_name, 'numeric_tag': rank}
    else:
        return {'file_name': file_name}

def extract_numeric_features(file_path, rank=None):
    """Extract numeric features of a file using pefile"""
    res = {}
    try:
        pe = pefile.PE(file_path)
        res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
        res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
        res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
        res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
        res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
        res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData if hasattr(pe.OPTIONAL_HEADER, 'BaseOfData') else 0
        res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
        res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
        res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
        res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
        res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
        res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
        res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
        res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
        res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
        res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
        res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
        res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
        res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
        res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
        res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
        res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
        res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
        res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
        res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
        res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes
        if rank is not None:
            res['numeric_tag'] = rank
    except Exception as e:
        print(f"An error occurred while processing {file_path}: {e}")
        
    return res
def load_malicious_files(folder):
    """Load malicious files and extract their information"""
    files_info = []
    numeric_features = []
    rank = 1  # Initialize rank
    
    for root, _, files in os.walk(folder, topdown=True):
        for file in files:
            if file.endswith('.vir'):
                file_path = os.path.join(root, file)
                file_info = extract_infos(file_path, rank=rank)
                numeric_info = extract_numeric_features(file_path, rank=rank)
                if file_info:
                    files_info.append(file_info)
                if numeric_info:
                    numeric_features.append(numeric_info)
                rank += 1  # Increment rank for next file
                
    return files_info, numeric_features
def load_benign_files(folder):
    """Load benign files and extract their information"""
    files_info = []
    numeric_features = []
    for root, _, files in os.walk(folder, topdown=True):
        for index, file in enumerate(files, start=1):
            file_path = os.path.join(root, file)
            if os.path.isfile(file_path):
                file_info = extract_infos(file_path, rank=index)
                numeric_info = extract_numeric_features(file_path, rank=index)
                if file_info:
                    files_info.append(file_info)
                if numeric_info:
                    numeric_features.append(numeric_info)
    return files_info, numeric_features
def main():
    # Load data
    malicious_files_info, malicious_numeric_features = load_malicious_files('datamaliciousorder')
    benign_files_info, benign_numeric_features = load_benign_files('data2')

    # Save malicious file names in JSON
    with open('malicious_file_names.json', 'w') as f:
        json.dump(malicious_files_info, f)

    # Save numeric features for malicious files as pickle file
    with open('malicious_numeric.pkl', 'wb') as f:
        joblib.dump(malicious_numeric_features, f)

    # Save numeric features for benign files as pickle file
    with open('benign_numeric.pkl', 'wb') as f:
        joblib.dump(benign_numeric_features, f)

    print("Files information saved in JSON. Numeric features saved separately for malicious and benign files.")

if __name__ == "__main__":
    main()