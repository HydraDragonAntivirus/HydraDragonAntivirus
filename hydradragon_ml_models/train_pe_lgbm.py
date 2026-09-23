#!/usr/bin/env python3
"""
HydraDragon ML Model Trainer (Python Edition)
Extracts standard Microsoft PE/COFF + x86 Assembly features from binaries,
trains an ultra-fast LightGBM model with class balancing, and exports to ONNX.
"""

import os
import sys
import math
import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import numpy as np
import pefile
import capstone
import lightgbm as lgb
import joblib
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import onnxmltools
from onnxmltools.convert.common.data_types import FloatTensorType

FEATURE_NAMES = [
    "size_of_optional_header", "coff_characteristics", "machine",
    "major_linker_version", "minor_linker_version", "size_of_code",
    "size_of_initialized_data", "size_of_uninitialized_data",
    "address_of_entry_point", "image_base", "section_alignment",
    "file_alignment", "major_operating_system_version",
    "minor_operating_system_version", "major_image_version",
    "minor_image_version", "major_subsystem_version",
    "minor_subsystem_version", "size_of_image", "size_of_headers",
    "checksum", "subsystem", "dll_characteristics",
    "size_of_stack_reserve", "size_of_stack_commit", "size_of_heap_reserve",
    "size_of_heap_commit", "loader_flags", "number_of_rva_and_sizes",
    "export_table_size", "import_table_size", "resource_table_size",
    "exception_table_size", "certificate_table_size", "base_relocation_table_size",
    "debug_table_size", "tls_table_size", "load_config_table_size",
    "bound_import_table_size", "iat_table_size", "delay_import_table_size",
    "clr_runtime_header_size", "imports_count", "exports_count",
    "resources_count", "sections_count", "overlay_exists", "overlay_size",
    "sec_entropy_mean", "sec_entropy_min", "sec_entropy_max",
    "total_instructions", "total_add_instructions", "total_mov_instructions",
    "is_likely_packed", "add_mov_ratio", "instructions_per_kb",
    "num_tls_callbacks", "num_delay_imports", "num_reloc_entries",
    "num_reloc_blocks", "num_bound_imports", "num_debug_entries",
    "cert_size", "has_rich_header"
]

def ln1p(x):
    if x is None or math.isnan(x) or x <= 0:
        return 0.0
    return float(math.log1p(x))

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    length = len(data)
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c > 0:
            p = c / length
            ent -= p * math.log2(p)
    return float(ent)

def extract_pe_features_from_file(filepath: str):
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception:
        return None

    if len(data) < 64 or data[:2] != b"MZ":
        return None

    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories()
    except Exception:
        return None

    try:
        coff = pe.FILE_HEADER
        opt = pe.OPTIONAL_HEADER

        # Basic headers
        size_of_optional_header = ln1p(coff.SizeOfOptionalHeader)
        coff_characteristics = ln1p(coff.Characteristics)
        machine = ln1p(coff.Machine)

        major_linker_version = float(opt.MajorLinkerVersion)
        minor_linker_version = float(opt.MinorLinkerVersion)
        size_of_code = ln1p(opt.SizeOfCode)
        size_of_initialized_data = ln1p(opt.SizeOfInitializedData)
        size_of_uninitialized_data = ln1p(opt.SizeOfUninitializedData)
        address_of_entry_point = ln1p(opt.AddressOfEntryPoint)
        image_base = ln1p(opt.ImageBase)
        section_alignment = ln1p(opt.SectionAlignment)
        file_alignment = ln1p(opt.FileAlignment)
        major_os_version = float(opt.MajorOperatingSystemVersion)
        minor_os_version = float(opt.MinorOperatingSystemVersion)
        major_image_version = float(opt.MajorImageVersion)
        minor_image_version = float(opt.MinorImageVersion)
        major_subsystem_version = float(opt.MajorSubsystemVersion)
        minor_subsystem_version = float(opt.MinorSubsystemVersion)
        size_of_image = ln1p(opt.SizeOfImage)
        size_of_headers = ln1p(opt.SizeOfHeaders)
        checksum = ln1p(opt.CheckSum)
        subsystem = float(opt.Subsystem)
        dll_characteristics = ln1p(opt.DllCharacteristics)
        size_of_stack_reserve = ln1p(opt.SizeOfStackReserve)
        size_of_stack_commit = ln1p(opt.SizeOfStackCommit)
        size_of_heap_reserve = ln1p(opt.SizeOfHeapReserve)
        size_of_heap_commit = ln1p(opt.SizeOfHeapCommit)
        loader_flags = ln1p(opt.LoaderFlags)
        number_of_rva_and_sizes = ln1p(opt.NumberOfRvaAndSizes)

        # Data directories
        dir_sizes = [0.0] * 16
        if hasattr(opt, "DATA_DIRECTORY"):
            for i, d in enumerate(opt.DATA_DIRECTORY):
                if i < 16 and hasattr(d, "Size"):
                    dir_sizes[i] = ln1p(d.Size)

        export_table_size = dir_sizes[0]
        import_table_size = dir_sizes[1]
        resource_table_size = dir_sizes[2]
        exception_table_size = dir_sizes[3]
        certificate_table_size = dir_sizes[4]
        base_relocation_table_size = dir_sizes[5]
        debug_table_size = dir_sizes[6]
        tls_table_size = dir_sizes[9]
        load_config_table_size = dir_sizes[10]
        bound_import_table_size = dir_sizes[11]
        iat_table_size = dir_sizes[12]
        delay_import_table_size = dir_sizes[13]
        clr_runtime_header_size = dir_sizes[14]

        # Imports & Exports count
        imports_count = 0.0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                imports_count += len(entry.imports)
        imports_count = ln1p(imports_count)

        exports_count = 0.0
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            exports_count = float(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
        exports_count = ln1p(exports_count)

        # Resources count
        resources_count = 0.0
        if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            resources_count = float(len(pe.DIRECTORY_ENTRY_RESOURCE.entries))
        resources_count = ln1p(resources_count)

        # Sections & Entropy
        sections = pe.sections
        sections_count = float(len(sections))
        entropies = [s.get_entropy() for s in sections]
        if entropies:
            sec_entropy_mean = float(np.mean(entropies))
            sec_entropy_min = float(np.min(entropies))
            sec_entropy_max = float(np.max(entropies))
        else:
            sec_entropy_mean = sec_entropy_min = sec_entropy_max = 0.0

        # Overlay detection
        overlay_exists = 0.0
        overlay_size = 0.0
        try:
            overlay_offset = pe.get_overlay_data_start_offset()
            if overlay_offset is not None and overlay_offset < len(data):
                overlay_exists = 1.0
                overlay_size = ln1p(len(data) - overlay_offset)
        except Exception:
            pass

        # Rich Header
        has_rich_header = 1.0 if b"Rich" in data[:4096] else 0.0

        # Relocations count
        num_reloc_blocks = 0.0
        num_reloc_entries = 0.0
        if hasattr(pe, "DIRECTORY_ENTRY_BASERELOC"):
            num_reloc_blocks = float(len(pe.DIRECTORY_ENTRY_BASERELOC))
            for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                num_reloc_entries += len(base_reloc.entries)
        num_reloc_blocks = ln1p(num_reloc_blocks)
        num_reloc_entries = ln1p(num_reloc_entries)

        # TLS callbacks
        num_tls_callbacks = 0.0
        if hasattr(pe, "DIRECTORY_ENTRY_TLS") and hasattr(pe.DIRECTORY_ENTRY_TLS.struct, "AddressOfCallBacks"):
            num_tls_callbacks = 1.0

        # Delay imports & bound imports
        num_delay_imports = ln1p(float(len(getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []))))
        num_bound_imports = ln1p(float(len(getattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT", []))))
        num_debug_entries = ln1p(float(len(getattr(pe, "DIRECTORY_ENTRY_DEBUG", []))))
        cert_size = certificate_table_size

        # Disassembly snippet (first code section)
        total_instructions = 0.0
        total_add = 0.0
        total_mov = 0.0
        try:
            mode = capstone.CS_MODE_64 if opt.Magic == 0x20B else capstone.CS_MODE_32
            md = capstone.Cs(capstone.CS_ARCH_X86, mode)
            for section in sections:
                if section.Characteristics & 0x00000020: # IMAGE_SCN_CNT_CODE
                    code_data = section.get_data()[:65536] # inspect first 64KB
                    for insn in md.disasm(code_data, section.VirtualAddress):
                        total_instructions += 1
                        if insn.mnemonic == "add":
                            total_add += 1
                        elif insn.mnemonic == "mov":
                            total_mov += 1
                    break
        except Exception:
            pass

        likely_packed = 1.0 if (total_instructions > 0 and total_add > total_mov) else 0.0
        add_mov_ratio = min(10.0, total_add / total_mov) if total_mov > 0 else 0.0
        raw_size_of_image = float(opt.SizeOfImage)
        instructions_per_kb = min(1000.0, total_instructions / (raw_size_of_image / 1024.0 + 1e-6)) if raw_size_of_image > 0 else 0.0

        vector = [
            size_of_optional_header, coff_characteristics, machine,
            major_linker_version, minor_linker_version, size_of_code,
            size_of_initialized_data, size_of_uninitialized_data,
            address_of_entry_point, image_base, section_alignment,
            file_alignment, major_os_version, minor_os_version,
            major_image_version, minor_image_version, major_subsystem_version,
            minor_subsystem_version, size_of_image, size_of_headers,
            checksum, subsystem, dll_characteristics,
            size_of_stack_reserve, size_of_stack_commit, size_of_heap_reserve,
            size_of_heap_commit, loader_flags, number_of_rva_and_sizes,
            export_table_size, import_table_size, resource_table_size,
            exception_table_size, certificate_table_size, base_relocation_table_size,
            debug_table_size, tls_table_size, load_config_table_size,
            bound_import_table_size, iat_table_size, delay_import_table_size,
            clr_runtime_header_size, imports_count, exports_count,
            resources_count, sections_count, overlay_exists, overlay_size,
            sec_entropy_mean, sec_entropy_min, sec_entropy_max,
            ln1p(total_instructions), ln1p(total_add), ln1p(total_mov),
            likely_packed, add_mov_ratio, instructions_per_kb,
            num_tls_callbacks, num_delay_imports, num_reloc_entries,
            num_reloc_blocks, num_bound_imports, num_debug_entries,
            cert_size, has_rich_header
        ]
        return vector
    except Exception:
        return None

def find_files(dir_path: str, max_files: int = 200000):
    files = []
    for root, _, filenames in os.walk(dir_path):
        for f in filenames:
            files.append(os.path.join(root, f))
            if len(files) >= max_files:
                return files
    return files

def parse_args():
    parser = argparse.ArgumentParser(description="Train LightGBM PE Model and Export to ONNX")
    parser.add_argument("--malicious", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\datamaliciousorder", help="Directory of malicious PEs")
    parser.add_argument("--benign", type=str, default=r"C:\Users\semae\OneDrive\Belgeler\usbdosyalar\data2", help="Directory of benign PEs")
    parser.add_argument("--output-onnx", type=str, default="pe_model.onnx", help="Output ONNX model path")
    parser.add_argument("--max-samples-per-class", type=int, default=100000, help="Max samples to train from each class")
    parser.add_argument("--cache-file", type=str, default=None, help="Legacy single-file cache (joblib)")
    parser.add_argument("--chunk-dir", type=str, default="cache_chunks_pe", help="Directory to store feature chunks")
    parser.add_argument("--chunk-size", type=int, default=5000, help="Number of files per disk chunk to avoid RAM blowup")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Feature extraction threads")
    parser.add_argument("--extract-only", action="store_true", help="Only extract chunks to disk, do not train")
    parser.add_argument("--train-only", action="store_true", help="Only train from existing chunk directory")
    return parser.parse_args()

def collect_features_batch(file_batch, workers):
    features = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(extract_pe_features_from_file, p): p for p in file_batch}
        for future in as_completed(futures):
            res = future.result()
            if res is not None:
                features.append(res)
    return features

def extract_chunks_to_disk(file_list, workers, label_name, label_val, chunk_dir, chunk_size):
    os.makedirs(chunk_dir, exist_ok=True)
    total_files = len(file_list)
    print(f"[*] Extracting {label_name} PEs ({total_files} files) into chunks of {chunk_size} to {chunk_dir}...")
    
    chunk_idx = 0
    total_valid = 0
    
    for i in range(0, total_files, chunk_size):
        chunk_files = file_list[i : i + chunk_size]
        chunk_path = os.path.join(chunk_dir, f"chunk_pe_{label_name.lower()}_{chunk_idx:04d}.joblib")
        
        if os.path.exists(chunk_path):
            print(f"  [>] Chunk {chunk_idx:04d} already exists on disk, skipping.")
            chunk_idx += 1
            continue
            
        feats = collect_features_batch(chunk_files, workers)
        if feats:
            X_chunk = np.array(feats, dtype=np.float32)
            y_chunk = np.full(len(feats), label_val, dtype=np.int32)
            joblib.dump({"X": X_chunk, "y": y_chunk}, chunk_path, compress=3)
            total_valid += len(feats)
            print(f"  [+] Saved {chunk_path}: {len(feats)} valid samples (Processed {min(i + chunk_size, total_files)}/{total_files})")
        else:
            print(f"  [-] Chunk {chunk_idx:04d} had 0 valid PE files.")
            
        del feats
        import gc
        gc.collect()
        chunk_idx += 1
        
    print(f"[+] Total {label_name} PE samples extracted: {total_valid}")
    return total_valid

def load_chunks_balanced(chunk_dir):
    import glob
    chunk_files = glob.glob(os.path.join(chunk_dir, "chunk_pe_*.joblib"))
    if not chunk_files:
        raise RuntimeError(f"No PE chunk files found in {chunk_dir}")
        
    print(f"[*] Found {len(chunk_files)} chunk files in {chunk_dir}. Loading and balancing 50/50...")
    X_mal_list, X_ben_list = [], []
    
    for cf in chunk_files:
        data = joblib.load(cf)
        X_sub = data["X"]
        y_sub = data["y"]
        if y_sub[0] == 1:
            X_mal_list.append(X_sub)
        else:
            X_ben_list.append(X_sub)
            
    if not X_mal_list or not X_ben_list:
        raise RuntimeError(f"Need both Malicious and Benign chunks in {chunk_dir} to train!")
        
    X_mal = np.vstack(X_mal_list)
    X_ben = np.vstack(X_ben_list)
    
    n_mal = len(X_mal)
    n_ben = len(X_ben)
    target_each = min(n_mal, n_ben)
    print(f"[*] Raw counts: {n_mal} Malicious, {n_ben} Benign -> Balancing to {target_each} each (50/50)")
    
    np.random.seed(42)
    idx_mal = np.random.choice(n_mal, target_each, replace=False)
    idx_ben = np.random.choice(n_ben, target_each, replace=False)
    
    X = np.vstack([X_mal[idx_mal], X_ben[idx_ben]])
    y = np.array([1] * target_each + [0] * target_each, dtype=np.int32)
    
    del X_mal, X_ben, X_mal_list, X_ben_list
    import gc
    gc.collect()
    
    print(f"[+] Loaded perfectly balanced dataset: {len(X)} samples ({target_each} Malicious, {target_each} Benign)")
    return X, y

def main():
    args = parse_args()
    print("=" * 65)
    print(" HydraDragon Antivirus - High Precision PE LightGBM Trainer ")
    print(" (Out-of-Core Low RAM Chunked Engine) ")
    print("=" * 65)

    if not args.train_only:
        print(f"[*] Discovering PE files...")
        mal_files = find_files(args.malicious, args.max_samples_per_class) if os.path.exists(args.malicious) else []
        ben_files = find_files(args.benign, args.max_samples_per_class) if os.path.exists(args.benign) else []
        print(f"[+] Discovered {len(mal_files)} malicious PEs and {len(ben_files)} benign PEs.")
        
        extract_chunks_to_disk(mal_files, args.workers, "MALICIOUS", 1, args.chunk_dir, args.chunk_size)
        extract_chunks_to_disk(ben_files, args.workers, "BENIGN", 0, args.chunk_dir, args.chunk_size)

    if args.extract_only:
        print("[+] Feature extraction finished. Exiting as --extract-only was specified.")
        return

    X, y = load_chunks_balanced(args.chunk_dir)

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)}")

    print("[*] Training LightGBM Classifier (Balanced 50/50, zero false-positive tuning)...")
    clf = lgb.LGBMClassifier(
        n_estimators=500,
        learning_rate=0.03,
        num_leaves=127,
        max_depth=10,
        min_child_samples=50,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.0,
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0 if (fp + tn) > 0 else 0.0
    recall = tp / (tp + fn) * 100.0 if (tp + fn) > 0 else 0.0
    print(f"Confusion Matrix: TP={tp}, FN={fn}, TN={tn}, FP={fp}")
    print(f"Malware Recall (Detection Rate): {recall:.2f}%")
    print(f"False Positive Rate (FPR):       {fpr:.2f}%")
    print("=" * 79)

    print(f"[*] Converting LightGBM model to ONNX: {args.output_onnx}...")
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_NAMES)]))]
    onnx_model = onnxmltools.convert_lightgbm(clf, initial_types=initial_type, target_opset=14)
    with open(args.output_onnx, "wb") as f:
        f.write(onnx_model.SerializeToString())
    print(f"[+] ONNX model successfully saved to {args.output_onnx}!")

if __name__ == "__main__":
    main()
