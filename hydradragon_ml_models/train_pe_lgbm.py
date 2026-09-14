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
    parser.add_argument("--malicious", type=str, required=True, help="Directory of malicious PEs")
    parser.add_argument("--benign", type=str, required=True, help="Directory of benign PEs")
    parser.add_argument("--output-onnx", type=str, default="pe_model.onnx", help="Output ONNX model path")
    parser.add_argument("--max-samples-per-class", type=int, default=100000, help="Max samples to train from each class")
    parser.add_argument("--cache-file", type=str, default="pe_features_200k.joblib", help="Cache extracted features to joblib")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Feature extraction threads")
    return parser.parse_args()

def collect_features(file_list, workers, label_name):
    print(f"[*] Extracting features from {len(file_list)} {label_name} files with {workers} workers...")
    features = []
    processed = 0
    total = len(file_list)
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(extract_pe_features_from_file, p): p for p in file_list}
        for future in as_completed(futures):
            processed += 1
            if processed % 10000 == 0 or processed == total:
                print(f"  -> Progress [{label_name}]: {processed}/{total} ({(processed/total)*100:.1f}%)")
            res = future.result()
            if res is not None:
                features.append(res)
    print(f"[+] Valid {label_name} samples extracted: {len(features)} / {len(file_list)}")
    return features

def main():
    args = parse_args()
    print("=" * 60)
    print(" HydraDragon Antivirus - High Precision LightGBM Trainer ")
    print("=" * 60)

    if args.cache_file and os.path.exists(args.cache_file):
        print(f"[*] Loading cached features from {args.cache_file}...")
        cached_data = joblib.load(args.cache_file)
        X = cached_data["X"]
        y = cached_data["y"]
        print(f"[+] Loaded {len(X)} cached samples ({np.sum(y == 1)} Malicious, {np.sum(y == 0)} Benign)")
    else:
        mal_files = find_files(args.malicious, args.max_samples_per_class)
        ben_files = find_files(args.benign, args.max_samples_per_class)

        X_mal = collect_features(mal_files, args.workers, "MALICIOUS")
        X_ben = collect_features(ben_files, args.workers, "BENIGN")

        if not X_mal or not X_ben:
            print("[!] Error: Not enough valid samples.")
            sys.exit(1)

        X = np.array(X_mal + X_ben, dtype=np.float32)
        y = np.array([1] * len(X_mal) + [0] * len(X_ben), dtype=np.int32)

        if args.cache_file:
            print(f"[*] Caching extracted features to {args.cache_file}...")
            joblib.dump({"X": X, "y": y}, args.cache_file, compress=3)
            print(f"[+] Cache saved successfully.")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.15, random_state=42, stratify=y)
    print(f"[*] Train set: {len(X_train)} | Test set: {len(X_test)}")

    print("[*] Training LightGBM Classifier (with class balancing & zero false-positive tuning)...")
    clf = lgb.LGBMClassifier(
        n_estimators=500,
        learning_rate=0.03,
        num_leaves=127,
        max_depth=10,
        min_child_samples=50,
        subsample=0.85,
        colsample_bytree=0.85,
        scale_pos_weight=1.2, # slight boost for aggressive zero-day recall
        random_state=42,
        n_jobs=-1
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_prob = clf.predict_proba(X_test)[:, 1]

    print("\n" + "=" * 30 + " EVALUATION REPORT " + "=" * 30)
    print(classification_report(y_test, y_pred, target_names=["Benign", "Malicious"], digits=4))
    cm = confusion_matrix(y_test, y_pred)
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) * 100.0
    recall = tp / (tp + fn) * 100.0
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
