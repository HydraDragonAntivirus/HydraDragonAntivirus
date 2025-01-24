import hashlib
import json
import os
import pefile
import logging
import joblib
import shutil
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
import numpy as np
import argparse
from tqdm import tqdm

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pe_extraction.log'),
        logging.StreamHandler()
    ]
)

class PEFeatureExtractor:
    def __init__(self):
        self.features_cache = {}

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        return entropy

    def _calculate_md5(self, file_path: str) -> str:
        """Calculate MD5 hash of file."""
        hasher = hashlib.md5()
        with open(file_path, 'rb') as f:
            hasher.update(f.read())
        return hasher.hexdigest()

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extract comprehensive section data including entropy."""
        raw_data = section.get_data()
        return {
            'name': section.Name.decode(errors='ignore').strip('\x00'),
            'virtual_size': section.Misc_VirtualSize,
            'virtual_address': section.VirtualAddress,
            'raw_size': section.SizeOfRawData,
            'pointer_to_raw_data': section.PointerToRawData,
            'characteristics': section.Characteristics,
            'entropy': self._calculate_entropy(raw_data),
            'raw_data_size': len(raw_data) if raw_data else 0
        }

    def extract_imports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed import information."""
        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_imports = {
                    'dll_name': entry.dll.decode() if entry.dll else None,
                    'imports': [{
                        'name': imp.name.decode() if imp.name else None,
                        'address': imp.address,
                        'ordinal': imp.ordinal
                    } for imp in entry.imports]
                }
                imports.append(dll_imports)
        return imports

    def extract_exports(self, pe) -> List[Dict[str, Any]]:
        """Extract detailed export information."""
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                export_info = {
                    'name': exp.name.decode() if exp.name else None,
                    'address': exp.address,
                    'ordinal': exp.ordinal,
                    'forwarder': exp.forwarder.decode() if exp.forwarder else None
                }
                exports.append(export_info)
        return exports

    def analyze_tls_callbacks(self, pe) -> Dict[str, Any]:
        """Analyze TLS (Thread Local Storage) callbacks and extract relevant details."""
        try:
            tls_callbacks = {}
            # Check if the PE file has a TLS directory
            if hasattr(pe, 'DIRECTORY_ENTRY_TLS'):
                tls = pe.DIRECTORY_ENTRY_TLS.struct
                tls_callbacks = {
                    'start_address_raw_data': tls.StartAddressOfRawData,
                    'end_address_raw_data': tls.EndAddressOfRawData,
                    'address_of_index': tls.AddressOfIndex,
                    'address_of_callbacks': tls.AddressOfCallBacks,
                    'size_of_zero_fill': tls.SizeOfZeroFill,
                    'characteristics': tls.Characteristics,
                    'callbacks': []
                }

                # If there are callbacks, extract their addresses
                if tls.AddressOfCallBacks:
                    callback_array = self._get_callback_addresses(pe, tls.AddressOfCallBacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array

            return tls_callbacks
        except Exception as e:
            logging.error(f"Error analyzing TLS callbacks: {e}")
            return {}

    def _get_callback_addresses(self, pe, address_of_callbacks) -> List[int]:
        """Retrieve callback addresses from the TLS directory."""
        try:
            callback_addresses = []
            # Read callback addresses from the memory-mapped file
            while True:
                callback_address = pe.get_dword_at_rva(address_of_callbacks - pe.OPTIONAL_HEADER.ImageBase)
                if callback_address == 0:
                    break  # End of callback list
                callback_addresses.append(callback_address)
                address_of_callbacks += 4  # Move to the next address (4 bytes for DWORD)

            return callback_addresses
        except Exception as e:
            logging.error(f"Error retrieving TLS callback addresses: {e}")
            return []

    def analyze_dos_stub(self, pe) -> Dict[str, Any]:
        """Analyze DOS stub program."""
        try:
            dos_stub = {
                'exists': False,
                'size': 0,
                'entropy': 0.0,
            }

            if hasattr(pe, 'DOS_HEADER'):
                stub_offset = pe.DOS_HEADER.e_lfanew - 64  # Typical DOS stub starts after DOS header
                if stub_offset > 0:
                    dos_stub_data = pe.__data__[64:pe.DOS_HEADER.e_lfanew]
                    if dos_stub_data:
                        dos_stub['exists'] = True
                        dos_stub['size'] = len(dos_stub_data)
                        dos_stub['entropy'] = self.calculate_entropy(list(dos_stub_data))

            return dos_stub
        except Exception as e:
            logging.error(f"Error analyzing DOS stub: {e}")
            return {}

    def calculate_entropy(self, data: list) -> float:
        """Calculate Shannon entropy of data (provided as a list of integers)."""
        if not data:
            return 0.0

        total_items = len(data)
        value_counts = [data.count(i) for i in range(256)]  # Count occurrences of each byte (0-255)

        entropy = 0.0
        for count in value_counts:
            if count > 0:
                # Calculate probability of each value and its contribution to entropy
                p_x = count / total_items
                entropy -= p_x * np.log2(p_x)

        return entropy

    def extract_numeric_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Extract numeric features of a file using pefile.
        """
        try:
            # Load the PE file
            pe = pefile.PE(file_path)

            # Extract features
            numeric_features = {
                # Optional Header Features
                'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode,
                'BaseOfData': getattr(pe.OPTIONAL_HEADER, 'BaseOfData', 0),
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase,
                'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage,
                'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum,
                'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
                'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit,
                'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
                'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes,
                
                # Section Headers
                'sections': [
                    {
                        'name': section.Name.decode(errors='ignore').strip('\x00'),
                        'virtual_size': section.Misc_VirtualSize,
                        'virtual_address': section.VirtualAddress,
                        'size_of_raw_data': section.SizeOfRawData,
                        'pointer_to_raw_data': section.PointerToRawData,
                        'characteristics': section.Characteristics,
                    }
                    for section in pe.sections
                ],

                # Imported Functions
                'imports': [
                    imp.name.decode(errors='ignore') if imp.name else "Unknown"
                    for entry in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
                    for imp in getattr(entry, 'imports', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else [],

                # Exported Functions
                'exports': [
                    exp.name.decode(errors='ignore') if exp.name else "Unknown"
                    for exp in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [],

                # Resources
                'resources': [
                    {
                        'type_id': resource_type.struct.Id,
                        'resource_id': resource_id.struct.Id,
                        'lang_id': resource_lang.struct.Id,
                        'size': resource_lang.data.struct.Size,
                        'codepage': resource_lang.data.struct.CodePage,
                    }
                    for resource_type in getattr(pe, 'DIRECTORY_ENTRY_RESOURCE', {}).get('entries', [])
                    if hasattr(resource_type, 'directory')
                    for resource_id in getattr(resource_type.directory, 'entries', [])
                    if hasattr(resource_id, 'directory')
                    for resource_lang in getattr(resource_id.directory, 'entries', [])
                    if hasattr(resource_lang, 'data') and resource_lang.data.struct
                ] if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else [],

                # Debug Information
                'debug': [
                    {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    for debug in getattr(pe, 'DIRECTORY_ENTRY_DEBUG', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else [],

                # Relocations
                'relocations': [
                    {
                        'virtual_address': entry.rva,
                        'type': entry.type
                    }
                    for relocation in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', [])
                    for entry in getattr(relocation, 'entries', [])
                ] if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC') else [],
    
                # TLS Callbacks
                'tls_callbacks': self.analyze_tls_callbacks(pe),

                # DOS Stub Analysis
                'dos_stub': self.analyze_dos_stub(pe),
            }

            # Add numeric tag if provided
            if rank is not None:
                numeric_features['numeric_tag'] = rank

            return numeric_features

        except Exception as ex:
            logging.error(f"Error extracting numeric features from {file_path}: {str(ex)}", exc_info=True)
            return None

class DataProcessor:
    def __init__(self, malicious_dir: str = 'datamaliciousorder', benign_dir: str = 'data2'):
        self.malicious_dir = malicious_dir
        self.benign_dir = benign_dir
        self.pe_extractor = PEFeatureExtractor()
        self.problematic_dir = Path('problematic_files')
        self.duplicates_dir = Path('duplicate_files')
        self.output_dir = Path(f"pe_features_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

        # Create necessary directories
        for directory in [self.problematic_dir, self.duplicates_dir, self.output_dir]:
            directory.mkdir(exist_ok=True, parents=True)

    def _process_file(self, file_path: Path, rank: int, is_malicious: bool) -> Optional[Dict[str, Any]]:
        """Process a single PE file."""
        try:
            return self.pe_extractor.extract_numeric_features(str(file_path), rank, is_malicious)
        except Exception as e:
            logging.error(f"Error processing {file_path}: {str(e)}")
            self._move_problematic_file(file_path, is_malicious)
            return None

    def _move_problematic_file(self, file_path: Path, is_malicious: bool):
        """Move problematic files to separate directory."""
        dest_dir = self.problematic_dir / ('malicious' if is_malicious else 'benign')
        dest_dir.mkdir(exist_ok=True)
        shutil.move(str(file_path), str(dest_dir / file_path.name))

    def _move_duplicate_file(self, file_path: Path, is_malicious: bool):
        """Move duplicate files to separate directory."""
        dest_dir = self.duplicates_dir / ('malicious' if is_malicious else 'benign')
        dest_dir.mkdir(exist_ok=True)
        shutil.move(str(file_path), str(dest_dir / file_path.name))

    # Update the process_files method to include a progress bar
    def process_files(self, directory: str, is_malicious: bool = False) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Process all files in directory with duplicate detection."""
        features_list = []
        md5_hashes = set()
        md5_list = []

        files = list(Path(directory).rglob('*.vir' if is_malicious else '*'))

        # Add a progress bar for file processing
        with tqdm(total=len(files), desc=f"Processing {'malicious' if is_malicious else 'benign'} files") as pbar:
            with ThreadPoolExecutor() as executor:
                futures = []
                for rank, file_path in enumerate(files, 1):
                    if file_path.is_file():
                        file_md5 = self.pe_extractor._calculate_md5(str(file_path))
                        if file_md5 in md5_hashes:
                            logging.info(f"Duplicate file detected: {file_path}")
                            self._move_duplicate_file(file_path, is_malicious)
                            pbar.update(1)  # Update progress bar even for duplicates
                            continue

                        md5_hashes.add(file_md5)
                        md5_list.append(file_md5)
                        futures.append(executor.submit(self._process_file, file_path, rank, is_malicious))

                    pbar.update(1)  # Increment progress bar after queuing file processing

                for future in tqdm(futures, desc="Finalizing file processing", leave=False):
                    features = future.result()
                    if features:
                        features_list.append(features)

        return features_list, md5_list

    # Update the process_dataset method to include the progress bar for clarity
    def process_dataset(self):
        """Process entire dataset and save results."""
        logging.info("Processing malicious files...")
        malicious_features, malicious_md5s = self.process_files(self.malicious_dir, is_malicious=True)

        logging.info("Processing benign files...")
        benign_features, benign_md5s = self.process_files(self.benign_dir, is_malicious=False)

        # Save results
        results = {
            'metadata': {
                'timestamp': datetime.now().isoformat(),
                'malicious_count': len(malicious_features),
                'benign_count': len(benign_features),
                'total_files': len(malicious_features) + len(benign_features)
            },
            'malicious_features': malicious_features,
            'benign_features': benign_features,
            'malicious_md5s': malicious_md5s,
            'benign_md5s': benign_md5s
        }

        # Save complete results
        with open(self.output_dir / 'complete_results.json', 'w') as f:
            json.dump(results, f, indent=2)

        # Save separate files for compatibility
        joblib.dump(malicious_features, self.output_dir / 'malicious_numeric.pkl')
        joblib.dump(benign_features, self.output_dir / 'benign_numeric.pkl')

        with open(self.output_dir / 'malicious_file_names.json', 'w') as f:
            json.dump([feat['file_info'] for feat in malicious_features], f, indent=2)

        logging.info(f"Processing complete. Results saved in {self.output_dir}")

def main():
    parser = argparse.ArgumentParser(description='PE File Feature Extractor')
    parser.add_argument('--malicious-dir', default='datamaliciousorder', help='Directory containing malicious PE files')
    parser.add_argument('--benign-dir', default='data2', help='Directory containing benign PE files')
    args = parser.parse_args()

    processor = DataProcessor(args.malicious_dir, args.benign_dir)
    processor.process_dataset()

if __name__ == "__main__":
    main()