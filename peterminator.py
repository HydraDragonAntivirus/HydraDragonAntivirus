import json
import re
import logging
import os
import subprocess
import numpy as np
from typing import Dict, List, Any, Optional
import pefile
import sys
import argparse
from tqdm import tqdm
import nltk
from difflib import SequenceMatcher
import struct
import ipaddress

script_dir = os.getcwd()

# Ensure that necessary NLTK resources are available
nltk.download('punkt')
nltk.download('words')
nltk.download('punkt_tab')

from nltk.corpus import words
from nltk.tokenize import word_tokenize

# Create a set of English words for faster lookup, only including words with 4 or more characters
nltk_words = set(word for word in words.words() if len(word) >= 4)

detectiteasy_dir = os.path.join(script_dir, "detectiteasy")
detectiteasy_console_path = os.path.join(detectiteasy_dir, "diec.exe")

# Define log directories and files
log_directory = os.path.join(script_dir, "log")
if not os.path.exists(log_directory):
    os.makedirs(log_directory)

application_log_file = os.path.join(log_directory, "peterminator.log")

# Configure logging
logging.basicConfig(filename=application_log_file,
                   level=logging.DEBUG,
                   format='%(asctime)s - %(levelname)s - %(message)s')

COMMON_PE_STRINGS = {
    "!This program cannot be run in DOS mode.",
    "Rich",  # Rich header signature
    "PE",    # Standard PE file signature
    ".text", ".data", ".rdata", ".bss", ".idata", ".edata", ".rsrc", ".reloc"  # Common section names
}

def filter_meaningful_words(word_list: List[str]) -> List[str]:
    """
    Filter out non-English, meaningless strings, duplicates, and words shorter than 4 characters.

    Args:
        word_list: List of words to filter

    Returns:
        List of unique, meaningful English words with at least 4 characters
    """
    # Convert to lowercase for comparison
    word_list = [word.lower() for word in word_list]

    # Remove duplicates and apply filters
    filtered_words = []
    seen_words = set()

    for word in word_list:
        if (
                word not in seen_words and
                word.isalpha() and
                len(word) >= 4 and
                word in nltk_words
        ):
            filtered_words.append(word)
            seen_words.add(word)

    return filtered_words

def calculate_string_similarity(str1: str, str2: str) -> float:
    """Calculate similarity ratio between two strings."""
    return SequenceMatcher(None, str1.lower(), str2.lower()).ratio()

class PEAnalyzer:
    def __init__(self):
        logging.info("PEAnalyzer initialized.")
        self.features_cache = {}

    def _bytes_to_hex(self, data):
        """Convert bytes to hexadecimal string."""
        if isinstance(data, bytes):
            return data.hex()
        return data

    def _serialize_data(self, obj):
        """Recursively serialize data structures containing bytes."""
        if isinstance(obj, dict):
            return {key: self._serialize_data(value) for key, value in obj.items()}
        elif isinstance(obj, list):
            return [self._serialize_data(item) for item in obj]
        elif isinstance(obj, bytes):
            return self._bytes_to_hex(obj)
        elif isinstance(obj, set):
            return list(obj)  # Convert sets to lists for JSON serialization
        return obj

    def _calculate_entropy(self, data: list) -> float:
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

    def extract_features(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract comprehensive PE file features."""
        if file_path in self.features_cache:
            return self.features_cache[file_path]

        try:
            pe = pefile.PE(file_path)

            features = {
                'file_info': {
                    'path': file_path,
                    'name': os.path.basename(file_path),
                    'size': os.path.getsize(file_path),
                },
                'headers': {
                    'optional_header': {
                        'major_linker_version': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                        'minor_linker_version': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                        'size_of_code': pe.OPTIONAL_HEADER.SizeOfCode,
                        'size_of_initialized_data': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                        'size_of_uninitialized_data': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                        'address_of_entry_point': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                        'base_of_code': pe.OPTIONAL_HEADER.BaseOfCode,
                        'image_base': pe.OPTIONAL_HEADER.ImageBase,
                        'section_alignment': pe.OPTIONAL_HEADER.SectionAlignment,
                        'file_alignment': pe.OPTIONAL_HEADER.FileAlignment,
                        'major_os_version': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                        'minor_os_version': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                        'subsystem': pe.OPTIONAL_HEADER.Subsystem,
                        'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                    },
                    'file_header': {
                        'machine': pe.FILE_HEADER.Machine,
                        'number_of_sections': pe.FILE_HEADER.NumberOfSections,
                        'time_date_stamp': pe.FILE_HEADER.TimeDateStamp,
                        'characteristics': pe.FILE_HEADER.Characteristics,
                    }
                },
                'sections': {
                    section.Name.decode(errors='ignore').strip('\x00'): {
                        'virtual_size': section.Misc_VirtualSize,
                        'raw_size': section.SizeOfRawData,
                        # Convert section data to a list of integers and calculate entropy
                        'entropy': self._calculate_entropy(list(section.get_data())),
                    } for section in pe.sections
                }
            }

            self.features_cache[file_path] = features
            return features
        except Exception as e:
            logging.error(f"Error extracting features from {file_path}: {e}")
            return None

    def _analyze_with_die(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a file using Detect It Easy (DIE) with JSON output."""
        try:
            if not os.path.exists(detectiteasy_console_path):
                raise FileNotFoundError(f"DIE executable not found at {detectiteasy_console_path}")

            result = subprocess.run(
                [detectiteasy_console_path, file_path, '--json'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                logging.error(f"DIE analysis failed: {result.stderr.strip()}")
                return None

            try:
                die_output = json.loads(result.stdout)
            except json.JSONDecodeError as e:
                logging.error(f"Error parsing DIE JSON output: {e}")
                return None

            return die_output

        except Exception as e:
            logging.error(f"Error during DIE analysis for {file_path}: {e}")
            return None

    def extract_enhanced_features(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract comprehensive PE file features with additional analysis."""
        try:
            pe = pefile.PE(file_path)
            base_features = self.extract_features(file_path)

            if not base_features:
                return None

            # Add rich header analysis
            rich_header = self._analyze_rich_header(pe)

            # Add certificate analysis
            certificates = self._analyze_certificates(pe)

            # Add delay import analysis
            delay_imports = self._analyze_delay_imports(pe)

            # Add TLS callback analysis
            tls_callbacks = self._analyze_tls_callbacks(pe)

            # Add load config analysis
            load_config = self._analyze_load_config(pe)

            # Add relocation analysis
            relocations = self._analyze_relocations(pe)

            # Add bound import analysis
            bound_imports = self._analyze_bound_imports(pe)

            # Add section characteristics analysis
            section_characteristics = self._analyze_section_characteristics(pe)

            # Add header analysis
            extended_header_info = self._analyze_extended_headers(pe)

            # Add resource analysis
            resource_details = self._analyze_resources(pe)

            # Add overlay analysis
            overlay_info = self._analyze_overlay(pe, file_path)

            # DOS Stub analysis
            dos_stub = self._analyze_dos_stub(pe)

            # Add anomaly detection
            anomalies = self._detect_anomalies(pe)

            # Add packer detection
            packer_info = self._detect_packers(pe)

            # Add string detection
            string_patterns = self.analyze_file(file_path)

            # Add imports/exports patterns
            import_patterns = self._analyze_import_patterns(base_features.get('imports', []))
            export_patterns = self._analyze_export_patterns(base_features.get('exports', []))

            enhanced_features = {
                **base_features,
                'enhanced_analysis': {
                    'rich_header': rich_header,
                    'certificates': certificates,
                    'delay_imports': delay_imports,
                    'tls_callbacks': tls_callbacks,
                    'load_config': load_config,
                    'relocations': relocations,
                    'bound_imports': bound_imports,
                    'section_characteristics': section_characteristics,
                    'extended_headers': extended_header_info,
                    'resource_details': resource_details,
                    'overlay': overlay_info,
                    'dos_stub': dos_stub,
                    'anomalies': anomalies,
                    'packer_detection': packer_info,
                    'patterns': {
                        'strings': string_patterns,
                        'imports': import_patterns,
                        'exports': export_patterns
                    }
                }
            }

            return enhanced_features

        except Exception as e:
            logging.error(f"Error in enhanced feature extraction for {file_path}: {e}")
            return None

    def _analyze_certificates(self, pe) -> Dict[str, Any]:
        """Analyze security certificates."""
        try:
            cert_info = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
                cert_info['virtual_address'] = pe.DIRECTORY_ENTRY_SECURITY.VirtualAddress
                cert_info['size'] = pe.DIRECTORY_ENTRY_SECURITY.Size
                
                # Extract certificate attributes if available
                if hasattr(pe, 'VS_FIXEDFILEINFO'):
                    cert_info['fixed_file_info'] = {
                        'signature': pe.VS_FIXEDFILEINFO.Signature,
                        'struct_version': pe.VS_FIXEDFILEINFO.StrucVersion,
                        'file_version': f"{pe.VS_FIXEDFILEINFO.FileVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.FileVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.FileVersionLS & 0xFFFF}",
                        'product_version': f"{pe.VS_FIXEDFILEINFO.ProductVersionMS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionMS & 0xFFFF}.{pe.VS_FIXEDFILEINFO.ProductVersionLS >> 16}.{pe.VS_FIXEDFILEINFO.ProductVersionLS & 0xFFFF}",
                        'file_flags': pe.VS_FIXEDFILEINFO.FileFlags,
                        'file_os': pe.VS_FIXEDFILEINFO.FileOS,
                        'file_type': pe.VS_FIXEDFILEINFO.FileType,
                        'file_subtype': pe.VS_FIXEDFILEINFO.FileSubtype,
                    }
            
            return cert_info
        except Exception as e:
            logging.error(f"Error analyzing certificates: {e}")
            return {}

    def _analyze_delay_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze delay-load imports with error handling for missing attributes."""
        try:
            delay_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
                    imports = []
                    for imp in entry.imports:
                        import_info = {
                            'name': imp.name.decode() if imp.name else None,
                            'address': imp.address,
                            'ordinal': imp.ordinal,
                        }
                        imports.append(import_info)

                    delay_import = {
                        'dll': entry.dll.decode() if entry.dll else None,
                        'attributes': getattr(entry.struct, 'Attributes', None),  # Use getattr for safe access
                        'name': getattr(entry.struct, 'Name', None),
                        'handle': getattr(entry.struct, 'Handle', None),
                        'iat': getattr(entry.struct, 'IAT', None),
                        'bound_iat': getattr(entry.struct, 'BoundIAT', None),
                        'unload_iat': getattr(entry.struct, 'UnloadIAT', None),
                        'timestamp': getattr(entry.struct, 'TimeDateStamp', None),
                        'imports': imports
                    }
                    delay_imports.append(delay_import)

            return delay_imports
        except Exception as e:
            logging.error(f"Error analyzing delay imports: {e}")
            return []

    def _analyze_tls_callbacks(self, pe) -> Dict[str, Any]:
        """Analyze TLS (Thread Local Storage) callbacks."""
        try:
            tls_callbacks = {}
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

                # Extract callback addresses manually
                address_of_callbacks = tls.AddressOfCallBacks
                if address_of_callbacks:
                    callback_array = self._get_callback_addresses(pe, address_of_callbacks)
                    if callback_array:
                        tls_callbacks['callbacks'] = callback_array

            return tls_callbacks
        except Exception as e:
            logging.error(f"Error analyzing TLS callbacks: {e}")
            return {}

    def _get_callback_addresses(self, pe, address_of_callbacks):
        """Extract callback addresses from the TLS structure."""
        callback_addresses = []
        try:
            # Ensure the address_of_callbacks is valid and within bounds
            if address_of_callbacks is None or address_of_callbacks == 0:
                logging.warning("Invalid address_of_callbacks: None or zero.")
                return callback_addresses

            # Check if the address_of_callbacks is within a valid section
            section = self._get_section_for_rva(pe, address_of_callbacks)
            if section is None:
                return callback_addresses

            # Read callback data from the section
            callback_data = pe.get_data(address_of_callbacks, 8)  # Read 8 bytes (pointer size)
            while callback_data:
                callback_address = struct.unpack('<Q', callback_data[:8])[0]  # Unpack address
                if callback_address:
                    callback_addresses.append(callback_address)
                callback_data = callback_data[8:]  # Move to the next callback address
        except Exception as e:
            logging.error(f"Error extracting callback addresses: {e}")
        return callback_addresses

    def _get_section_for_rva(self, pe, rva):
        """Check if the RVA is within any section."""
        for section in pe.sections:
            if section.contains(rva):
                return section
        return None

    def _analyze_load_config(self, pe) -> Dict[str, Any]:
        """Analyze load configuration."""
        try:
            load_config = {}
            if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG'):
                config = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct
                load_config = {
                    'size': config.Size,
                    'timestamp': config.TimeDateStamp,
                    'major_version': config.MajorVersion,
                    'minor_version': config.MinorVersion,
                    'global_flags_clear': config.GlobalFlagsClear,
                    'global_flags_set': config.GlobalFlagsSet,
                    'critical_section_default_timeout': config.CriticalSectionDefaultTimeout,
                    'decommit_free_block_threshold': config.DeCommitFreeBlockThreshold,
                    'decommit_total_free_threshold': config.DeCommitTotalFreeThreshold,
                    'security_cookie': config.SecurityCookie,
                    'se_handler_table': config.SEHandlerTable,
                    'se_handler_count': config.SEHandlerCount
                }
                
            return load_config
        except Exception as e:
            logging.error(f"Error analyzing load config: {e}")
            return {}

    def _analyze_relocations(self, pe) -> List[Dict[str, Any]]:
        """Analyze base relocations with summarized entries."""
        try:
            relocations = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BASERELOC'):
                for base_reloc in pe.DIRECTORY_ENTRY_BASERELOC:
                    # Summarize relocation entries
                    entry_types = {}
                    offsets = []

                    for entry in base_reloc.entries:
                        entry_types[entry.type] = entry_types.get(entry.type, 0) + 1
                        offsets.append(entry.rva - base_reloc.struct.VirtualAddress)

                    reloc_info = {
                        'virtual_address': base_reloc.struct.VirtualAddress,
                        'size_of_block': base_reloc.struct.SizeOfBlock,
                        'summary': {
                            'total_entries': len(base_reloc.entries),
                            'types': entry_types,  # Counts of each relocation type
                            'offset_range': (min(offsets), max(offsets)) if offsets else None
                        }
                    }

                    relocations.append(reloc_info)

            return relocations
        except Exception as e:
            logging.error(f"Error analyzing relocations: {e}")
            return []

    def _analyze_bound_imports(self, pe) -> List[Dict[str, Any]]:
        """Analyze bound imports with robust error handling."""
        try:
            bound_imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_BOUND_IMPORT'):
                for bound_imp in pe.DIRECTORY_ENTRY_BOUND_IMPORT:
                    bound_import = {
                        'name': bound_imp.name.decode() if bound_imp.name else None,
                        'timestamp': bound_imp.struct.TimeDateStamp,
                        'references': []
                    }

                    # Check if `references` exists
                    if hasattr(bound_imp, 'references') and bound_imp.references:
                        for ref in bound_imp.references:
                            reference = {
                                'name': ref.name.decode() if ref.name else None,
                                'timestamp': getattr(ref.struct, 'TimeDateStamp', None)
                            }
                            bound_import['references'].append(reference)
                    else:
                        logging.warning(f"Bound import {bound_import['name']} has no references.")

                    bound_imports.append(bound_import)

            return bound_imports
        except Exception as e:
            logging.error(f"Error analyzing bound imports: {e}")
            return []

    def _analyze_section_characteristics(self, pe) -> Dict[str, Dict[str, Any]]:
        """Analyze detailed section characteristics."""
        try:
            characteristics = {}
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                flags = section.Characteristics
                
                # Decode section characteristics flags
                section_flags = {
                    'CODE': bool(flags & 0x20),
                    'INITIALIZED_DATA': bool(flags & 0x40),
                    'UNINITIALIZED_DATA': bool(flags & 0x80),
                    'MEM_DISCARDABLE': bool(flags & 0x2000000),
                    'MEM_NOT_CACHED': bool(flags & 0x4000000),
                    'MEM_NOT_PAGED': bool(flags & 0x8000000),
                    'MEM_SHARED': bool(flags & 0x10000000),
                    'MEM_EXECUTE': bool(flags & 0x20000000),
                    'MEM_READ': bool(flags & 0x40000000),
                    'MEM_WRITE': bool(flags & 0x80000000)
                }
                
                characteristics[section_name] = {
                    'flags': section_flags,
                    'entropy': self._calculate_entropy(list(section.get_data())),
                    'size_ratio': section.SizeOfRawData / pe.OPTIONAL_HEADER.SizeOfImage if pe.OPTIONAL_HEADER.SizeOfImage else 0,
                    'pointer_to_raw_data': section.PointerToRawData,
                    'pointer_to_relocations': section.PointerToRelocations,
                    'pointer_to_line_numbers': section.PointerToLinenumbers,
                    'number_of_relocations': section.NumberOfRelocations,
                    'number_of_line_numbers': section.NumberOfLinenumbers,
                }
            
            return characteristics
        except Exception as e:
            logging.error(f"Error analyzing section characteristics: {e}")
            return {}

    def _analyze_extended_headers(self, pe) -> Dict[str, Any]:
        """Analyze extended header information."""
        try:
            headers = {
                'dos_header': {
                    'e_magic': pe.DOS_HEADER.e_magic,
                    'e_cblp': pe.DOS_HEADER.e_cblp,
                    'e_cp': pe.DOS_HEADER.e_cp,
                    'e_crlc': pe.DOS_HEADER.e_crlc,
                    'e_cparhdr': pe.DOS_HEADER.e_cparhdr,
                    'e_minalloc': pe.DOS_HEADER.e_minalloc,
                    'e_maxalloc': pe.DOS_HEADER.e_maxalloc,
                    'e_ss': pe.DOS_HEADER.e_ss,
                    'e_sp': pe.DOS_HEADER.e_sp,
                    'e_csum': pe.DOS_HEADER.e_csum,
                    'e_ip': pe.DOS_HEADER.e_ip,
                    'e_cs': pe.DOS_HEADER.e_cs,
                    'e_lfarlc': pe.DOS_HEADER.e_lfarlc,
                    'e_ovno': pe.DOS_HEADER.e_ovno,
                    'e_oemid': pe.DOS_HEADER.e_oemid,
                    'e_oeminfo': pe.DOS_HEADER.e_oeminfo
                },
                'nt_headers': {}
            }

            # Ensure NT_HEADERS exists and contains FileHeader
            if hasattr(pe, 'NT_HEADERS') and pe.NT_HEADERS is not None:
                nt_headers = pe.NT_HEADERS
                if hasattr(nt_headers, 'FileHeader'):
                    headers['nt_headers'] = {
                        'signature': nt_headers.Signature,
                        'machine': nt_headers.FileHeader.Machine,
                        'number_of_sections': nt_headers.FileHeader.NumberOfSections,
                        'time_date_stamp': nt_headers.FileHeader.TimeDateStamp,
                        'characteristics': nt_headers.FileHeader.Characteristics
                    }

            return headers
        except Exception as e:
            logging.error(f"Error analyzing extended headers: {e}")
            return {}

    def _analyze_rich_header(self, pe) -> Dict[str, Any]:
        """Analyze Rich header details."""
        try:
            rich_header = {}
            if hasattr(pe, 'RICH_HEADER') and pe.RICH_HEADER is not None:
                rich_header['checksum'] = getattr(pe.RICH_HEADER, 'checksum', None)
                rich_header['values'] = self._serialize_data(pe.RICH_HEADER.values)
                rich_header['clear_data'] = self._serialize_data(pe.RICH_HEADER.clear_data)
                rich_header['key'] = self._serialize_data(pe.RICH_HEADER.key)
                rich_header['raw_data'] = self._serialize_data(pe.RICH_HEADER.raw_data)

                # Decode CompID and build number information
                compid_info = []
                for i in range(0, len(pe.RICH_HEADER.values), 2):
                    if i + 1 < len(pe.RICH_HEADER.values):
                        comp_id = pe.RICH_HEADER.values[i] >> 16
                        build_number = pe.RICH_HEADER.values[i] & 0xFFFF
                        count = pe.RICH_HEADER.values[i + 1]
                        compid_info.append({
                            'comp_id': comp_id,
                            'build_number': build_number,
                            'count': count
                        })
                rich_header['comp_id_info'] = compid_info

            return rich_header
        except Exception as e:
            logging.error(f"Error analyzing Rich header: {e}")
            return {}

    def _analyze_resources(self, pe) -> Dict[str, Any]:
        """Detailed analysis of resources."""
        try:
            resources = {
                'entries': [],
                'languages': set(),
                'types': set()
            }
            
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    type_id = resource_type.id
                    if resource_type.id is not None:
                        # Map common resource types
                        type_mappings = {
                            1: 'RT_CURSOR',
                            2: 'RT_BITMAP',
                            3: 'RT_ICON',
                            4: 'RT_MENU',
                            5: 'RT_DIALOG',
                            6: 'RT_STRING',
                            7: 'RT_FONTDIR',
                            8: 'RT_FONT',
                            9: 'RT_ACCELERATOR',
                            10: 'RT_RCDATA',
                            11: 'RT_MESSAGETABLE',
                            12: 'RT_GROUP_CURSOR',
                            14: 'RT_GROUP_ICON',
                            16: 'RT_VERSION',
                            17: 'RT_DLGINCLUDE',
                            19: 'RT_PLUGPLAY',
                            20: 'RT_VXD',
                            21: 'RT_ANICURSOR',
                            22: 'RT_ANIICON',
                            23: 'RT_HTML',
                            24: 'RT_MANIFEST'
                        }
                        type_name = type_mappings.get(type_id, f'UNKNOWN_{type_id}')
                        resources['types'].add(type_name)
                        
                        for resource_id in resource_type.directory.entries:
                            for resource_lang in resource_id.directory.entries:
                                lang_id = resource_lang.data.lang
                                resources['languages'].add(lang_id)
                                
                                resource_data = {
                                    'type': type_name,
                                    'id': resource_id.id,
                                    'language': lang_id,
                                    'sublanguage': resource_lang.data.sublang,
                                    'size': resource_lang.data.struct.Size,
                                    'code_page': resource_lang.data.struct.CodePage,
                                    'offset': resource_lang.data.struct.OffsetToData,
                                }
                                resources['entries'].append(resource_data)
            
            # Convert sets to lists for JSON serialization
            resources['languages'] = list(resources['languages'])
            resources['types'] = list(resources['types'])
            return resources
        except Exception as e:
            logging.error(f"Error analyzing resources: {e}")
            return {}

    def _analyze_overlay(self, pe, file_path: str) -> Dict[str, Any]:
        """Analyze file overlay (data appended after the PE structure)."""
        try:
            overlay_info = {
                'exists': False,
                'offset': 0,
                'size': 0,
                'entropy': 0.0
            }
            
            # Calculate the end of the PE structure
            last_section = max(pe.sections, key=lambda s: s.PointerToRawData + s.SizeOfRawData)
            end_of_pe = last_section.PointerToRawData + last_section.SizeOfRawData
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Check for overlay
            if file_size > end_of_pe:
                with open(file_path, 'rb') as f:
                    f.seek(end_of_pe)
                    overlay_data = f.read()
                    
                    overlay_info['exists'] = True
                    overlay_info['offset'] = end_of_pe
                    overlay_info['size'] = len(overlay_data)
                    overlay_info['entropy'] = self._calculate_entropy(list(overlay_data))

            return overlay_info
        except Exception as e:
            logging.error(f"Error analyzing overlay: {e}")
            return {}

    def _analyze_dos_stub(self, pe) -> Dict[str, Any]:
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
                        dos_stub['entropy'] = self._calculate_entropy(list(dos_stub_data))

            return dos_stub
        except Exception as e:
            logging.error(f"Error analyzing DOS stub: {e}")
            return {}

    def _detect_anomalies(self, pe) -> List[Dict[str, Any]]:
        """Detect various PE file anomalies."""
        try:
            anomalies = []
            
            # Check section alignment
            if pe.OPTIONAL_HEADER.SectionAlignment < pe.OPTIONAL_HEADER.FileAlignment:
                anomalies.append({
                    'type': 'alignment',
                    'description': 'Section alignment is smaller than file alignment',
                    'severity': 'high'
                })
            
            # Check for suspicious section names
            suspicious_sections = ['.text', '.data', '.rdata', '.idata', '.edata', '.pdata', '.rsrc', '.reloc']
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                if section_name not in suspicious_sections:
                    anomalies.append({
                        'type': 'section_name',
                        'description': f'Unusual section name: {section_name}',
                        'severity': 'medium'
                    })
            
            # Check for suspicious characteristics
            for section in pe.sections:
                if section.Characteristics & 0xE0000000:  # Check if section is both writable and executable
                    anomalies.append({
                        'type': 'section_permissions',
                        'description': f'Section {section.Name.decode(errors="ignore").strip()} has suspicious permissions',
                        'severity': 'high'
                    })
            
            # Check for suspicious entry point
            for section in pe.sections:
                if (pe.OPTIONAL_HEADER.AddressOfEntryPoint >= section.VirtualAddress and
                    pe.OPTIONAL_HEADER.AddressOfEntryPoint < (section.VirtualAddress + section.Misc_VirtualSize)):
                    if section.Name.decode(errors='ignore').strip('\x00') != '.text':
                        anomalies.append({
                            'type': 'entry_point',
                            'description': f'Entry point in unusual section: {section.Name.decode(errors="ignore").strip()}',
                            'severity': 'high'
                        })
            
            return anomalies
        except Exception as e:
            logging.error(f"Error detecting anomalies: {e}")
            return []

    def _detect_packers(self, pe) -> Dict[str, Any]:
        """Detect potential packer signatures."""
        try:
            packer_info = {
                'detected': False,
                'probable_packers': [],
                'section_entropy': {},
                'indicators': []
            }

            # Common packer section names
            packer_sections = {
                'UPX': ['.UPX', 'UPX'],
                'ASPack': ['.aspack', 'ASPack'],
                'PECompact': ['.PECOMPACT'],
                'FSG': ['FSG'],
                'MPRESS': ['.MPRESS1', '.MPRESS2'],
                'Themida': ['Themida'],
                'VMProtect': ['.vmp'],
                'Enigma': ['.enigma']
            }

            # Check section names
            for section in pe.sections:
                section_name = section.Name.decode(errors='ignore').strip('\x00')
                section_data = section.get_data()

                # Convert section data to a list of integers and calculate entropy
                section_entropy = self._calculate_entropy(list(section_data))
                packer_info['section_entropy'][section_name] = section_entropy

                # Check against known packer section names
                for packer, patterns in packer_sections.items():
                    if any(pattern in section_name for pattern in patterns):
                        packer_info['detected'] = True
                        if packer not in packer_info['probable_packers']:
                            packer_info['probable_packers'].append(packer)

                # High entropy check
                if section_entropy > 7.0:
                    packer_info['indicators'].append({
                        'type': 'high_entropy',
                        'section': section_name,
                        'entropy': section_entropy
                    })

            # Check for other packing indicators
            if len(pe.sections) < 3:  # Unusually few sections
                packer_info['indicators'].append({
                    'type': 'few_sections',
                    'count': len(pe.sections)
                })

            # Check for imports if they exist
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and pe.DIRECTORY_ENTRY_IMPORT is not None:
                if len(pe.DIRECTORY_ENTRY_IMPORT) < 3:
                    packer_info['indicators'].append({
                        'type': 'few_imports',
                        'count': len(pe.DIRECTORY_ENTRY_IMPORT)
                    })

            return packer_info
        except Exception as e:
            logging.error(f"Error detecting packers: {e}")
            return {}

    def clean_text(self, input_text: str) -> str:
        """
        Remove non-printable ASCII control characters from the input text.
        
        Args:
            input_text: The string to clean.
        Returns:
            Cleaned text with control characters removed.
        """
        return re.sub(r'[\x00-\x1F\x7F]+', '', input_text)

    def process_file(self, file_path: str) -> Optional[List[str]]:
        """
        Process a file and return cleaned lines.
        
        Args:
            file_path: Path to the file to process
        Returns:
            List of cleaned lines or None if processing fails
        """
        if not os.path.isfile(file_path):
            logging.warning(f"Path {file_path} is not a valid file.")
            return None

        try:
            # Read the full content of the file, handling invalid UTF-8 gracefully
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
                if lines:
                    # Clean the last lines
                    return [self.clean_text(line.strip()) for line in lines]
                else:
                    logging.info(f"File {file_path} is empty.")
                    return None
        except Exception as ex:
            logging.error(f"Error reading file {file_path}: {ex}")
            return None

    def _analyze_string_patterns(self, content: str) -> Dict[str, List[Dict[str, str]]]:
        """
        Analyzes content for various patterns including URLs, emails, IPs, paths,
        commands, registry keys, and API calls.
        
        Args:
            content: String content to analyze
        Returns:
            Dictionary containing discovered patterns with their values
        """
        try:
            patterns = {
                'urls': [],
                'emails': [],
                'ips': [],
                'paths': [],
                'registry_keys': [],
                'potential_api_calls': [],
                'discord_webhooks': []
            }

            # Enhanced URL pattern to catch more variants
            url_pattern = re.compile(
                r'(?:https?:\/\/(?:www\.)?[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?|'
                r'(?:www\.)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}(?:\/[^\s]*)?)'
            )

            # Discord webhook pattern
            discord_pattern = re.compile(
                r'(?:https?:\/\/)?(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[\w-]+'
            )

            # Other patterns
            email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
            ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            path_pattern = re.compile(r'(?:[a-zA-Z]:\\[^\s<>"|?*]+|/[^\s<>"|?*]+)')
            registry_pattern = re.compile(r'HKEY_[^\s\\]+\\[^\s]+')
            api_pattern = re.compile(
                r'\b(?:Create|Get|Set|Open|Close|Read|Write|Send|Recv|Load|Free|Alloc|Connect)[A-Z]\w+\b'
            )

            def is_local_ip(ip):
                try:
                    ip_obj = ipaddress.ip_address(ip)
                    return ip_obj.is_private
                except ValueError:
                    return False

            # Helper function to add unique findings
            def add_unique_finding(category: str, match: re.Match):
                value = match.group()
                start_pos = match.start()

                # Skip local IPs for IP category
                if category == 'ips' and is_local_ip(value):
                    return

                # Check if value already exists in the category
                if not any(item['value'] == value for item in patterns[category]):
                    patterns[category].append({
                        'value': value,
                        'offset': start_pos
                    })

            # Process all matches
            for match in url_pattern.finditer(content):
                add_unique_finding('urls', match)

            for match in discord_pattern.finditer(content):
                add_unique_finding('discord_webhooks', match)

            for match in email_pattern.finditer(content):
                add_unique_finding('emails', match)

            for match in ip_pattern.finditer(content):
                add_unique_finding('ips', match)

            for match in path_pattern.finditer(content):
                add_unique_finding('paths', match)

            for match in registry_pattern.finditer(content):
                add_unique_finding('registry_keys', match)

            for match in api_pattern.finditer(content):
                add_unique_finding('potential_api_calls', match)

            return patterns

        except Exception as e:
            logging.error(f"Error analyzing patterns: {e}")
            return {}

    def analyze_file(self, file_path: str) -> Optional[Dict[str, List[Dict[str, str]]]]:
        """
        Process and analyze a file for patterns.
        
        Args:
            file_path: Path to the file to analyze
        Returns:
            Dictionary of patterns found or None if processing fails
        """
        cleaned_lines = self.process_file(file_path)
        if cleaned_lines:
            # Join all lines for pattern analysis
            content = '\n'.join(cleaned_lines)
            return self._analyze_string_patterns(content)
        return None

    def _analyze_import_patterns(self, imports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in imports."""
        try:
            patterns = {
                'categories': {
                    'network': [],
                    'crypto': [],
                    'filesystem': [],
                    'gui': [],
                    'process': [],
                    'registry': [],
                    'system': []
                },
                'statistics': {
                    'total_dlls': 0,
                    'total_imports': 0,
                    'dlls_by_count': {},
                    'most_common_imports': []
                }
            }
            
            # Category keywords
            categories = {
                'network': ['ws2_32', 'wininet', 'socket', 'connect', 'internet', 'url', 'ftp', 'http'],
                'crypto': ['crypt', 'ssl', 'tls', 'cipher', 'decrypt', 'encrypt'],
                'filesystem': ['file', 'directory', 'folder', 'path', 'drive'],
                'gui': ['user32', 'gdi32', 'window', 'dialog', 'menu', 'button'],
                'process': ['process', 'thread', 'job', 'token', 'handle'],
                'registry': ['reg', 'registry', 'hkey'],
                'system': ['system32', 'kernel32', 'ntdll', 'advapi32']
            }
            
            all_imports = []
            for dll in imports:

                dll_name = dll.get('dll_name', '').lower()
                patterns['statistics']['total_dlls'] += 1
                dll_imports = dll.get('imports', [])
                patterns['statistics']['total_imports'] += len(dll_imports)

                # Count DLL occurrences
                if dll_name not in patterns['statistics']['dlls_by_count']:
                    patterns['statistics']['dlls_by_count'][dll_name] = 0
                patterns['statistics']['dlls_by_count'][dll_name] += 1

                for imp in dll_imports:
                    imp_name = imp.get('name', '').lower()

                    # Match imports to categories
                    for category, keywords in categories.items():
                        if any(keyword in imp_name for keyword in keywords):
                            patterns['categories'][category].append({
                                'dll': dll_name,
                                'import': imp_name
                            })

            # Identify most common imports
            sorted_imports = sorted(patterns['statistics']['dlls_by_count'].items(), key=lambda x: x[1], reverse=True)
            patterns['statistics']['most_common_imports'] = sorted_imports[:5]

            return patterns
        except Exception as e:
            logging.error(f"Error analyzing import patterns: {e}")
            return {}

    def _analyze_export_patterns(self, exports: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze patterns in exports."""
        try:
            patterns = {
                'common_exports': [],
                'total_exports': len(exports)
            }

            # Common export function names (example set, expand as needed)
            common_exports = ['DllMain', 'DllRegisterServer', 'DllUnregisterServer', 'DllGetClassObject']

            for exp in exports:
                exp_name = exp.get('name', '').lower()
                if exp_name in common_exports:
                    patterns['common_exports'].append(exp_name)

            return patterns
        except Exception as e:
            logging.error(f"Error analyzing export patterns: {e}")
            return {}

    def analyze_pe(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a PE file comprehensively with enhanced logging and feature extraction."""
        try:
            base_features = self.extract_enhanced_features(file_path)
            if not base_features:
                logging.error(f"Failed to extract base features from {file_path}")
                return None

            die_analysis = self._analyze_with_die(file_path)
            
            # Serialize the entire result to ensure JSON compatibility
            result = {
                'base_features': base_features,
                'die_analysis': die_analysis
            }
            
            return self._serialize_data(result)
            
        except Exception as e:
            logging.error(f"Error analyzing PE file {file_path}: {e}")
            return None

class PESignatureCompiler:
    def __init__(self):
        logging.info("PESignatureCompiler initialized.")
        self.rules = []

    def add_rule(self, rule_content: dict) -> None:
        """Add a rule from content."""
        try:
            if isinstance(rule_content, dict):
                self.process_rule(rule_content)  # Process single rule
            elif isinstance(rule_content, list):
                for rule in rule_content:  # Process list of rules
                    if isinstance(rule, dict):
                        self.process_rule(rule)
                    else:
                        logging.error(f"Invalid rule format in list: {type(rule)}")
            else:
                logging.error(f"Invalid rule content type: {type(rule_content)}")

        except Exception as e:
            logging.error(f"Error processing rule: {e}")

    def process_rule(self, rule_dict: dict) -> None:
        """Validate and compile a single rule into a signature format that matches training data.

        Args:
            rule_dict (dict): Dictionary containing the features and classification
        """
        try:
            # Basic validation of input
            if not isinstance(rule_dict, dict):
                logging.error("Invalid rule format: Rule must be a dictionary.")
                return

            # Extract/normalize the file path info
            file_name = rule_dict.get('file_name', '')
            normalized_path = os.path.normpath(file_name) if file_name else ''

            # Construct the signature matching training data format
            signature = {
                "file_name": os.path.basename(file_name),
                "file_path": normalized_path,
                "label": rule_dict.get('label', 'unknown'),
                "classification": rule_dict.get('classification', 'unknown')
            }

            # Add all remaining features from the rule_dict
            signature.update(rule_dict)

            # Check for duplicates before adding
            if not any(existing_rule["file_path"] == signature["file_path"] for existing_rule in self.rules):
                self.rules.append(signature)
                logging.debug(f"Successfully added rule: {signature['file_name']}")
            else:
                logging.warning(f"Skipping duplicate rule: {signature['file_name']}")

        except Exception as e:
            logging.error(f"Error processing rule: {str(e)}")

class PESignatureEngine:
    def __init__(self, similarity_threshold = 0.9):
        logging.info("PESignatureEngine initialized.")
        self.analyzer = PEAnalyzer()
        self.compiler = PESignatureCompiler()
        self.rules = []
        self.similarity_threshold = similarity_threshold  # Store threshold as an instance variable

    def _evaluate_rule(self, rule: dict, features: dict) -> dict:
        """Enhanced rule evaluation with detailed debug logging."""
        if not isinstance(rule, dict):
            logging.error(f"Invalid rule format: {type(rule)}")
            return {}

        # Extract rule details
        rule_file_name = rule.get('file_name', 'unknown_rule_file')
        rule_file_path = rule.get('file_path', 'unknown_rule_path')

        # Extract feature file details
        feature_file_name = features.get('file_info', {}).get('name', 'unknown_file')
        feature_file_path = features.get('file_info', {}).get('path', 'unknown_path')

        logging.debug(f"Starting evaluation of rule: {rule_file_name} for file: {feature_file_name} at {feature_file_path}")

        # Construct the result dictionary
        result = {
            "rule_file_name": rule_file_name,
            "rule_file_path": rule_file_path,
            "file_name": feature_file_name,
            "file_path": feature_file_path,
            "strings": [],
            "imports": [],
            "sections": [],
            "confidence_scores": {
                "strings": 0.0,
                "imports": 0.0,
                "sections": 0.0,
            },
            "label": None,
            "classification": None,
        }

        try:
            def process_matches(rule_items, feature_items):
                """Helper function to process exact and near matches."""
                total_items = len(rule_items)
                exact_matches = []
                near_matches = []
                similarity_sum = 0.0

                for rule_item in rule_items:
                    pattern_value = rule_item.get('value', '')
                    best_match = None
                    best_similarity = 0.0

                    for feature_item in feature_items:
                        feature_value = feature_item.get('value', '')
                        similarity = calculate_string_similarity(pattern_value, feature_value)

                        if similarity == 1.0:
                            exact_matches.append({
                                'pattern': pattern_value,
                                'matched': feature_value,
                                'offset': feature_item.get('offset'),
                            })
                            break
                        elif similarity >= self.similarity_threshold and similarity > best_similarity:
                            best_match = {
                                'pattern': pattern_value,
                                'matched': feature_value,
                                'offset': feature_item.get('offset'),
                                'similarity': similarity,
                            }
                            best_similarity = similarity

                    if best_match:
                        near_matches.append(best_match)
                        similarity_sum += best_similarity

                confidence = (
                    (len(exact_matches) + similarity_sum) / total_items
                    if total_items > 0 else 0.0
                )

                return exact_matches, near_matches, confidence

            # Process strings
            rule_strings = rule.get('strings', [])
            feature_strings = features.get('strings', [])

            exact_strings, near_strings, string_confidence = process_matches(rule_strings, feature_strings)
            result['strings'] = exact_strings + near_strings
            result['confidence_scores']['strings'] = string_confidence

            # Process imports
            rule_imports = rule.get('imports', [])
            feature_imports = features.get('imports', [])

            exact_imports, near_imports, import_confidence = process_matches(
                [
                    {
                        'value': f"{imp.get('dll_name', '').lower()}::{imp_name.get('name', '')}"
                    }
                    for imp in rule_imports
                    for imp_name in imp.get('imports', [])
                ],
                [
                    {
                        'value': f"{feat_imp.get('dll_name', '').lower()}::{feat_name.get('name', '')}",
                        'offset': feat_name.get('address')
                    }
                    for feat_imp in feature_imports
                    for feat_name in feat_imp.get('imports', [])
                ]
            )

            result['imports'] = exact_imports + near_imports
            result['confidence_scores']['imports'] = import_confidence

            # Process sections
            rule_sections = rule.get('sections', [])
            feature_sections = features.get('sections', {}).items()

            exact_sections, near_sections, section_confidence = process_matches(
                [
                    {"value": f"{name}::{section.get('entropy', '')}::virtual_size::{section.get('virtual_size', 0)}"}
                    for name, section in rule_sections
                ],
                [
                    {"value": f"{name}::{section.get('entropy', '')}::virtual_size::{section.get('virtual_size', 0)}"}
                    for name, section in feature_sections
                ]
            )

            result['sections'] = exact_sections + near_sections
            result['confidence_scores']['sections'] = section_confidence

            # Calculate overall confidence
            overall_confidence = round(
                (
                    0.33 * result['confidence_scores']['strings'] +
                    0.33 * result['confidence_scores']['imports'] +
                    0.34 * result['confidence_scores']['sections']
                ), 3
            )

            result['overall_confidence'] = overall_confidence

            return result

        except Exception as e:
            logging.error(f"Error evaluating rule {rule_file_name} for file {feature_file_name}: {str(e)}")
            return result

    def load_rules(self, rules_file: str) -> None:
        """Load rules from a JSON file."""
        try:
            with open(rules_file, 'r') as f:
                rules_data = json.load(f)

            if isinstance(rules_data, list):
                for rule in rules_data:
                    self.compiler.add_rule(rule)

            logging.info(f"Loaded {len(self.compiler.rules)} rules")

        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")
            raise

    def scan_file(self, file_path: str) -> tuple:
        """Scan a PE file with enhanced logging and near-match detection."""
        if not os.path.exists(file_path):
            logging.error(f"Invalid file path: {file_path}")
            return [], None, 0.0

        logging.info(f"Scanning file: {file_path}")
        matches = []
        features = None
        overall_confidence = 0.0

        try:
            features = self.analyzer.analyze_pe(file_path)
            if not features:
                logging.error(f"Failed to analyze file: {file_path}")
                return matches, features, overall_confidence

            # Add debug logging
            logging.debug(f"Number of rules to evaluate: {len(self.compiler.rules)}")

            confidence_scores = []
            for rule in self.compiler.rules:
                result = self._evaluate_rule(rule, features)
                logging.debug(f"Rule evaluation result: {result}")  # Add debug logging

                if result and result['overall_confidence'] > 0:
                    confidence_scores.append(result['overall_confidence'])
                    matches.append({
                        'rule': rule.get('name', 'unknown'),
                        'matches': result,
                    })

            # Add debug logging for confidence calculation
            logging.debug(f"Confidence scores collected: {confidence_scores}")

            # Calculate average confidence if we have matches
            if confidence_scores:
                overall_confidence = sum(confidence_scores) / len(confidence_scores)
                logging.debug(f"Calculated overall confidence: {overall_confidence}")

            return matches, features, overall_confidence

        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {str(e)}")
            logging.exception("Full traceback:")  # Add full traceback
            return [], features, 0.0

def scan_action(args):
    """Handle the scan action with improved confidence handling."""
    if not args.file or not os.path.exists(args.file):
        logging.error("A valid file path or directory must be specified for the scan action.")
        sys.exit(1)

    signature_engine = PESignatureEngine(similarity_threshold=args.min_confidence)

    # Load rules if provided
    if args.rules and os.path.exists(args.rules):
        logging.info(f"Loading rules from {args.rules}")
        signature_engine.load_rules(args.rules)

    # Check if any rules are loaded
    if not signature_engine.compiler.rules:
        logging.error("No rules loaded. Please provide valid rules.")
        sys.exit(1)

    files_scanned = files_clean = files_malware = files_unknown = 0

    # Collect all files to scan
    all_files = []
    if os.path.isdir(args.file):
        logging.info(f"Scanning directory: {args.file}")
        for root, dirs, files in os.walk(args.file):
            for file_name in files:
                all_files.append(os.path.join(root, file_name))
    else:
        all_files.append(args.file)

    # Limit to max-files (1000 by default)
    all_files = all_files[:args.max_files]

    # Process each file
    for file_path in tqdm(all_files, desc="Scanning files", unit="file"):
        files_scanned += 1
        matches, features, overall_confidence = signature_engine.scan_file(file_path)

        if matches:
            # Classification based on confidence score
            classification = "malware" if overall_confidence >= args.min_confidence else "clean"
            if classification == "malware":
                files_malware += 1
                logging.warning(
                    f"\nFile {file_path} classified as {classification} "
                    f"Confidence: {overall_confidence:.4f}"
                )
            else:
                files_clean += 1
                logging.info(
                    f"\nFile {file_path} classified as {classification} "
                    f"Confidence: {overall_confidence:.4f}"
                )
        else:
            classification = "unknown"
            files_unknown += 1
            logging.info(f"\nFile {file_path} classified as {classification} Confidence: {overall_confidence:.4f}")

    # Summary logging
    logging.info("Scan Summary:")
    logging.info(f"  Total files scanned: {files_scanned}")
    logging.info(f"  Clean files: {files_clean}")
    logging.info(f"  Malware files: {files_malware}")
    logging.info(f"  Unknown files: {files_unknown}")

def main():
    """Main entry point for PE signature scanning and training."""

    # Set up argument parser
    parser = argparse.ArgumentParser(description="PE Signature Compiler, Analyzer, and Trainer")
    parser.add_argument('action', choices=['scan', 'train'], help="Action to perform: scan file or train model")
    parser.add_argument('--rules', type=str, help="Path to the rules file")
    parser.add_argument('--file', type=str, help="Path to the PE file or directory to scan (required for scan)")
    parser.add_argument('--clean-dir', type=str, help="Directory containing clean files for training")
    parser.add_argument('--malware-dir', type=str, help="Directory containing malware files for training")
    parser.add_argument('--max-files', type=int, default=1000, help="Maximum number of files to process during training or scanning")
    parser.add_argument('--min-confidence', type=float, default=0.9, help="Minimum confidence threshold for matches")

    # Parse arguments
    args = parser.parse_args()

    if args.action == 'scan':
        scan_action(args)

    elif args.action == 'train':
        if not args.clean_dir or not os.path.exists(args.clean_dir) or not args.malware_dir or not os.path.exists(
                args.malware_dir):
            logging.error("Valid clean and malware directories must be specified for training.")
            sys.exit(1)

        pe_analyzer = PEAnalyzer()
        clean_files = [os.path.join(args.clean_dir, f) for f in os.listdir(args.clean_dir) if
                       os.path.isfile(os.path.join(args.clean_dir, f))][:args.max_files]
        malware_files = [os.path.join(args.malware_dir, f) for f in os.listdir(args.malware_dir) if
                         os.path.isfile(os.path.join(args.malware_dir, f))][:args.max_files]

        logging.info(f"Extracting features from {len(clean_files)} clean files and {len(malware_files)} malware files.")

        clean_strings = set()  # To store unique strings from clean files
        malware_strings = set()  # To store unique strings from malware files

        # Extract strings from clean files
        for file_path in tqdm(clean_files, desc="Extracting clean strings", unit="file"):
            features = pe_analyzer.analyze_pe(file_path)
            if features:
                extracted_strings = features.get("strings", [])
                meaningful_strings = {
                    string["value"]
                    for string in extracted_strings
                    if len(string["value"]) >= 4  # Ensure the string has at least 4 characters
                       and filter_meaningful_words(word_tokenize(string["value"]))  # Apply NLTK filtering
                }
                clean_strings.update(meaningful_strings)

        # Extract strings from malware files
        for file_path in tqdm(malware_files, desc="Extracting malware strings", unit="file"):
            features = pe_analyzer.analyze_pe(file_path)
            if features:
                extracted_strings = features.get("strings", [])
                meaningful_strings = {
                    string["value"]
                    for string in extracted_strings
                    if len(string["value"]) >= 4  # Ensure the string has at least 4 characters
                       and filter_meaningful_words(word_tokenize(string["value"]))  # Apply NLTK filtering
                }
                malware_strings.update(meaningful_strings)

        # Compare clean and malware strings, removing overlap
        overlapping_strings = clean_strings.intersection(malware_strings)
        clean_strings -= overlapping_strings  # Remove overlapping strings from clean set
        malware_strings -= overlapping_strings  # Remove overlapping strings from malware set

        # Store training data while ensuring the proper string classification
        training_data = []
        logging.info(f"Feature extraction complete. Total training samples: {len(training_data)}")
        processed_files = set()  # Track processed files to avoid duplicates

        # Deduplicate clean and malware files
        unique_clean_files = set(clean_files)
        unique_malware_files = set(malware_files)

        # Ensure clean_strings and malware_strings are disjoint and deduplicated
        clean_strings = set(clean_strings) - set(malware_strings)
        malware_strings = set(malware_strings) - set(clean_strings)

        # Process each file exactly once
        for file_path in tqdm(unique_clean_files.union(unique_malware_files), desc="Constructing training samples",
                              unit="file"):
            normalized_path = os.path.abspath(file_path)  # Normalize file paths
            if normalized_path in processed_files:
                continue  # Skip already processed files
            processed_files.add(normalized_path)  # Mark as processed

            features = pe_analyzer.analyze_pe(file_path)
            if features:
                # Determine classification: clean or malware
                if file_path in unique_clean_files:
                    classification = "clean"
                    label = 0
                    strings_to_add = clean_strings
                elif file_path in unique_malware_files:
                    classification = "malware"
                    label = 1
                    strings_to_add = malware_strings
                else:
                    continue  # Skip files that don't belong to either category

                # Extract meaningful strings, avoiding duplicates
                extracted_strings = features.get("strings", [])
                meaningful_strings = list({
                                              string["value"]: string
                                              for string in extracted_strings
                                              if string["value"] in strings_to_add
                                                 and len(string["value"]) >= 4
                                                 and filter_meaningful_words(word_tokenize(string["value"]))
                                          }.values())

                # Construct the signature
                signature = {
                    "file_name": os.path.basename(file_path),
                    "file_path": normalized_path,  # Use normalized path for deduplication
                    **features,
                    "label": label,
                    "classification": classification,
                }

                # Avoid duplicate signatures in training_data
                if not any(sig["file_path"] == signature["file_path"] for sig in training_data):
                    training_data.append(signature)

        # Save training data to JSON file
        training_data_path = "training_data.json"
        with open(training_data_path, "w") as f:
            json.dump(training_data, f, indent=4)

        logging.info(f"Training data saved to {training_data_path}.")

if __name__ == "__main__":
    main()