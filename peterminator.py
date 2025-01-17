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
import string

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

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of binary data."""
        if not data:
            return 0.0

        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * np.log2(p_x)
        return entropy

    def extract_section_data(self, section) -> Dict[str, Any]:
        """Extract comprehensive section data including entropy."""
        try:
            raw_data = section.get_data()
            return {
                'name': section.Name.decode(errors='ignore').strip('\x00'),
                'virtual_size': section.Misc_VirtualSize,
                'virtual_address': section.VirtualAddress,
                'raw_size': section.SizeOfRawData,
                'pointer_to_raw_data': section.PointerToRawData,
                'characteristics': section.Characteristics,
                'entropy': self._calculate_entropy(raw_data),
                'raw_data_size': len(raw_data) if raw_data else 0,
            }
        except Exception as e:
            logging.error(f"Error extracting section data: {e}")
            return {}

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

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract ASCII strings from binary data, filtering out common PE headers."""
        strings = []
        try:
            ascii_pattern = f'[\x20-\x7e]{{{min_length},}}'
            for match in re.finditer(ascii_pattern.encode(), data):
                string_value = match.group().decode('ascii', errors='ignore').strip()

                # Skip common PE header strings
                if string_value in COMMON_PE_STRINGS or string_value.lower() in (s.lower() for s in COMMON_PE_STRINGS):
                    continue

                strings.append({
                    'type': 'ascii',
                    'value': string_value,
                    'offset': match.start(),
                    'size': len(string_value)
                })
        except Exception as e:
            logging.error(f"Error extracting strings: {e}")

        return strings

    def _analyze_iat(self, pe) -> Dict[str, int]:
        """Analyze the Import Address Table (IAT)."""
        iat = {}
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_IAT'):
                for entry in pe.DIRECTORY_ENTRY_IAT:
                    if entry.name:
                        iat[entry.name.decode()] = entry.struct.FirstThunk
        except Exception as e:
            logging.error(f"Error analyzing IAT: {e}")
        return iat

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

    def extract_features(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Extract comprehensive PE file features."""
        if file_path in self.features_cache:
            return self.features_cache[file_path]

        try:
            pe = pefile.PE(file_path)

            # Extract sections with validation
            valid_sections = [self.extract_section_data(section) for section in pe.sections]
            valid_sections = [s for s in valid_sections if isinstance(s, dict) and 'name' in s]

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
                'sections': {s['name']: s for s in valid_sections},
                'imports': self.extract_imports(pe),
                'exports': self.extract_exports(pe),
                'resources': [],
                'debug_info': [],
                'iat': self._analyze_iat(pe)
            }

            # Extract resources
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if hasattr(resource_type, 'directory'):
                        for resource_id in resource_type.directory.entries:
                            if hasattr(resource_id, 'directory'):
                                for resource_lang in resource_id.directory.entries:
                                    if hasattr(resource_lang, 'data'):
                                        res_data = {
                                            'type_id': resource_type.id,
                                            'resource_id': resource_id.id,
                                            'lang_id': resource_lang.id,
                                            'size': resource_lang.data.struct.Size,
                                            'codepage': resource_lang.data.struct.CodePage,
                                        }
                                        features['resources'].append(res_data)

            # Extract debug information
            if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
                for debug in pe.DIRECTORY_ENTRY_DEBUG:
                    debug_info = {
                        'type': debug.struct.Type,
                        'timestamp': debug.struct.TimeDateStamp,
                        'version': f"{debug.struct.MajorVersion}.{debug.struct.MinorVersion}",
                        'size': debug.struct.SizeOfData,
                    }
                    features['debug_info'].append(debug_info)

            self.features_cache[file_path] = features
            return features
        except Exception as e:
            logging.error(f"Error extracting features from {file_path}: {e}")
            return None

    def analyze_pe(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Analyze a PE file comprehensively with enhanced logging and string filtering."""
        try:
            features = self.extract_features(file_path)
            if not features:
                logging.error(f"Failed to extract features from {file_path}")
                return None

            die_analysis = self._analyze_with_die(file_path)
            logging.info(f"DIE analysis completed for {file_path}")

            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Validate 'sections' format with detailed logging
            sections = features.get('sections', {})
            if not isinstance(sections, dict):
                logging.error(f"Invalid format for 'sections': {type(sections)}")
                return None

            # Enhanced string extraction with filtering
            raw_strings = self._extract_strings(file_data)
            if not isinstance(raw_strings, list):
                logging.error(f"Invalid output from _extract_strings: {type(raw_strings)}")
                return None

            # Filter and deduplicate strings
            filtered_strings = {}  # Use dict for deduplication
            for string_entry in raw_strings:
                string_value = string_entry['value']

                # Apply filtering criteria
                if (len(string_value) >= 4 and  # Length check
                        not string_value.isdigit() and  # Not just numbers
                        not all(c in string.punctuation for c in string_value)):  # Not just punctuation

                    # Use string value as key for deduplication
                    if string_value not in filtered_strings:
                        filtered_strings[string_value] = string_entry

            # Calculate entropy scores
            full_entropy = self._calculate_entropy(file_data)
            section_entropies = {name: data.get('entropy', 0) for name, data in sections.items()}

            return {
                **features,
                'die_info': die_analysis,
                'strings': list(filtered_strings.values()),
                'entropy': {
                    'full': full_entropy,
                    'sections': section_entropies
                }
            }
        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {e}")
            return None

class PESignatureCompiler:
    def __init__(self):
        logging.info("PESignatureCompiler initialized.")
        self.rules = []

    def add_rule(self, rule_content: str) -> None:
        """Add a rule from JSON content."""
        logging.debug("Adding rule.")
        try:
            # Ensure rule_content is in dictionary format
            if isinstance(rule_content, str):
                rule_dict = json.loads(rule_content)  # Parse JSON string into a dictionary
            elif isinstance(rule_content, dict):
                rule_dict = rule_content  # Use the content directly if it's already a dictionary
            else:
                logging.error(f"Invalid rule content type: {type(rule_content)}")
                return

            # If it's a list of rules, process each rule individually
            if isinstance(rule_dict, list):
                for rule in rule_dict:
                    self.process_rule(rule)
            else:
                # Process single rule
                self.process_rule(rule_dict)

        except json.JSONDecodeError as e:
            logging.error(f"Error parsing rule JSON: {e}")
        except Exception as e:
            logging.error(f"Error compiling rule: {e}")

    def process_rule(self, rule_dict: dict) -> None:
        """Validate and compile a single rule."""
        # Validate required fields
        required_fields = ['rule', 'meta', 'strings', 'conditions']
        if not all(field in rule_dict for field in required_fields):
            missing = [f for f in required_fields if f not in rule_dict]
            logging.error(f"Missing required fields in rule: {missing}")
            return

        # Convert the rule format to internal representation
        compiled_rule = {
            'name': rule_dict['rule'],
            'meta': rule_dict['meta'],
            'strings': rule_dict['strings'],
            'conditions': rule_dict['conditions']
        }

        self.rules.append(compiled_rule)
        logging.debug(f"Successfully added rule: {compiled_rule['name']}")

class PESignatureEngine:
    def __init__(self, similarity_threshold):
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

        rule_name = rule.get('name', 'unknown')
        logging.debug(f"Starting evaluation of rule: {rule_name}")

        try:
            # Initialize matches dictionary
            matches = {
                'strings': [],
                'imports': [],
                'near_matches': {
                    'strings': [],
                    'imports': [],
                },
                'confidence_scores': {
                    'strings': 0.0,
                    'imports': 0.0,
                },
            }

            # Process strings
            rule_strings = rule.get('strings', [])
            feature_strings = features.get('strings', [])
            total_strings = len(rule_strings)

            if total_strings > 0:
                for string_def in rule_strings:
                    pattern_value = string_def.get('value', '')
                    best_match = None
                    best_similarity = 0.0

                    for feature_string in feature_strings:
                        string_value = feature_string.get('value', '')
                        similarity = calculate_string_similarity(pattern_value, string_value)

                        if similarity == 1.0:
                            matches['strings'].append({
                                'pattern': pattern_value,
                                'matched': string_value,
                                'offset': feature_string.get('offset'),
                            })
                            break
                        elif similarity >= self.similarity_threshold and similarity > best_similarity:
                            best_match = {
                                'pattern': pattern_value,
                                'matched': string_value,
                                'offset': feature_string.get('offset'),
                                'similarity': similarity,
                            }
                            best_similarity = similarity

                    if best_match:
                        matches['near_matches']['strings'].append(best_match)

                matches['confidence_scores']['strings'] = (
                    len(matches['strings']) +
                    sum(match['similarity'] for match in matches['near_matches']['strings'])
                ) / total_strings

            # Process imports
            rule_imports = rule.get('imports', [])
            feature_imports = features.get('imports', [])
            total_imports = sum(len(imp.get('imports', [])) for imp in rule_imports)

            if total_imports > 0:
                for import_def in rule_imports:
                    dll_name = import_def.get('dll_name', '').lower()
                    import_list = import_def.get('imports', [])

                    for feature_import in feature_imports:
                        if feature_import.get('dll_name', '').lower() == dll_name:
                            for required_import in import_list:
                                req_name = required_import.get('name', '')
                                for feature_imp in feature_import.get('imports', []):
                                    feat_name = feature_imp.get('name', '')
                                    similarity = calculate_string_similarity(req_name, feat_name)

                                    if similarity == 1.0:
                                        matches['imports'].append({
                                            'dll': dll_name,
                                            'import': req_name,
                                            'address': feature_imp.get('address'),
                                        })
                                    elif similarity >= self.similarity_threshold:
                                        matches['near_matches']['imports'].append({
                                            'dll': dll_name,
                                            'required': req_name,
                                            'found': feat_name,
                                            'similarity': similarity,
                                        })

                matches['confidence_scores']['imports'] = len(matches['imports']) / total_imports

            # Calculate overall confidence
            matches['overall_confidence'] = round(
                0.5 * matches['confidence_scores']['strings'] +
                0.5 * matches['confidence_scores']['imports'], 3
            )

            return matches

        except Exception as e:
            logging.error(f"Error evaluating rule {rule_name}: {str(e)}")
            return {}

    def load_rules(self, rules_file: str) -> None:
        """Load rules from a JSON file."""
        try:
            with open(rules_file, 'r') as f:
                rules_data = json.load(f)

            if isinstance(rules_data, list):
                for rule in rules_data:
                    self.compiler.add_rule(rule)
            elif isinstance(rules_data, dict):
                self.compiler.add_rule(rules_data)

            logging.info(f"Loaded {len(self.compiler.rules)} rules")

        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")
            raise

    def scan_file(self, file_path: str) -> list:
        """Scan a PE file with enhanced logging and near-match detection."""
        if not os.path.exists(file_path):
            logging.error(f"Invalid file path: {file_path}")
            return []

        logging.info(f"Scanning file: {file_path}")
        matches = []

        try:
            features = self.analyzer.analyze_pe(file_path)
            if not features:
                logging.error(f"Failed to analyze file: {file_path}")
                return matches

            for rule in self.compiler.rules:
                result = self._evaluate_rule(rule, features)
                if result and result['overall_confidence'] > 0:
                    matches.append({
                        'rule': rule.get('name', 'unknown'),
                        'matches': result,
                    })

            return matches

        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {str(e)}")
            return []

def main():
    """Main entry point for PE signature scanning and training."""

    # Set up argument parser
    parser = argparse.ArgumentParser(description="PE Signature Compiler, Analyzer, and Trainer")
    parser.add_argument('action', choices=['scan', 'train'], help="Action to perform: scan file or train model")
    parser.add_argument('--rules', type=str, help="Path to the rules file")
    parser.add_argument('--file', type=str, help="Path to the PE file or directory to scan (required for scan)")
    parser.add_argument('--clean-dir', type=str, help="Directory containing clean files for training")
    parser.add_argument('--malware-dir', type=str, help="Directory containing malware files for training")
    parser.add_argument('--max-files', type=int, default=1000,
                        help="Maximum number of files to process during training or scanning")
    parser.add_argument('--min-confidence', type=float, default=0.9, help="Minimum confidence threshold for matches")

    # Parse arguments
    args = parser.parse_args()

    if args.action == 'scan':
        if not args.file or not os.path.exists(args.file):
            logging.error("A valid file path or directory must be specified for the scan action.")
            sys.exit(1)

        signature_engine = PESignatureEngine(similarity_threshold=args.min_confidence)

        # Load rules if provided
        if args.rules and os.path.exists(args.rules):
            logging.info(f"Loading rules from {args.rules}")
            signature_engine.load_rules(args.rules)

        # Load training data
        training_data = []
        training_data_path = "training_data.json"
        if os.path.exists(training_data_path):
            logging.info(f"Loading training data from {training_data_path}")
            with open(training_data_path, 'r') as f:
                training_data = json.load(f)

        files_scanned = 0
        files_clean = 0
        files_malware = 0
        files_unknown = 0

        all_files = []
        if os.path.isdir(args.file):
            logging.info(f"Scanning directory: {args.file}")

            # Walk through all subdirectories and files
            for root, dirs, files in os.walk(args.file):
                for file_name in files:
                    all_files.append(os.path.join(root, file_name))
        else:
            all_files.append(args.file)

        # Limit to max-files (1000 by default)
        all_files = all_files[:args.max_files]

        for file_path in tqdm(all_files, desc="Scanning files", unit="file"):
            files_scanned += 1
            matches = signature_engine.scan_file(file_path)
            features = signature_engine.analyzer.analyze_pe(file_path)

            # Enhanced matching analysis
            match_details = {
                'confidence_scores': [],
                'string_matches': [],
                'section_matches': [],
                'entropy_matches': []
            }

            if features and training_data:
                for entry in training_data:
                    # Calculate string similarity
                    entry_strings = set(s['value'] for s in entry.get('strings', []))
                    feature_strings = set(s['value'] for s in features.get('strings', []))
                    string_overlap = len(entry_strings.intersection(feature_strings))
                    string_similarity = string_overlap / max(len(entry_strings), len(feature_strings)) if max(
                        len(entry_strings), len(feature_strings)) > 0 else 0

                    # Calculate section similarity
                    section_match = all(
                        section in features.get('sections', {})
                        for section in entry.get('sections', {})
                    )

                    # Calculate entropy similarity
                    entry_entropy = entry.get('entropy', {}).get('full', 0)
                    feature_entropy = features.get('entropy', {}).get('full', 0)
                    entropy_similarity = 1 - abs(entry_entropy - feature_entropy) / max(entry_entropy,
                                                                                        feature_entropy) if max(
                        entry_entropy, feature_entropy) > 0 else 0

                    # Calculate overall confidence
                    confidence = (string_similarity * 0.4 +
                                  (1 if section_match else 0) * 0.3 +
                                  entropy_similarity * 0.3)

                    match_details['confidence_scores'].append(confidence)

                    if string_overlap > 0:
                        match_details['string_matches'].append({
                            'matched_strings': entry_strings.intersection(feature_strings),
                            'similarity': string_similarity
                        })

                    if section_match:
                        match_details['section_matches'].append({
                            'matching_sections': list(entry.get('sections', {}).keys())
                        })

                    if entropy_similarity > 0.8:  # High entropy similarity threshold
                        match_details['entropy_matches'].append({
                            'similarity': entropy_similarity,
                            'reference_entropy': entry_entropy,
                            'sample_entropy': feature_entropy
                        })

                    if confidence >= args.min_confidence:
                        matches.append({
                            'rule': 'Training Match',
                            'label': entry.get('label', 'unknown'),
                            'confidence': confidence
                        })

            # Enhanced logging of match details
            logging.info(f"\nAnalysis results for {file_path}:")

            # Extract confidence scores from matches
            confidence_scores = [m['confidence'] for m in matches if 'confidence' in m]

            if confidence_scores:
                # Compute overall confidence as an average of all matched rule confidences
                overall_confidence = sum(confidence_scores) / len(confidence_scores)
                logging.info(f"Overall Confidence Score: {overall_confidence:.4f}")
            else:
                overall_confidence = 0.0  # No matches found
                logging.info("Overall Confidence Score: 0.0000")

            # Classification logging
            if overall_confidence >= args.min_confidence:
                classification = 'malware' if any(m['label'] == 1 for m in matches) else 'clean'
                logging.warning(f"\nFile classified as {classification} with confidence {overall_confidence:.4f}")
            else:
                logging.info("\nFile classification: unknown")
                if matches:
                    logging.info("Below threshold matches found:")
                    for match in matches:
                        logging.info(f"- Rule: {match['rule']}, Confidence: {match['confidence']:.4f}")

        logging.info("Scan Summary:")
        logging.info(f"  Total files scanned: {files_scanned}")
        logging.info(f"  Clean files: {files_clean}")
        logging.info(f"  Malware files: {files_malware}")
        logging.info(f"  Unknown files: {files_unknown}")

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