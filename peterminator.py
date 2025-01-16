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

# Set script directory
script_dir = os.getcwd()

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
                'raw_data': raw_data
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
        strings = []
        try:
            ascii_pattern = f'[\x20-\x7e]{{{min_length},}}'
            for match in re.finditer(ascii_pattern.encode(), data):
                strings.append({
                    'type': 'ascii',
                    'value': match.group().decode('ascii', errors='ignore'),
                    'offset': match.start(),
                    'size': len(match.group())
                })

            unicode_pattern = f'(?:[\x20-\x7e]\x00){{{min_length},}}'
            for match in re.finditer(unicode_pattern.encode(), data):
                try:
                    strings.append({
                        'type': 'unicode',
                        'value': match.group().decode('utf-16le', errors='ignore'),
                        'offset': match.start(),
                        'size': len(match.group())
                    })
                except UnicodeDecodeError:
                    continue
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

    def _analyze_with_die(self, file_path: str) -> Optional[str]:
        """Analyze a file using Detect It Easy (DIE) without JSON output."""
        try:
            if not os.path.exists(detectiteasy_console_path):
                raise FileNotFoundError(f"DIE executable not found at {detectiteasy_console_path}")

            result = subprocess.run(
                [detectiteasy_console_path, file_path],  # No /json argument for text output
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                logging.error(f"DIE analysis failed: {result.stderr.strip()}")
                return None

            die_output = result.stdout.strip()
            return die_output  # Return the standard text output from DIE
        except Exception as e:
            logging.error(f"Error during DIE analysis for {file_path}: {e}")
            return None

    def extract_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
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
                    'rank': rank,
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
        """Analyze a PE file comprehensively."""
        try:
            features = self.extract_features(file_path)
            if not features:
                return None

            die_analysis = self._analyze_with_die(file_path)

            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Validate 'sections' format
            sections = features.get('sections', {})
            if not isinstance(sections, dict):
                logging.error(f"Invalid format for 'sections': {sections}")
                return None

            # Validate and log strings
            extracted_strings = self._extract_strings(file_data)
            if not isinstance(extracted_strings, list):
                logging.error(f"Invalid output from _extract_strings: {extracted_strings}")
                return None

            return {
                **features,
                'die_info': die_analysis,
                'strings': extracted_strings,
                'entropy': {
                    'full': self._calculate_entropy(file_data),
                    'sections': {name: data.get('entropy', 0) for name, data in sections.items()}
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
            # Parse JSON if the input is a string
            if isinstance(rule_content, str):
                rule_dict = json.loads(rule_content)
            else:
                rule_dict = rule_content

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
    def __init__(self):
        logging.info("PESignatureEngine initialized.")
        self.analyzer = PEAnalyzer()
        self.compiler = PESignatureCompiler()
        self.rules = []
        self.private_rules = {}

    def _evaluate_rule(self, rule: Dict, features: Dict) -> Optional[Dict]:
        """Enhanced rule evaluation with detailed debug logging."""
        try:
            matches = {
                'strings': [],
                'imports': [],
                'sections': [],
                'resources': [],
                'headers': [],
                'conditions_met': [],
                'confidence_scores': {
                    'strings': 0.0,
                    'imports': 0.0,
                    'sections': 0.0,
                    'conditions': 0.0
                }
            }

            # Handle strings
            total_strings = len(rule.get('strings', []))
            if total_strings > 0:
                logging.debug(f"Processing {total_strings} string patterns...")
                for string_def in rule.get('strings', []):
                    if isinstance(string_def, dict):
                        pattern_value = string_def.get('value', '')
                        pattern_type = string_def.get('type', 'ascii')

                        for file_string in features.get('strings', []):
                            string_value = file_string.get('value', '')
                            if pattern_value.lower() in string_value.lower():
                                match_detail = {
                                    'pattern': pattern_value,
                                    'matched': string_value,
                                    'type': pattern_type,
                                    'offset': file_string.get('offset')
                                }
                                matches['strings'].append(match_detail)
                                logging.debug(f"Matched string: {match_detail}")

                # Calculate string match confidence
                matches['confidence_scores']['strings'] = len(matches['strings']) / total_strings
                logging.debug(f"String match confidence: {matches['confidence_scores']['strings']}")

            # Handle imports
            total_imports = sum(len(imp.get('imports', [])) for imp in rule.get('imports', []))
            matched_imports = 0

            logging.debug(f"Processing imports with total_imports={total_imports}...")
            for import_def in rule.get('imports', []):
                dll_name = import_def.get('dll_name', '').lower()
                import_list = import_def.get('imports', [])

                for feature_imp in features.get('imports', []):
                    if feature_imp.get('dll_name', '').lower() == dll_name:
                        for required_imp in import_list:
                            req_name = required_imp.get('name', '')
                            for feature_imp_detail in feature_imp.get('imports', []):
                                if req_name.lower() == feature_imp_detail.get('name', '').lower():
                                    matched_imports += 1
                                    match_detail = {
                                        'dll': dll_name,
                                        'import': req_name,
                                        'address': feature_imp_detail.get('address')
                                    }
                                    matches['imports'].append(match_detail)
                                    logging.debug(f"Matched import: {match_detail}")

            if total_imports > 0:
                matches['confidence_scores']['imports'] = matched_imports / total_imports
                logging.debug(f"Import match confidence: {matches['confidence_scores']['imports']}")

            # Handle sections
            rule_sections = rule.get('sections', {})
            total_sections = len(rule_sections)
            matched_sections = 0

            logging.debug(f"Processing sections with total_sections={total_sections}...")
            for section_name, section_data in features.get('sections', {}).items():
                if section_name in rule_sections:
                    required_section = rule_sections[section_name]
                    section_matches = True
                    total_props = 0
                    matched_props = 0

                    for key, value in required_section.items():
                        if key in section_data:
                            total_props += 1
                            if section_data.get(key) == value:
                                matched_props += 1
                            else:
                                section_matches = False

                    if section_matches and total_props > 0:
                        matched_sections += 1
                        match_detail = {
                            'name': section_name,
                            'data': section_data,
                            'match_quality': matched_props / total_props
                        }
                        matches['sections'].append(match_detail)
                        logging.debug(f"Matched section: {match_detail}")

            if total_sections > 0:
                matches['confidence_scores']['sections'] = matched_sections / total_sections
                logging.debug(f"Section match confidence: {matches['confidence_scores']['sections']}")

            # Evaluate conditions
            conditions = rule.get('conditions', {})
            total_conditions = len(conditions)
            met_conditions = 0

            logging.debug(f"Processing conditions with total_conditions={total_conditions}...")
            if conditions:
                # Check minimum imports
                min_imports = conditions.get('min_imports', 0)
                if len(matches['imports']) >= min_imports:
                    met_conditions += 1
                    matches['conditions_met'].append('min_imports')
                    logging.debug(f"Condition 'min_imports' met.")

                # Check minimum sections
                min_sections = conditions.get('min_sections', 0)
                if len(matches['sections']) >= min_sections:
                    met_conditions += 1
                    matches['conditions_met'].append('min_sections')
                    logging.debug(f"Condition 'min_sections' met.")

                # Check entropy threshold
                entropy_threshold = conditions.get('entropy_threshold', 0)
                if features.get('entropy', {}).get('full', 0) >= entropy_threshold:
                    met_conditions += 1
                    matches['conditions_met'].append('entropy_threshold')
                    logging.debug(f"Condition 'entropy_threshold' met.")

                # Check required IAT imports
                iat_imports = conditions.get('iat_imports', [])
                if all(imp in features.get('iat', {}) for imp in iat_imports):
                    met_conditions += 1
                    matches['conditions_met'].append('iat_imports')
                    logging.debug(f"Condition 'iat_imports' met.")

                # Check required section names
                section_names = conditions.get('section_names', [])
                if all(name in features.get('sections', {}) for name in section_names):
                    met_conditions += 1
                    matches['conditions_met'].append('section_names')
                    logging.debug(f"Condition 'section_names' met.")

            if total_conditions > 0:
                matches['confidence_scores']['conditions'] = met_conditions / total_conditions
                logging.debug(f"Condition match confidence: {matches['confidence_scores']['conditions']}")

            # Calculate overall confidence score
            weights = {
                'strings': 0.3,
                'imports': 0.3,
                'sections': 0.2,
                'conditions': 0.2
            }

            overall_confidence = sum(
                score * weights[category]
                for category, score in matches['confidence_scores'].items()
            )

            matches['overall_confidence'] = round(overall_confidence, 2)
            logging.debug(f"Overall confidence: {matches['overall_confidence']}")

            logging.debug(f"Final matches: {matches}")
            return matches

        except Exception as e:
            logging.error(f"Error in _evaluate_rule: {e}")
            return None

    def load_rules(self, rules_file: str) -> None:
        """Load rules including private rules from a JSON file."""
        try:
            with open(rules_file, 'r') as f:
                rules_data = json.load(f)
                
            if isinstance(rules_data, list):
                for rule in rules_data:
                    if rule.get('private', False):
                        self.add_private_rule(rule)
                    else:
                        self.compiler.add_rule(rule)
            elif isinstance(rules_data, dict):
                if rules_data.get('private', False):
                    self.add_private_rule(rules_data)
                else:
                    self.compiler.add_rule(rules_data)
                    
            logging.info(f"Loaded {len(self.compiler.rules)} public rules and {len(self.private_rules)} private rules")
            
        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")
            raise

    def scan_file(self, file_path: str) -> List[Dict]:
        """Scan a PE file and return matches against loaded rules."""
        logging.debug(f"Scanning file: {file_path}")
        matches = []

        try:
            features = self.analyzer.analyze_pe(file_path)
            if not features:
                logging.error(f"Failed to analyze file: {file_path}")
                return matches

            # Process each rule
            for rule in self.compiler.rules:
                try:
                    match_result = self._evaluate_rule(rule, features)
                    if match_result:
                        match_info = {
                            'rule': rule.get('rule'),
                            'meta': rule.get('meta', {}),
                            'matches': match_result
                        }
                        matches.append(match_info)
                        logging.debug(f"Rule '{rule.get('rule')}' matched")
                except Exception as e:
                    logging.error(f"Error evaluating rule {rule.get('rule', 'unknown')} for file {file_path}: {e}")
                    continue

            return matches

        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return matches

def log_match_details(match, min_confidence):
    """Logs detailed information about a match."""
    if match['overall_confidence'] < min_confidence:
        logging.debug(f"Skipping low-confidence match: {match['rule']} (Confidence: {match['overall_confidence']})")
        return

    logging.info(f"  Rule: {match['rule']} (Confidence: {match['overall_confidence']})")

    # Log matched strings
    if "strings" in match and match["strings"]:
        logging.info("  Matched Strings:")
        for string_match in match["strings"]:
            logging.info(f"    Pattern: {string_match['pattern']} | Matched: {string_match['matched']}")

    # Log matched imports
    if "imports" in match and match["imports"]:
        logging.info("  Matched Imports:")
        for import_match in match["imports"]:
            logging.info(f"    DLL: {import_match['dll']} | Import: {import_match['import']} | Address: {import_match.get('address')}")

    # Log matched sections
    if "sections" in match and match["sections"]:
        logging.info("  Matched Sections:")
        for section_match in match["sections"]:
            logging.info(f"    Section: {section_match['name']} | Entropy: {section_match['entropy']} | Match Quality: {section_match['match_quality']}")

    # Log conditions met
    if "conditions_met" in match and match["conditions_met"]:
        logging.info("  Conditions Met:")
        for condition in match["conditions_met"]:
            logging.info(f"    {condition}")

def main():
    """Main entry point for PE signature scanning."""
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.StreamHandler(sys.stdout)]
    )

    # Set up argument parser
    parser = argparse.ArgumentParser(description="PE Signature Compiler and Analyzer")
    parser.add_argument('action', choices=['scan'], help="Action to perform: scan file")
    parser.add_argument('--rules', type=str, help="Path to the rules file")
    parser.add_argument('--file', type=str, required=True, help="Path to the PE file or directory to scan")
    parser.add_argument('--min-confidence', type=float, default=0.5, help="Minimum confidence threshold for matches")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging for debugging")

    # Parse arguments
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action == 'scan':
        if not args.file or not os.path.exists(args.file):
            logging.error("A valid file path or directory must be specified for the scan action.")
            sys.exit(1)

        # Perform the scanning
        try:
            signature_engine = PESignatureEngine()

            # Load the rules
            if args.rules and os.path.exists(args.rules):
                logging.info(f"Loading rules from {args.rules}")
                signature_engine.load_rules(args.rules)
            else:
                logging.warning("No rules file specified or file doesn't exist. Using default rules.")

            files_scanned = 0
            files_clean = 0
            files_with_matches = 0

            # Check if it's a directory or a single file
            if os.path.isdir(args.file):
                logging.info(f"Scanning all files in directory: {args.file}")
                all_files = []
                for root, _, files in os.walk(args.file):
                    for file in files:
                        all_files.append(os.path.join(root, file))

                # Use tqdm for progress tracking
                for file_path in tqdm(all_files, desc="Scanning files", unit="file"):
                    files_scanned += 1
                    matches = signature_engine.scan_file(file_path)
                    if matches:
                        files_with_matches += 1
                        logging.info(f"File {file_path} matches the following rules:")
                        for match in matches:
                            log_match_details(match, args.min_confidence)
                    else:
                        files_clean += 1

            else:
                # Scan a single file
                logging.info(f"Scanning file: {args.file}")
                files_scanned += 1
                matches = signature_engine.scan_file(args.file)
                if matches:
                    files_with_matches += 1
                    logging.info(f"File {args.file} matches the following rules:")
                    for match in matches:
                        log_match_details(match, args.min_confidence)
                else:
                    files_clean += 1

            # Print a summary of the scan results
            logging.info("Scan Summary:")
            logging.info(f"  Total files scanned: {files_scanned}")
            logging.info(f"  Clean files: {files_clean}")
            logging.info(f"  Files with matches: {files_with_matches}")

        except Exception as e:
            logging.error(f"Error during scanning: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()