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
        self.private_rules = {}  # Store private rules separately

    def add_private_rule(self, rule: Dict) -> None:
        """Add a private rule that can be referenced by other rules."""
        if not rule.get('name'):
            logging.error("Private rule must have a name")
            return
            
        self.private_rules[rule['name']] = rule
        logging.debug(f"Added private rule: {rule['name']}")

    def _compile_regex(self, pattern: str) -> Optional[re.Pattern]:
        """Safely compile a regex pattern."""
        try:
            if pattern.startswith('/') and pattern.rfind('/') > 0:
                # Extract flags from the regex pattern (e.g., /pattern/i)
                last_slash = pattern.rfind('/')
                pattern_content = pattern[1:last_slash]
                flags_str = pattern[last_slash + 1:]
                
                # Convert string flags to re module flags
                flags = 0
                if 'i' in flags_str:
                    flags |= re.IGNORECASE
                if 'm' in flags_str:
                    flags |= re.MULTILINE
                if 's' in flags_str:
                    flags |= re.DOTALL
                    
                return re.compile(pattern_content, flags)
            else:
                return re.compile(pattern)
        except re.error as e:
            logging.error(f"Invalid regex pattern '{pattern}': {e}")
            return None

    def _evaluate_rule(self, rule: Dict, features: Dict) -> Optional[Dict]:
        """Enhanced rule evaluation with regex support."""
        try:
            matches = {
                'strings': [],
                'imports': [],
                'sections': [],
                'resources': [],
                'headers': [],
                'private_rule_matches': []
            }

            # Process strings section
            for pattern_id, pattern in rule.get('strings', {}).items():
                is_regex = False
                regex_pattern = None
                
                if isinstance(pattern, dict):
                    # Handle structured string definitions
                    pattern_type = pattern.get('type', 'plain')
                    pattern_value = pattern.get('value', '')
                    is_regex = pattern_type == 'regex'
                    if is_regex:
                        regex_pattern = self._compile_regex(pattern_value)
                elif isinstance(pattern, str):
                    # Check if it's a regex pattern (starts and ends with /)
                    if pattern.startswith('/') and pattern.rfind('/') > 0:
                        is_regex = True
                        regex_pattern = self._compile_regex(pattern)
                    pattern_value = pattern

                # Check file strings
                for file_string in features.get('strings', []):
                    string_value = file_string.get('value', '')
                    if is_regex and regex_pattern:
                        if regex_pattern.search(string_value):
                            matches['strings'].append({
                                'pattern_id': pattern_id,
                                'string': string_value,
                                'offset': file_string.get('offset'),
                                'type': 'regex_match'
                            })
                    elif not is_regex and pattern_value.lower() in string_value.lower():
                        matches['strings'].append({
                            'pattern_id': pattern_id,
                            'string': string_value,
                            'offset': file_string.get('offset'),
                            'type': 'plain_match'
                        })

            # Check imports with regex support
            for imp in features.get('imports', []):
                dll_name = imp.get('dll_name', '').lower()
                for imp_detail in imp.get('imports', []):
                    imp_name = imp_detail.get('name', '')
                    if imp_name:
                        for pattern_id, pattern in rule.get('strings', {}).items():
                            if isinstance(pattern, dict) and pattern.get('type') == 'regex':
                                regex_pattern = self._compile_regex(pattern['value'])
                                if regex_pattern and regex_pattern.search(imp_name):
                                    matches['imports'].append({
                                        'pattern_id': pattern_id,
                                        'dll': dll_name,
                                        'import': imp_name,
                                        'type': 'regex_match'
                                    })
                            elif isinstance(pattern, str):
                                if pattern.startswith('/'):
                                    regex_pattern = self._compile_regex(pattern)
                                    if regex_pattern and regex_pattern.search(imp_name):
                                        matches['imports'].append({
                                            'pattern_id': pattern_id,
                                            'dll': dll_name,
                                            'import': imp_name,
                                            'type': 'regex_match'
                                        })
                                elif pattern.lower() in imp_name.lower():
                                    matches['imports'].append({
                                        'pattern_id': pattern_id,
                                        'dll': dll_name,
                                        'import': imp_name,
                                        'type': 'plain_match'
                                    })

            # Evaluate private rules
            for condition in rule.get('conditions', []):
                if isinstance(condition, str) and 'private.' in condition:
                    private_rule_name = condition.split('private.')[1].strip()
                    if private_rule_name in self.private_rules:
                        private_match = self._evaluate_rule(self.private_rules[private_rule_name], features)
                        if private_match:
                            matches['private_rule_matches'].append({
                                'rule_name': private_rule_name,
                                'matches': private_match
                            })

            # Evaluate conditions
            all_conditions_met = True
            for condition in rule.get('conditions', []):
                condition = str(condition).lower().strip()
                
                # Handle private rule conditions
                if condition.startswith('private.'):
                    private_rule_name = condition.split('private.')[1].strip()
                    if not any(m['rule_name'] == private_rule_name for m in matches['private_rule_matches']):
                        all_conditions_met = False
                        break
                
                # Handle other conditions as before
                elif condition == "any of strings" and not matches['strings']:
                    all_conditions_met = False
                    break
                elif condition == "any of imports" and not matches['imports']:
                    all_conditions_met = False
                    break
                elif condition.startswith('entropy.'):
                    try:
                        parts = condition.split()
                        threshold = float(parts[2])
                        if parts[0] == 'entropy.full':
                            actual = features.get('entropy', {}).get('full', 0)
                            if actual < threshold:
                                all_conditions_met = False
                                break
                    except (ValueError, IndexError):
                        all_conditions_met = False
                        break

            return matches if all_conditions_met else None

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
        """
        Scan a PE file and return matches against loaded rules.
        
        Args:
            file_path (str): Path to the PE file to scan
            
        Returns:
            List[Dict]: List of matches, each containing rule name, meta info, and match details
        """
        logging.debug(f"Scanning file: {file_path}")
        matches = []

        try:
            # Extract features using the analyzer
            features = self.analyzer.analyze_pe(file_path)
            if not features:
                logging.error(f"Failed to analyze file: {file_path}")
                return matches

            # Check each rule against the features
            for rule in self.compiler.rules:
                try:
                    match_result = self._evaluate_rule(rule, features)
                    if match_result and any(match_result.values()):  # Check if any matches were found
                        match_info = {
                            'rule': rule['name'],
                            'meta': rule.get('meta', {}),
                            'matches': match_result
                        }
                        matches.append(match_info)
                        logging.debug(f"Rule '{rule['name']}' matched")
                except Exception as e:
                    logging.error(f"Error evaluating rule {rule.get('name', 'unknown')} for file {file_path}: {e}")
                    continue

            return matches

        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return matches

def main():
    """Main entry point for PE signature scanning."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="PE Signature Compiler and Analyzer")
    parser.add_argument('action', choices=['scan'], help="Action to perform: scan file")
    parser.add_argument('--rules', type=str, help="Path to the rules file")
    parser.add_argument('--file', type=str, help="Path to the PE file or directory to scan")

    # Parse arguments
    args = parser.parse_args()

    if args.action == 'scan':
        if not args.file or not os.path.exists(args.file):
            logging.error("A valid file path or directory must be specified for scan action.")
            sys.exit(1)

        # Perform the scanning
        try:
            signature_engine = PESignatureEngine()

            # Load the rules
            if args.rules and os.path.exists(args.rules):
                logging.info(f"Loading rules from {args.rules}")
                signature_engine.load_rules(args.rules)
            else:
                logging.warning("No rules file specified or file doesn't exist, using default rules.")

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
                            logging.info(f"Rule: {match['rule']}")
                            for match_type, match_data in match.items():
                                if match_type != 'rule':
                                    logging.info(f"  {match_type}: {match_data}")
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
                        logging.info(f"Rule: {match['rule']}")
                        for match_type, match_data in match.items():
                            if match_type != 'rule':
                                logging.info(f"  {match_type}: {match_data}")
                else:
                    files_clean += 1

            # Print a summary of the scan results
            logging.info(f"Scan Summary:")
            logging.info(f"Total files scanned: {files_scanned}")
            logging.info(f"Clean files: {files_clean}")
            logging.info(f"Files with matches: {files_with_matches}")

        except Exception as e:
            logging.error(f"Error scanning file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()