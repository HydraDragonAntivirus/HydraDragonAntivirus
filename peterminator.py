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

# Ensure that necessary NLTK resources are available
nltk.download('punkt')
nltk.download('punkt_tab')
nltk.download('words')

from nltk.corpus import words
from nltk.tokenize import word_tokenize

# Create a set of English words for faster lookup, only including words with 4 or more characters
nltk_words = set(word for word in words.words() if len(word) >= 4)

# A filter function to keep only meaningful words, remove duplicates, and ensure each word is at least 4 characters long
def filter_meaningful_words(word_list):
    """
    Filter out non-English, meaningless strings, duplicates, and words shorter than 4 characters.
    :param word_list: List of words (strings) to filter.
    :return: List of unique, meaningful English words with at least 4 characters.
    """
    # Remove duplicates by converting the list to a set
    return list(set(word for word in word_list if word.isalpha() and word.lower() in nltk_words and len(word) >= 4))

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
        """Extract ASCII strings from the binary data."""
        strings = []
        try:
            # Define the regex pattern to match ASCII strings of at least `min_length` characters
            ascii_pattern = f'[\x20-\x7e]{{{min_length},}}'

            # Find matches using the ASCII pattern
            for match in re.finditer(ascii_pattern.encode(), data):
                strings.append({
                    'type': 'ascii',
                    'value': match.group().decode('ascii', errors='ignore'),
                    'offset': match.start(),
                    'size': len(match.group())
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
        self.private_rules = []

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

    def add_private_rule(self, rule_content: str) -> None:
        """Add a private rule from JSON content."""
        logging.debug("Adding private rule.")
        try:
            # Ensure rule_content is in dictionary format
            if isinstance(rule_content, str):
                rule_dict = json.loads(rule_content)  # Parse JSON string into a dictionary
            elif isinstance(rule_content, dict):
                rule_dict = rule_content  # Use the content directly if it's already a dictionary
            else:
                logging.error(f"Invalid private rule content type: {type(rule_content)}")
                return

            # If it's a list of rules, process each rule individually
            if isinstance(rule_dict, list):
                for rule in rule_dict:
                    self.process_private_rule(rule)
            else:
                # Process single private rule
                self.process_private_rule(rule_dict)

        except json.JSONDecodeError as e:
            logging.error(f"Error parsing private rule JSON: {e}")
        except Exception as e:
            logging.error(f"Error compiling private rule: {e}")

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

    def process_private_rule(self, rule_dict: dict) -> None:
        """Validate and compile a private rule."""
        # Validate required fields for private rules (could be stricter)
        required_fields = ['rule', 'meta', 'strings', 'conditions', 'private']
        if not all(field in rule_dict for field in required_fields):
            missing = [f for f in required_fields if f not in rule_dict]
            logging.error(f"Missing required fields in private rule: {missing}")
            return

        # Ensure the 'private' field is correctly set
        if not rule_dict['private']:
            logging.error("Private rule must have 'private' set to True.")
            return

        # Convert the rule format to internal representation
        compiled_private_rule = {
            'name': rule_dict['rule'],
            'meta': rule_dict['meta'],
            'strings': rule_dict['strings'],
            'conditions': rule_dict['conditions'],
            'private': rule_dict['private']  # Add 'private' field
        }

        self.private_rules.append(compiled_private_rule)
        logging.debug(f"Successfully added private rule: {compiled_private_rule['name']}")

class PESignatureEngine:
    def __init__(self):
        logging.info("PESignatureEngine initialized.")
        self.analyzer = PEAnalyzer()
        self.compiler = PESignatureCompiler()
        self.rules = []
        self.private_rules = {}

    def _evaluate_rule(self, rule: dict, features: dict) -> dict:
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

                matches['confidence_scores']['strings'] = len(
                    matches['strings']) / total_strings if total_strings > 0 else 0
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
                    score * weights.get(category, 0)
                    for category, score in matches['confidence_scores'].items()
                )

                matches['overall_confidence'] = round(overall_confidence, 2)
                logging.debug(f"Overall confidence: {matches['overall_confidence']}")

            logging.debug(f"Final matches: {matches}")
            return matches

        except Exception as e:
            logging.error(f"Error in _evaluate_rule: {e}")
            return {}

    def load_rules(self, rules_file: str) -> None:
        """Load rules including private rules from a JSON file."""
        try:
            with open(rules_file, 'r') as f:
                rules_data = json.load(f)

            if isinstance(rules_data, list):
                for i, rule in enumerate(rules_data):
                    if 'rule' not in rule:
                        rule['rule'] = f"rule_{i}"
                    if rule.get('private', False):
                        self.compiler.add_private_rule(rule)
                    else:
                        self.compiler.add_rule(rule)
            elif isinstance(rules_data, dict):
                if 'rule' not in rules_data:
                    rules_data['rule'] = "rule_0"
                if rules_data.get('private', False):
                    self.compiler.add_private_rule(rules_data)
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
            # Analyze the PE file using the analyzer
            features = self.analyzer.analyze_pe(file_path)
            if not features:
                logging.error(f"Failed to analyze file: {file_path}")
                return matches

            # Evaluate each rule
            for rule in self.compiler.rules:
                try:
                    rule_name = rule.get('name', 'unknown')  # Get rule name from the compiled rule

                    # Evaluate rule match result for the current file
                    match_result = self._evaluate_rule(rule, features)

                    if match_result:  # If we have matches
                        match_info = {
                            'rule': rule_name,
                            'meta': rule.get('meta', {}),
                            'strings': match_result.get('strings', []),
                            'imports': match_result.get('imports', []),
                            'sections': match_result.get('sections', []),
                            'conditions_met': match_result.get('conditions_met', []),
                            'overall_confidence': match_result.get('overall_confidence', 0.0)
                        }

                        matches.append(match_info)
                        logging.debug(f"Rule '{rule_name}' matched with confidence {match_info['overall_confidence']}")

                except Exception as e:
                    logging.error(f"Error evaluating rule {rule.get('name', 'unknown')} for file {file_path}: {e}")
                    continue

            return matches

        except Exception as e:
            logging.error(f"Error scanning file {file_path}: {e}")
            return matches

    def calculate_overall_confidence(self, rule: dict, match_result: dict) -> float:
        """Calculate overall confidence based on matched conditions."""
        try:
            # Extract confidence scores from match_result
            confidence_scores = match_result.get('confidence_scores', {})
            string_confidence = confidence_scores.get('strings', 0.0)
            import_confidence = confidence_scores.get('imports', 0.0)
            section_confidence = confidence_scores.get('sections', 0.0)
            condition_confidence = confidence_scores.get('conditions', 0.0)

            # Compute overall confidence by averaging individual scores
            total_confidence = (string_confidence + import_confidence + section_confidence + condition_confidence) / 4

            # Log the confidence values
            logging.debug(f"String Confidence: {string_confidence}")
            logging.debug(f"Import Confidence: {import_confidence}")
            logging.debug(f"Section Confidence: {section_confidence}")
            logging.debug(f"Condition Confidence: {condition_confidence}")
            logging.debug(f"Calculated Overall Confidence: {total_confidence}")

            return total_confidence
        except KeyError as e:
            logging.error(f"Missing confidence score key: {e}")
            return 0.0

def log_match_details(match, min_confidence):
    """Logs detailed information about a match."""
    # Calculate overall confidence if not present
    if 'overall_confidence' not in match and 'confidence_scores' in match:
        engine = PESignatureEngine()
        match['overall_confidence'] = engine.calculate_overall_confidence({}, match)
    elif 'overall_confidence' not in match and 'confidence' in match:
        match['overall_confidence'] = match['confidence']
    else:
        match['overall_confidence'] = 0.0

    # Initialize empty confidence scores if not present
    if 'confidence_scores' not in match:
        match['confidence_scores'] = {
            'strings': 0.0,
            'imports': 0.0,
            'sections': 0.0,
            'conditions': 0.0
        }

    # Log all confidence scores first
    logging.info(f"\nMatch Details for Rule: {match['rule']}")
    logging.info("Confidence Scores:")

    confidence_scores = match['confidence_scores']
    logging.info(f"  Strings Confidence: {confidence_scores.get('strings', 0.0):.4f}")
    logging.info(f"  Imports Confidence: {confidence_scores.get('imports', 0.0):.4f}")
    logging.info(f"  Sections Confidence: {confidence_scores.get('sections', 0.0):.4f}")
    logging.info(f"  Conditions Confidence: {confidence_scores.get('conditions', 0.0):.4f}")
    logging.info(f"  Overall Confidence: {match['overall_confidence']:.4f}")
    logging.info(f"  Classification: {match.get('classification', 'unknown')}")

    # Log matched strings
    if match.get("strings"):
        logging.info("\nMatched Strings:")
        for string_match in match["strings"]:
            logging.info(f"  Pattern: {string_match['pattern']} | Matched: {string_match['matched']}")

    # Log matched imports
    if match.get("imports"):
        logging.info("\nMatched Imports:")
        for import_match in match["imports"]:
            logging.info(
                f"  DLL: {import_match['dll']} | Import: {import_match['import']} | Address: {import_match.get('address')}")

    # Log matched sections
    if match.get("sections"):
        logging.info("\nMatched Sections:")
        for section_match in match["sections"]:
            logging.info(
                f"  Section: {section_match['name']} | Match Quality: {section_match.get('match_quality', 0):.4f}")

    # Log conditions met
    if match.get("conditions_met"):
        logging.info("\nConditions Met:")
        for condition in match["conditions_met"]:
            logging.info(f"  {condition}")

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
    parser.add_argument('--verbose', action='store_true', help="Enable verbose logging for debugging")

    # Parse arguments
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    if args.action == 'scan':
        if not args.file or not os.path.exists(args.file):
            logging.error("A valid file path or directory must be specified for the scan action.")
            sys.exit(1)

        signature_engine = PESignatureEngine()

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

            # Compare features with training data
            features = signature_engine.analyzer.analyze_pe(file_path)
            match_found = False
            file_class = 'unknown'  # Default classification

            if features and training_data:
                for entry in training_data:
                    headers_match = entry.get('headers')
                    sections_match = entry.get('sections')
                    entropy_match = entry.get('entropy')

                    # Compare these fields with the current file's features
                    if headers_match and features.get('headers') == headers_match:
                        matches.append({'rule': 'Training Match', 'label': entry['label'], 'confidence': 1.0})
                        match_found = True
                        file_class = 'clean' if entry['label'] == 0 else 'malware'
                    elif sections_match and features.get('sections') == sections_match:
                        matches.append({'rule': 'Training Match', 'label': entry['label'], 'confidence': 1.0})
                        match_found = True
                        file_class = 'clean' if entry['label'] == 0 else 'malware'
                    elif entropy_match and features.get('entropy') == entropy_match:
                        matches.append({'rule': 'Training Match', 'label': entry['label'], 'confidence': 1.0})
                        match_found = True
                        file_class = 'clean' if entry['label'] == 0 else 'malware'

            # If no match found, classify as unknown
            if not match_found:
                file_class = 'unknown'

            # Increment appropriate classification counters
            if file_class == 'clean':
                files_clean += 1
            elif file_class == 'malware':
                files_malware += 1
            else:
                files_unknown += 1

            logging.info(f"File: {file_path} classified as {file_class}")

            # Now check the threshold for the matches
            # Log all matches regardless of classification
            if matches:
                for match in matches:
                    log_match_details(match, args.min_confidence)

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
        for file_path in tqdm(clean_files + malware_files, desc="Constructing training samples", unit="file"):
            features = pe_analyzer.analyze_pe(file_path)
            if features:
                # Determine classification: clean or malware
                if file_path in clean_files:
                    classification = "clean"  # Clean file
                    label = 0  # Clean files get label 0
                    strings_to_add = clean_strings  # Add only clean strings
                elif file_path in malware_files:
                    classification = "malware"  # Malware file
                    label = 1  # Malware files get label 1
                    strings_to_add = malware_strings  # Add only malware strings
                else:
                    classification = "unknown"  # Unknown file
                    label = -1  # Unknown label

                # Append strings relevant to classification
                extracted_strings = features.get("strings", [])
                meaningful_strings = [
                    {
                        "type": string["type"],
                        "value": string["value"],
                        "offset": string["offset"],
                        "size": string["size"]
                    }
                    for string in extracted_strings
                    if string["value"] in strings_to_add  # Only include strings that are unique to this category
                       and len(string["value"]) >= 4  # Ensure the string has at least 4 characters
                       and filter_meaningful_words(word_tokenize(string["value"]))  # Apply NLTK filtering
                ]

                # Construct the signature for the current file
                signature = {
                    "file_name": os.path.basename(file_path),
                    "file_path": file_path,
                    "headers": features["headers"],
                    "sections": features["sections"],  # Keeping the section info
                    "entropy": features["entropy"],
                    "imports": features["imports"],
                    "strings": meaningful_strings,  # Add only unique strings
                    "label": label,
                    "classification": classification  # Add classification info
                }

                # Append the signature to the training data
                training_data.append(signature)

        logging.info(f"Feature extraction complete. Total training samples: {len(training_data)}")

        # Save training data to JSON file
        training_data_path = "training_data.json"
        with open(training_data_path, "w") as f:
            json.dump(training_data, f, indent=4)

        logging.info(f"Training data saved to {training_data_path}.")

if __name__ == "__main__":
    main()
