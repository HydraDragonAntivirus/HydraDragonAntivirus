import json
import re
import logging
import os
import subprocess
import numpy as np
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum, auto
import pefile
import sys
import argparse

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

class RuleType(Enum):
    STRING_MATCH = auto()
    SECTION_PATTERN = auto()
    IMPORT_CHECK = auto()
    ENTROPY_CHECK = auto()
    RESOURCE_CHECK = auto()
    IAT_PATTERN = auto()
    SIZE_CHECK = auto()
    CUSTOM = auto()

@dataclass
class PEFeatures:
    sections: Dict[str, Dict]
    imports: Dict[str, List[str]]
    exports: List[str]
    resources: List[Dict]
    strings: List[Dict]
    entropy_values: Dict[str, float]
    iat: Dict[str, int]
    size_info: Dict[str, int]
    characteristics: Dict[str, int]

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
        logging.debug("Adding rule.")
        try:
            compiled_rule = self._compile_rule(rule_content)
            self.rules.append(compiled_rule)
        except Exception as e:
            logging.error(f"Error compiling rule: {e}")

    def _compile_rule(self, rule_content: str) -> Dict:
        logging.debug("Compiling rule.")
        lines = rule_content.strip().split('\n')
        rule_dict = {
            'meta': {},
            'strings': {},
            'conditions': []
        }

        current_section = None
        for line in lines:
            line = line.strip()

            # Remove sideway comments (everything after #)
            if '#' in line:
                line = line.split('#', 1)[0].strip()

            # Skip empty lines after removing comments
            if not line:
                continue

            if line.startswith('rule '):
                rule_dict['name'] = line[5:].strip()
            elif line == 'meta:':
                current_section = 'meta'
            elif line == 'strings:':
                current_section = 'strings'
            elif line == 'condition:':
                current_section = 'condition'
            elif current_section == 'meta':
                key, value = line.split('=', 1)
                rule_dict['meta'][key.strip()] = value.strip().strip('"')
            elif current_section == 'strings':
                if '=' in line:
                    name, pattern = line.split('=', 1)
                    rule_dict['strings'][name.strip()] = pattern.strip().strip('"')
            elif current_section == 'condition':
                rule_dict['conditions'].append(line)

        logging.debug(f"Compiled rule: {rule_dict}")
        return rule_dict

    def save_rules(self, output_file: str) -> None:
        """Save the compiled rules to a file."""
        logging.debug(f"Saving rules to {output_file}")
        try:
            with open(output_file, 'w') as f:
                json.dump(self.rules, f, indent=2)
            logging.info(f"Successfully saved {len(self.rules)} rules to {output_file}")
        except Exception as e:
            logging.error(f"Error saving rules to {output_file}: {e}")

    def load_rules(self, input_file: str) -> None:
        """Load compiled rules from a file."""
        logging.debug(f"Loading rules from {input_file}")
        try:
            with open(input_file, 'r') as f:
                self.rules = json.load(f)
            logging.info(f"Successfully loaded {len(self.rules)} rules from {input_file}")
            logging.debug(f"Loaded rules: {self.rules}")  # Debugging loaded rules
        except Exception as e:
            logging.error(f"Error loading rules from {input_file}: {e}")
            raise

class PESignatureEngine:
    def __init__(self):
        logging.info("PESignatureEngine initialized.")
        self.analyzer = PEAnalyzer()  # Now using PEAnalyzer only
        self.compiler = PESignatureCompiler()

    def load_rules(self, rules_file: str) -> None:
        logging.debug(f"Loading rules from {rules_file}")
        try:
            self.compiler.load_rules(rules_file)
        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")
            raise

    def _evaluate_rule(self, rule: Dict, features: Dict) -> Optional[Dict]:
        """
        Evaluate a rule against PE file features.

        Args:
            rule (Dict): Rule dictionary containing strings and conditions
            features (Dict): Extracted PE file features

        Returns:
            Optional[Dict]: Dictionary of matches if rule conditions are met, None otherwise
        """
        try:
            if not all(isinstance(x, dict) for x in [rule, features]):
                logging.error("Invalid input types for rule evaluation")
                return None

            # Build matches dictionary for string patterns
            matches = {}
            for imp in features.get('imports', []):
                if not isinstance(imp, dict):
                    continue

                dll_name = imp.get('dll_name', '').lower()
                imports_list = imp.get('imports', [])

                if not isinstance(imports_list, list):
                    continue

                for imp_detail in imports_list:
                    if not isinstance(imp_detail, dict):
                        continue

                    imp_name = imp_detail.get('name', '')
                    if not imp_name:
                        continue

                    # Check each string pattern against the import
                    for pattern_id, pattern in rule.get('strings', {}).items():
                        if pattern.lower() in imp_name.lower():
                            if pattern_id not in matches:
                                matches[pattern_id] = []
                            matches[pattern_id].append({
                                'dll': dll_name,
                                'import': imp_name,
                                'address': imp_detail.get('address'),
                                'ordinal': imp_detail.get('ordinal')
                            })

            # Evaluate each condition
            all_conditions_met = True
            matched_conditions = []

            for condition in rule.get('conditions', []):
                if not isinstance(condition, str):
                    continue

                condition = condition.strip().lower()

                # Handle entropy conditions
                if condition.startswith('entropy.'):
                    try:
                        parts = condition.split()
                        if len(parts) != 3:
                            continue

                        threshold = float(parts[2])
                        if parts[0] == 'entropy.full':
                            actual = features.get('entropy', {}).get('full', 0)
                            comparison = actual >= threshold
                        else:
                            continue

                        if not comparison:
                            all_conditions_met = False
                            break
                        matched_conditions.append(condition)
                    except (ValueError, TypeError):
                        continue

                # Handle section entropy conditions
                elif condition.startswith('sections['):
                    try:
                        section_name = condition[9:].split(']')[0].strip('"')
                        parts = condition.split()
                        if len(parts) != 3:
                            continue

                        threshold = float(parts[2])
                        section_entropy = features.get('entropy', {}).get('sections', {}).get(section_name, 0)

                        if section_entropy < threshold:
                            all_conditions_met = False
                            break
                        matched_conditions.append(condition)
                    except (ValueError, TypeError, IndexError):
                        continue

                # Handle import conditions
                elif condition.startswith('any of import'):
                    try:
                        # Extract DLL name and API names
                        import_str = condition[13:-1]  # Remove 'any of import(' and ')'
                        parts = [p.strip().strip('"') for p in import_str.split(',')]

                        if not parts:
                            continue

                        dll_name = parts[0].lower()
                        api_patterns = parts[1:]

                        # Check if any of the specified APIs are imported from the DLL
                        found_match = False
                        for imp in features.get('imports', []):
                            if not isinstance(imp, dict):
                                continue

                            if imp.get('dll_name', '').lower() == dll_name:
                                for api_pattern in api_patterns:
                                    for imp_detail in imp.get('imports', []):
                                        if not isinstance(imp_detail, dict):
                                            continue

                                        imp_name = imp_detail.get('name', '').lower()
                                        if api_pattern.lower() in imp_name:
                                            found_match = True
                                            break
                                    if found_match:
                                        break
                            if found_match:
                                break

                        if not found_match:
                            all_conditions_met = False
                            break
                        matched_conditions.append(condition)
                    except Exception as e:
                        logging.error(f"Error evaluating import condition: {e}")
                        continue

                # Handle IAT conditions
                elif 'iat[' in condition:
                    try:
                        api_name = condition.split('[')[1].split(']')[0].strip('"')
                        parts = condition.split()
                        if len(parts) != 3:
                            continue

                        threshold = int(parts[2])
                        iat_count = len([imp for imp in features.get('imports', [])
                                         if any(detail.get('name') == api_name
                                                for detail in imp.get('imports', []))])

                        if iat_count <= threshold:
                            all_conditions_met = False
                            break
                        matched_conditions.append(condition)
                    except (ValueError, TypeError, IndexError):
                        continue

            if all_conditions_met and matched_conditions:
                return {
                    'matches': matches,
                    'matched_conditions': matched_conditions
                }

            return None

        except Exception as e:
            logging.error(f"Error evaluating rule: {e}")
            return None

    def scan_file(self, file_path: str) -> List[Dict]:
        logging.debug(f"Scanning file: {file_path}")
        matches = []

        try:
            # Get features from the analyzer
            features = self.analyzer.analyze_pe(file_path)
            if not features:
                logging.error(f"Failed to analyze file: {file_path}")
                return matches

            logging.debug(f"Analyzed features: {features}")

            # Process each rule
            for rule in self.compiler.rules:
                try:
                    match_result = self._evaluate_rule(rule, features)
                    if match_result:
                        match_info = {
                            'rule': rule['name'],
                            'meta': rule['meta'],
                            'matches': match_result
                        }
                        matches.append(match_info)
                except Exception as e:
                    logging.error(f"Error evaluating rule {rule['name']} for file {file_path}: {e}")

        except Exception as e:
            logging.error(f"Error scanning file: {e}")

        logging.debug(f"Matches found: {matches}")
        return matches

    def _evaluate_conditions(self, conditions: List[str], features: Dict, matches: Dict) -> bool:
        for condition in conditions:
            try:
                tokens = condition.split()
                if not tokens:
                    continue

                # Check entropy conditions
                if 'entropy' in condition.lower():
                    section_name = tokens[0]
                    min_entropy = float(tokens[2])

                    if section_name == 'file':
                        if features.get('entropy', {}).get('full', 0) <= min_entropy:
                            return False
                    else:
                        section_entropy = features.get('entropy', {}).get('sections', {}).get(section_name, 0)
                        if section_entropy <= min_entropy:
                            return False

                # Check import conditions
                elif 'import' in condition.lower():
                    import_name = condition.split('"')[1]
                    if not any(import_name in dll_imports for dll_imports in features.get('imports', [])):
                        return False

                # Check section conditions
                elif 'section' in condition.lower():
                    section_name = condition.split('"')[1]
                    if section_name not in features.get('sections', {}):
                        return False

                # Check size conditions
                elif 'size' in condition.lower():
                    size_type = tokens[0].split('.')[0]
                    min_size = int(tokens[2])
                    if features.get('size_info', {}).get(size_type, 0) <= min_size:
                        return False
            except ValueError as e:
                logging.error(f"Error parsing condition '{condition}': {e}")
            except Exception as e:
                logging.error(f"Error evaluating condition '{condition}': {e}")
                continue

        return True

    def classify_severity(self, matches: List[Dict]) -> str:
        """Classify the severity of the file based on the match results."""
        if not matches:
            return "Clean"

        max_severity = 0
        for match in matches:
            if 'severity' in match['meta']:
                try:
                    severity = int(match['meta']['severity'])
                    max_severity = max(max_severity, severity)
                except ValueError:
                    continue

        if max_severity == 0:
            return "Clean"
        elif max_severity <= 40:
            return "Suspicious (Low)"
        elif max_severity <= 70:
            return "Suspicious (High)"
        else:
            return "Malicious"

def main():
    """Main entry point for PE signature scanning."""
    # Set up argument parser
    parser = argparse.ArgumentParser(description="PE Signature Compiler and Analyzer")
    parser.add_argument('action', choices=['compile', 'scan'], help="Action to perform: compile rules or scan file")
    parser.add_argument('--rules', type=str, help="Path to the rules file")
    parser.add_argument('--file', type=str, help="Path to the PE file or directory to scan")
    parser.add_argument('--output', type=str, help="Path to save compiled rules (only for compile action)")

    # Parse arguments
    args = parser.parse_args()

    if args.action == 'compile':
        if not args.rules or not args.output:
            logging.error("Both --rules and --output must be specified for compile action.")
            sys.exit(1)

        # Compile signatures from rule file
        try:
            compiler = PESignatureCompiler()
            with open(args.rules, 'r') as rule_file:
                rules_content = rule_file.read()
                compiler.add_rule(rules_content)
            compiler.save_rules(args.output)
            logging.info(f"Compiled rules saved to {args.output}")
        except Exception as e:
            logging.error(f"Error compiling rules: {e}")
            sys.exit(1)

    elif args.action == 'scan':
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

            # Check if it's a directory or a single file
            if os.path.isdir(args.file):
                logging.info(f"Scanning all files in directory: {args.file}")
                for root, _, files in os.walk(args.file):
                    for file in files:
                        file_path = os.path.join(root, file)
                        logging.info(f"Scanning file: {file_path}")
                        matches = signature_engine.scan_file(file_path)
                        if matches:
                            logging.info(f"File {file_path} matches the following rules:")
                            for match in matches:
                                logging.info(f"Rule: {match['rule']}")
                                for match_type, match_data in match.items():
                                    if match_type != 'rule':
                                        logging.info(f"  {match_type}: {match_data}")
                        else:
                            logging.info(f"No matches found for {file_path}. File is clean.")
            else:
                # Scan a single file
                logging.info(f"Scanning file: {args.file}")
                matches = signature_engine.scan_file(args.file)
                if matches:
                    logging.info(f"File {args.file} matches the following rules:")
                    for match in matches:
                        logging.info(f"Rule: {match['rule']}")
                        for match_type, match_data in match.items():
                            if match_type != 'rule':
                                logging.info(f"  {match_type}: {match_data}")
                else:
                    logging.info(f"No matches found for {args.file}. File is clean.")
        except Exception as e:
            logging.error(f"Error scanning file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()