import json
import re
import logging
import math
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
            'raw_data_size': len(raw_data) if raw_data else 0,
            'raw_data': raw_data
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

    def extract_features(self, file_path: str, rank: Optional[int] = None) -> Optional[Dict[str, Any]]:
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
                
                'sections': [self.extract_section_data(section) for section in pe.sections],
                'imports': self.extract_imports(pe),
                'exports': self.extract_exports(pe),
                
                'resources': [],
                'debug_info': []
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
            logging.error(f"Error extracting features from {file_path}: {str(e)}")
            return None

class PEAnalyzer:
    def __init__(self):
        logging.info("PEAnalyzer initialized.")
        self.feature_extractor = PEFeatureExtractor()
    
    def _calculate_entropy(self, data: bytes) -> float:
        logging.debug("Calculating entropy.")
        if not data:
            return 0.0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(x)) / len(data)
            if p_x > 0:
                entropy += -p_x * math.log2(p_x)
        logging.debug(f"Calculated entropy: {entropy}")
        return entropy

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        logging.debug("Extracting strings from data.")
        strings = []

        ascii_pattern = f'[\x20-\x7e]{{{min_length},}}'
        for match in re.finditer(ascii_pattern.encode(), data):
            strings.append({
                'type': 'ascii',
                'value': match.group().decode('ascii'),
                'offset': match.start(),
                'size': len(match.group())
            })

        unicode_pattern = f'(?:[\x20-\x7e]\x00){{{min_length},}}'
        for match in re.finditer(unicode_pattern.encode(), data):
            try:
                strings.append({
                    'type': 'unicode',
                    'value': match.group().decode('utf-16le'),
                    'offset': match.start(),
                    'size': len(match.group())
                })
            except UnicodeDecodeError:
                continue

        logging.debug(f"Extracted {len(strings)} strings.")
        return strings

    def _analyze_with_die(self, file_path: str) -> Optional[Dict[str, Any]]:
        logging.debug(f"Analyzing file {file_path} with DIE.")
        try:
            if not os.path.exists(detectiteasy_console_path):
                raise FileNotFoundError(f"DIE executable not found at {detectiteasy_console_path}")

            result = subprocess.run(
                [detectiteasy_console_path, file_path, "/json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.returncode != 0:
                logging.error(f"DIE analysis failed: {result.stderr.strip()}")
                return None

            die_output = result.stdout.strip()
            logging.debug("DIE analysis completed successfully.")
            return json.loads(die_output)

        except Exception as e:
            logging.error(f"Error during DIE analysis for {file_path}: {e}")
            return None

    def analyze_pe(self, file_path: str) -> Optional[PEFeatures]:
        logging.debug(f"Starting analysis for file: {file_path}")
        try:
            # Use feature extractor for basic features
            features = self.feature_extractor.extract_features(file_path)
            if not features:
                return None

            # Additional analysis with DIE
            die_analysis = self._analyze_with_die(file_path)

            # Read file for string extraction
            with open(file_path, 'rb') as f:
                file_data = f.read()

            # Combine all features into PEFeatures format
            pe_features = PEFeatures(
                sections={section['name']: {
                    'virtual_address': section['virtual_address'],
                    'virtual_size': section['virtual_size'],
                    'raw_size': section['raw_size'],
                    'characteristics': section['characteristics'],
                    'entropy': section['entropy'],
                    'strings': self._extract_strings(section['raw_data'])
                } for section in features['sections']},
                imports={entry['dll_name']: [imp['name'] for imp in entry['imports']] 
                        for entry in features['imports'] if entry['dll_name']},
                exports=[exp['name'] for exp in features['exports'] if exp['name']],
                resources=features['resources'],
                strings=self._extract_strings(file_data),
                entropy_values={
                    'full': self._calculate_entropy(file_data),
                    'sections': {section['name']: section['entropy'] for section in features['sections']}
                },
                iat=self._analyze_iat(file_path),
                size_info={
                    'image_size': features['headers']['optional_header']['size_of_code'],
                    'headers_size': features['headers']['optional_header']['size_of_initialized_data'],
                    'code_size': features['headers']['optional_header']['size_of_code'],
                    'data_size': features['headers']['optional_header']['size_of_initialized_data']
                },
                characteristics={
                    'file_characteristics': features['headers']['file_header']['characteristics'],
                    'dll_characteristics': features['headers']['optional_header']['dll_characteristics'],
                    'subsystem': features['headers']['optional_header']['subsystem'],
                    'die_info': die_analysis if die_analysis else {}
                }
            )
            
            logging.debug(f"Analysis completed for file: {file_path}")
            return pe_features

        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {e}")
            return None

    def _analyze_iat(self, file_path: str) -> Dict[str, int]:
        logging.debug("Analyzing IAT.")
        iat = {}
        try:
            pe = pefile.PE(file_path)
            if hasattr(pe, 'DIRECTORY_ENTRY_IAT'):
                for entry in pe.DIRECTORY_ENTRY_IAT:
                    if entry.name:
                        iat[entry.name.decode()] = entry.struct.FirstThunk
        except Exception as e:
            logging.error(f"Error analyzing IAT: {e}")
        logging.debug(f"Extracted {len(iat)} IAT entries.")
        return iat

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
            logging.debug(f"Saving rules to {output_file}")
            with open(output_file, 'w') as f:
                json.dump(self.rules, f, indent=2)

        def load_rules(self, input_file: str) -> None:
            logging.debug(f"Loading rules from {input_file}")
            with open(input_file, 'r') as f:
                self.rules = json.load(f)

class PESignatureEngine:
    def __init__(self):
        logging.info("PESignatureEngine initialized.")
        self.analyzer = PEAnalyzer()
        self.feature_extractor = PEFeatureExtractor()
        self.compiler = PESignatureCompiler()

    def load_rules(self, rules_file: str) -> None:
        logging.debug(f"Loading rules from {rules_file}")
        try:
            self.compiler.load_rules(rules_file)
        except Exception as e:
            logging.error(f"Error loading rules from {rules_file}: {e}")
            raise

    def scan_file(self, file_path: str) -> List[Dict]:
        logging.debug(f"Scanning file: {file_path}")
        matches = []

        # Get features from both analyzers for comprehensive analysis
        try:
            analyzer_features = self.analyzer.analyze_pe(file_path)
            extractor_features = self.feature_extractor.extract_features(file_path)
        except Exception as e:
            logging.error(f"Error analyzing file {file_path}: {e}")
            return matches  # Early return if analysis fails

        # Debug logs for features
        logging.debug(f"Analyzer features: {analyzer_features}")
        logging.debug(f"Extractor features: {extractor_features}")

        if not analyzer_features or not extractor_features:
            logging.warning(f"File {file_path} analysis failed.")
            return matches

        # Combine features for complete analysis
        try:
            combined_features = self._combine_features(analyzer_features, extractor_features)
        except Exception as e:
            logging.error(f"Error combining features for file {file_path}: {e}")
            return matches

        # Process each rule
        for rule in self.compiler.rules:
            try:
                match_result = self._evaluate_rule(rule, combined_features)
                if match_result:
                    match_info = {
                        'rule': rule['name'],
                        'meta': rule['meta'],
                        'matches': match_result
                    }
                    matches.append(match_info)
            except Exception as e:
                logging.error(f"Error evaluating rule {rule['name']} for file {file_path}: {e}")

        # Log matches
        if matches:
            logging.info(f"File {file_path} matches the following rules:")
            for match in matches:
                logging.info(f"Rule: {match['rule']}")
                for match_type, match_data in match.items():
                    if match_type != 'rule':
                        logging.info(f"  {match_type}: {match_data}")
        else:
            logging.info(f"No matches found for {file_path}. File is clean.")

        # Classify severity
        try:
            severity = self.classify_severity(matches)
            logging.info(f"File {file_path} is classified as: {severity}")
        except Exception as e:
            logging.error(f"Error classifying severity for file {file_path}: {e}")
            severity = "Unknown"

        return matches

    def _combine_features(self, analyzer_features: PEFeatures, extractor_features: Dict) -> PEFeatures:
        """Combine features from both analyzers for comprehensive analysis."""
        try:
            # Start with analyzer features as base
            combined = analyzer_features

            # Add additional information from extractor if not present
            if 'debug_info' in extractor_features:
                combined.characteristics['debug_info'] = extractor_features['debug_info']

            # Merge section information
            for section_name, section_data in extractor_features.get('sections', {}).items():
                if section_name in combined.sections:
                    combined.sections[section_name].update({
                        'pointer_to_raw_data': section_data['pointer_to_raw_data'],
                        'raw_data_size': section_data['raw_data_size']
                    })

            return combined
        except Exception as e:
            logging.error(f"Error combining features: {e}")
            raise

    def _evaluate_rule(self, rule: Dict, features: PEFeatures) -> Optional[Dict]:
        logging.debug(f"Evaluating rule: {rule['name']}")
        matches = {
            'strings': {},
            'sections': {},
            'imports': [],
            'other': []
        }

        # Check string matches
        try:
            for str_name, pattern in rule.get('strings', {}).items():
                found = False
                # Check in sections
                for section_name, section_data in features.sections.items():
                    for string in section_data.get('strings', []):
                        if re.search(pattern.encode(), string['value'].encode()):
                            matches['strings'][str_name] = {
                                'section': section_name,
                                'offset': string['offset'],
                                'value': string['value']
                            }
                            found = True
                            break
                    if found:
                        break

                # Check in full file strings if not found in sections
                if not found:
                    for string in features.strings:
                        if re.search(pattern.encode(), string['value'].encode()):
                            matches['strings'][str_name] = {
                                'section': 'global',
                                'offset': string['offset'],
                                'value': string['value']
                            }
                            break
        except Exception as e:
            logging.error(f"Error checking strings for rule {rule['name']}: {e}")
            raise

        # Check conditions
        try:
            if self._evaluate_conditions(rule.get('conditions', []), features, matches):
                return matches
        except Exception as e:
            logging.error(f"Error evaluating conditions for rule {rule['name']}: {e}")

        return None if not any(matches.values()) else matches

    def _evaluate_conditions(self, conditions: List[str], features: PEFeatures, matches: Dict) -> bool:
        for condition in conditions:
            try:
                # Check entropy conditions
                if 'entropy' in condition.lower():
                    section_name = condition.split()[0]
                    min_entropy = float(condition.split()[2])

                    if section_name == 'file':
                        if features.entropy_values.get('full', 0) <= min_entropy:
                            return False
                    else:
                        section_entropy = features.entropy_values.get('sections', {}).get(section_name, 0)
                        if section_entropy <= min_entropy:
                            return False

                # Check import conditions
                elif 'import' in condition.lower():
                    import_name = condition.split('"')[1]
                    if not any(import_name in dll_imports for dll_imports in features.imports.values()):
                        return False

                # Check section conditions
                elif 'section' in condition.lower():
                    section_name = condition.split('"')[1]
                    if section_name not in features.sections:
                        return False

                # Check size conditions
                elif 'size' in condition.lower():
                    size_type = condition.split('.')[0]
                    min_size = int(condition.split()[2])
                    if features.size_info.get(size_type, 0) <= min_size:
                        return False
            except Exception as e:
                logging.error(f"Error evaluating condition {condition}: {e}")
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
    parser.add_argument('--file', type=str, help="Path to the PE file to scan")
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
            logging.error("A valid file path must be specified for scan action.")
            sys.exit(1)

        # Perform the scanning
        try:
            signature_engine = PESignatureEngine()

            # Load the rules
            if args.rules and os.path.exists(args.rules):
                signature_engine.load_rules(args.rules)
            else:
                logging.warning("No rules file specified or file doesn't exist, using default rules.")

            # Scan the PE file
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