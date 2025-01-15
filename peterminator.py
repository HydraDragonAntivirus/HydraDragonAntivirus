import hashlib
import json
import re
import logging
import math
import os
import subprocess
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum, auto
import pefile
import logging

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

            # Execute DIE with the provided file path
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

    def _analyze_sections(self, pe: pefile.PE) -> Dict[str, Dict]:
        logging.debug("Analyzing sections.")
        sections = {}
        for section in pe.sections:
            name = section.Name.decode(errors='ignore').rstrip('\x00')
            data = section.get_data()

            sections[name] = {
                'virtual_address': section.VirtualAddress,
                'virtual_size': section.Misc_VirtualSize,
                'raw_size': section.SizeOfRawData,
                'characteristics': section.Characteristics,
                'entropy': self._calculate_entropy(data),
                'md5': hashlib.md5(data).hexdigest(),
                'strings': self._extract_strings(data)
            }
        logging.debug(f"Analyzed {len(sections)} sections.")
        return sections

    def _analyze_imports(self, pe: pefile.PE) -> Dict[str, List[str]]:
        logging.debug("Analyzing imports.")
        imports = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode()
                imports[dll_name] = [
                    imp.name.decode() if imp.name else f'ord_{imp.ordinal}'
                    for imp in entry.imports
                ]
        logging.debug(f"Analyzed {len(imports)} imports.")
        return imports

    def analyze_pe(self, file_path: str) -> Optional[PEFeatures]:
        logging.debug(f"Starting analysis for file: {file_path}")
        try:
            pe = pefile.PE(file_path)
            with open(file_path, 'rb') as f:
                data = f.read()

            features = PEFeatures(
                sections=self._analyze_sections(pe),
                imports=self._analyze_imports(pe),
                exports=self._get_exports(pe),
                resources=self._analyze_resources(pe),
                strings=self._extract_strings(data),
                entropy_values={'full': self._calculate_entropy(data)},
                iat=self._analyze_iat(pe),
                size_info=self._get_size_info(pe),
                characteristics=self._get_characteristics(pe)
            )
            logging.debug(f"Analysis completed for file: {file_path}")
            return features

        except Exception as e:
            logging.error(f"Error analyzing {file_path}: {e}")
            return None

    def _get_exports(self, pe: pefile.PE) -> List[str]:
        logging.debug("Extracting exports.")
        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode())
        logging.debug(f"Extracted {len(exports)} exports.")
        return exports

    def _analyze_resources(self, pe: pefile.PE) -> List[Dict]:
        logging.debug("Analyzing resources.")
        resources = []
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                if hasattr(resource_lang, 'data'):
                                    resources.append({
                                        'type': resource_type.id,
                                        'name': resource_id.id,
                                        'language': resource_lang.id,
                                        'size': resource_lang.data.struct.Size,
                                        'codepage': resource_lang.data.struct.CodePage
                                    })
        logging.debug(f"Extracted {len(resources)} resources.")
        return resources

    def _analyze_iat(self, pe: pefile.PE) -> Dict[str, int]:
        logging.debug("Analyzing IAT.")
        iat = {}
        if hasattr(pe, 'DIRECTORY_ENTRY_IAT'):
            for entry in pe.DIRECTORY_ENTRY_IAT:
                if entry.name:
                    iat[entry.name.decode()] = entry.struct.FirstThunk
        logging.debug(f"Extracted {len(iat)} IAT entries.")
        return iat

    def _get_size_info(self, pe: pefile.PE) -> Dict[str, int]:
        logging.debug("Getting size info.")
        size_info = {
            'image_size': pe.OPTIONAL_HEADER.SizeOfImage,
            'headers_size': pe.OPTIONAL_HEADER.SizeOfHeaders,
            'code_size': pe.OPTIONAL_HEADER.SizeOfCode,
            'data_size': pe.OPTIONAL_HEADER.SizeOfInitializedData
        }
        logging.debug(f"Size info: {size_info}")
        return size_info

    def _get_characteristics(self, pe: pefile.PE) -> Dict[str, int]:
        logging.debug("Getting characteristics.")
        characteristics = {
            'file_characteristics': pe.FILE_HEADER.Characteristics,
            'dll_characteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
            'subsystem': pe.OPTIONAL_HEADER.Subsystem
        }
        logging.debug(f"Characteristics: {characteristics}")
        return characteristics

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
    def __init__(self, analyzer: PEAnalyzer):
        logging.info("PESignatureEngine initialized.")
        self.analyzer = analyzer
        self.compiler = PESignatureCompiler()

    def load_rules(self, rules_file: str) -> None:
        logging.debug(f"Loading rules from {rules_file}")
        self.compiler.load_rules(rules_file)

    def scan_file(self, file_path: str) -> List[Dict]:
        logging.debug(f"Scanning file: {file_path}")
        matches = []
        features = self.analyzer.analyze_pe(file_path)

        if not features:
            logging.warning(f"File {file_path} analysis failed.")
            return matches

        for rule in self.compiler.rules:
            match_result = self._evaluate_rule(rule, features)
            if match_result:
                matches.append({
                    'rule': rule['name'],
                    'meta': rule['meta'],
                    'matches': match_result
                })

        logging.debug(f"Scan completed for file: {file_path}")
        return matches

    def _evaluate_rule(self, rule: Dict, features: PEFeatures) -> Optional[Dict]:
        logging.debug(f"Evaluating rule: {rule['name']}")
        matches = {
            'strings': {},
            'sections': {},
            'imports': [],
            'other': []
        }

        for str_name, pattern in rule['strings'].items():
            found = False
            for section_name, section_data in features.sections.items():
                for string in section_data['strings']:
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

        try:
            if self._evaluate_conditions(rule['conditions'], features, matches):
                return matches
        except Exception as e:
            logging.error(f"Error evaluating conditions: {e}")

        return None

    def _evaluate_conditions(self, conditions: List[str], features: PEFeatures, matches: Dict) -> bool:
        logging.debug("Evaluating conditions.")
        for condition in conditions:
            if 'entropy' in condition.lower():
                section_name = condition.split()[0]
                min_entropy = float(condition.split()[2])
                if section_name not in features.sections:
                    logging.error(f"Section '{section_name}' not found in PE features.")
                    return False
                if features.sections[section_name].get('entropy', 0) < min_entropy:
                    logging.debug(f"Condition failed for entropy in section {section_name}.")
                    return False
        return bool(matches['strings'] or matches['sections'] or matches['imports'])

def example_usage():
    analyzer = PEAnalyzer()
    engine = PESignatureEngine(analyzer)

    rule = """
    rule SuspiciousPE
    meta:
        description = "Detects suspicious PE characteristics"
        author = "Security Analyst"
        severity = "high"
    strings:
        $suspicious_api1 = "VirtualAlloc"
        $suspicious_api2 = "WriteProcessMemory"
        $hex_pattern = { 4D 5A 90 00 }
    condition:
        pe.sections[".text"].entropy > 7.0 and
        ($suspicious_api1 or $suspicious_api2) and
        $hex_pattern
    """

    engine.compiler.add_rule(rule)
    engine.compiler.save_rules("compiled_rules.json")

    results = engine.scan_file("sample.exe")
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    example_usage()
