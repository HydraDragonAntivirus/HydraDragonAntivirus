#!/usr/bin/env python3
"""
Robust Sigma to OpenHydraDragon (OHD) Rule Converter
Handles malformed YAML, complex detection logic, and generates proper OHD rules.
"""

import sys
import os
import yaml
import re
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Union

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SigmaToOHDConverter:
    """Enhanced Sigma to OHD converter with robust YAML parsing and comprehensive field mapping."""
    
    def __init__(self):
        # Enhanced logsource mapping
        self.logsource_map = {
            ('process_creation', 'windows'): 'process.creation_commandline',
            ('process_creation', 'linux'): 'process.creation_commandline',
            ('file_event', 'windows'): 'file.operation',
            ('file_event', 'linux'): 'file.operation',
            ('network_connection', None): 'network.new_network_events',
            ('network_traffic', None): 'network.new_network_events',
            ('registry_event', 'windows'): 'registry.new_registry_keys',
            ('registry_add', 'windows'): 'registry.new_registry_keys',
            ('registry_set', 'windows'): 'registry.modified_registry_values',
            ('webserver', None): 'network.new_network_events',
            ('dns_query', None): 'network.new_network_events',
            ('windows_eventlog', None): 'eventlog.Application',
        }
        
        # Comprehensive field mapping
        self.field_map = {
            # Process fields
            'CommandLine': 'process.creation_commandline',
            'ProcessCommandLine': 'process.creation_commandline',
            'Image': 'process.image',
            'ProcessImage': 'process.image',
            'ParentImage': 'process.parent_image',
            'ParentProcessImage': 'process.parent_image',
            'ParentCommandLine': 'process.parent_commandline',
            'User': 'process.user',
            'LogonType': 'process.logon_type',
            
            # File fields
            'FileName': 'file.name',
            'FilePath': 'file.path',
            'TargetFilename': 'file.target_filename',
            'SourceFilename': 'file.source_filename',
            
            # Registry fields
            'TargetObject': 'registry.key',
            'Details': 'registry.value',
            'EventType': 'registry.event_type',
            
            # Network fields
            'DestinationHostname': 'network.destination_hostname',
            'DestinationIp': 'network.destination_ip',
            'DestinationPort': 'network.destination_port',
            'SourceIp': 'network.source_ip',
            'SourcePort': 'network.source_port',
            'Protocol': 'network.protocol',
            'c-useragent': 'http.user_agent',
            'c-uri': 'http.uri',
            'cs-host': 'http.host',
            'cs-method': 'http.method',
            
            # Windows Event Log fields
            'EventID': 'eventlog.event_id',
            'Channel': 'eventlog.channel',
            'Provider_Name': 'eventlog.provider',
            'Computer': 'eventlog.computer',
            'Message': 'eventlog.message',
            
            # DNS fields
            'QueryName': 'dns.query_name',
            'QueryType': 'dns.query_type',
            'QueryResults': 'dns.query_results',
        }
        
        # Operator mapping with enhanced support
        self.operator_map = {
            'contains': 'contains',
            'endswith': 'endswith',
            'startswith': 'startswith',
            'all': 'contains',  # Handle 'all' as contains for simplicity
            'eq': 'equals',
            'equals': 'equals',
            're': 'matches',
            'regex': 'matches',
            'base64': 'contains',  # Decode base64 and use contains
            'base64offset': 'contains',
            'utf16': 'contains',
            'utf16le': 'contains',
            'utf16be': 'contains',
            'wide': 'contains',
            'windash': 'contains',
        }

    def clean_yaml_content(self, content: str) -> str:
        """Clean problematic YAML content before parsing."""
        lines = content.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Remove malformed list entries like "- :"
            if re.match(r'^\s*-\s*:\s*$', line):
                logger.debug(f"Skipping malformed line: {line.strip()}")
                continue

            # NEW: Remove malformed list items that look like a key without a value, e.g., "- Signature|startswith:"
            if re.match(r'^\s*-\s*[\w|.-]+\s*:\s*$', line):
                logger.debug(f"Skipping malformed key-only list item: {line.strip()}")
                continue
            
            # Remove empty list items
            if re.match(r'^\s*-\s*$', line):
                logger.debug(f"Skipping empty list item: {line.strip()}")
                continue
            
            # Remove YAML tags that cause issues
            line = re.sub(r'!\w+\s*', '', line)
            
            # Fix common YAML formatting issues
            line = re.sub(r'^\s*-\s*([^:]+):\s*$', r'- \1:', line)
            
            cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    def safe_yaml_loader(self):
        """Create a safe YAML loader that handles unknown tags."""
        class SafeLoaderWithUnknownTags(yaml.SafeLoader):
            pass
        
        def construct_unknown(loader, tag_suffix, node):
            if isinstance(node, yaml.ScalarNode):
                return loader.construct_scalar(node)
            elif isinstance(node, yaml.SequenceNode):
                return loader.construct_sequence(node)
            elif isinstance(node, yaml.MappingNode):
                return loader.construct_mapping(node)
            return None
        
        SafeLoaderWithUnknownTags.add_multi_constructor('!', construct_unknown)
        return SafeLoaderWithUnknownTags

    def load_sigma_rules(self, file_path: str) -> List[Dict[str, Any]]:
        """Load Sigma rules from a YAML file with robust error handling."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Clean the content
            cleaned_content = self.clean_yaml_content(content)
            
            # Try to parse with custom loader
            loader = self.safe_yaml_loader()
            documents = list(yaml.load_all(cleaned_content, Loader=loader))
            
            # Filter out None documents and validate
            valid_documents = []
            for doc in documents:
                if doc and isinstance(doc, dict) and self.is_valid_sigma_rule(doc):
                    valid_documents.append(doc)
            
            logger.info(f"Loaded {len(valid_documents)} valid Sigma rules from {file_path}")
            return valid_documents
            
        except yaml.YAMLError as e:
            logger.error(f"YAML parsing error in {file_path}: {e}")
            # Try alternative parsing method
            return self.fallback_yaml_parse(file_path)
        except Exception as e:
            logger.error(f"Error loading {file_path}: {e}")
            return []

    def fallback_yaml_parse(self, file_path: str) -> List[Dict[str, Any]]:
        """Fallback YAML parsing for severely malformed files."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Split by document separators
            documents = re.split(r'^---\s*$', content, flags=re.MULTILINE)
            parsed_docs = []
            
            for i, doc_content in enumerate(documents):
                if not doc_content.strip():
                    continue
                
                try:
                    # More aggressive cleaning
                    doc_content = self.aggressive_yaml_clean(doc_content)
                    doc = yaml.safe_load(doc_content)
                    if doc and isinstance(doc, dict) and self.is_valid_sigma_rule(doc):
                        parsed_docs.append(doc)
                except Exception as e:
                    logger.debug(f"Skipping document {i} due to parsing error: {e}")
                    continue
            
            logger.info(f"Fallback parser loaded {len(parsed_docs)} rules from {file_path}")
            return parsed_docs
            
        except Exception as e:
            logger.error(f"Fallback parsing also failed for {file_path}: {e}")
            return []

    def aggressive_yaml_clean(self, content: str) -> str:
        """More aggressive YAML cleaning for problematic content."""
        lines = content.split('\n')
        cleaned = []
        in_multiline = False
        
        for line in lines:
            # Skip obviously malformed lines
            if re.match(r'^\s*-\s*:\s*$', line):
                continue
            if re.match(r'^\s*-\s*$', line):
                continue
            
            # Handle multiline strings
            if '|' in line or '>' in line:
                in_multiline = True
            elif in_multiline and not line.startswith(' '):
                in_multiline = False
            
            # Clean the line
            if not in_multiline:
                line = re.sub(r'!\w+\s*', '', line)
                line = re.sub(r'^\s*-\s*([^:]+):\s*$', r'- \1:', line)
            
            cleaned.append(line)
        
        return '\n'.join(cleaned)

    def is_valid_sigma_rule(self, rule: Dict[str, Any]) -> bool:
        """Validate if a dictionary represents a valid Sigma rule."""
        required_fields = ['title', 'detection']
        return all(field in rule for field in required_fields)

    def map_logsource(self, logsource: Dict[str, Any]) -> str:
        """Map Sigma logsource to OHD extraction context."""
        if not isinstance(logsource, dict):
            return 'generic.record'
        
        category = logsource.get('category', '').lower()
        product = logsource.get('product', '').lower()
        service = logsource.get('service', '').lower()
        
        # Try exact match first
        key = (category, product if product else None)
        if key in self.logsource_map:
            return self.logsource_map[key]
        
        # Try category only
        key = (category, None)
        if key in self.logsource_map:
            return self.logsource_map[key]
        
        # Service-based mapping
        if service == 'sysmon':
            return 'process.creation_commandline'
        elif service == 'security':
            return 'eventlog.Security'
        elif service == 'system':
            return 'eventlog.System'
        
        return 'generic.record'

    def parse_detection_logic(self, detection: Dict[str, Any]) -> List[str]:
        """Parse Sigma detection logic and convert to OHD conditions."""
        conditions = []
        
        if not isinstance(detection, dict):
            return conditions
        
        # Handle different detection patterns
        for key, value in detection.items():
            if key == 'condition':
                # Skip the condition logic for now, we'll handle selection blocks
                continue
            elif key.startswith('selection') or key in ['filter', 'keywords']:
                conditions.extend(self.parse_selection_block(key, value))
        
        return conditions

    def parse_selection_block(self, block_name: str, block_content: Any) -> List[str]:
        """Parse a selection block and convert to OHD conditions."""
        conditions = []
        
        if isinstance(block_content, dict):
            for field, values in block_content.items():
                conditions.extend(self.parse_field_condition(field, values))
        elif isinstance(block_content, list):
            # Handle list of conditions
            for item in block_content:
                if isinstance(item, dict):
                    for field, values in item.items():
                        conditions.extend(self.parse_field_condition(field, values))
        
        return conditions

    def parse_field_condition(self, field: str, values: Any) -> List[str]:
        """Parse a field condition and convert to OHD format."""
        conditions = []
        
        # Handle field modifiers
        base_field = field
        operator = 'equals'
        
        if '|' in field:
            parts = field.split('|')
            base_field = parts[0]
            for modifier in parts[1:]:
                if modifier in self.operator_map:
                    operator = self.operator_map[modifier]
                    break
        
        # Map field name
        ohd_field = self.field_map.get(base_field, base_field.lower())
        
        # Convert values to list if not already
        if not isinstance(values, list):
            values = [values]
        
        # Generate conditions
        for value in values:
            if value is None:
                continue
            
            # Handle different value types
            if isinstance(value, dict):
                # Handle complex value structures
                for sub_key, sub_value in value.items():
                    condition = f"        {ohd_field}.{sub_key} {operator} \"{self.escape_value(sub_value)}\""
                    conditions.append(condition)
            else:
                condition = f"        {ohd_field} {operator} \"{self.escape_value(value)}\""
                conditions.append(condition)
        
        return conditions

    def escape_value(self, value: Any) -> str:
        """Escape value for OHD rule format."""
        if isinstance(value, str):
            # Escape quotes and backslashes
            return value.replace('\\', '\\\\').replace('"', '\\"')
        return str(value)

    def generate_rule_name(self, rule: Dict[str, Any]) -> str:
        """Generate a valid OHD rule name from Sigma rule."""
        title = rule.get('title', 'UNKNOWN_RULE')
        # Clean the title to make it a valid identifier
        clean_title = re.sub(r'[^\w\s-]', '', title)
        clean_title = re.sub(r'\s+', '_', clean_title.strip())
        clean_title = clean_title.upper()
        
        # Ensure it's not too long
        if len(clean_title) > 50:
            clean_title = clean_title[:50]
        
        return clean_title or 'SIGMA_RULE'

    def convert_sigma_to_ohd(self, sigma_rule: Dict[str, Any]) -> Optional[str]:
        """Convert a single Sigma rule to OHD format."""
        try:
            # Generate rule name
            rule_name = self.generate_rule_name(sigma_rule)
            
            # Extract metadata
            rule_id = sigma_rule.get('id', rule_name)
            description = sigma_rule.get('description', '').replace('"', '\\"')
            author = sigma_rule.get('author', '')
            date = sigma_rule.get('date', '')
            level = sigma_rule.get('level', '')
            
            # Parse detection logic
            detection = sigma_rule.get('detection', {})
            conditions = self.parse_detection_logic(detection)
            
            if not conditions:
                logger.warning(f"No valid conditions found for rule: {rule_name}")
                return None
            
            # Build OHD rule
            ohd_lines = [f"rule {rule_name}", "{", "    meta:"]
            ohd_lines.append(f'        id = "{rule_id}"')
            
            if description:
                ohd_lines.append(f'        description = "{description}"')
            if author:
                ohd_lines.append(f'        author = "{author}"')
            if date:
                ohd_lines.append(f'        date = "{date}"')
            if level:
                ohd_lines.append(f'        level = "{level}"')
            
            # Add logsource information
            logsource = sigma_rule.get('logsource', {})
            if logsource:
                logsource_context = self.map_logsource(logsource)
                ohd_lines.append(f'        logsource = "{logsource_context}"')
            
            # Add conditions
            ohd_lines.append("")
            ohd_lines.append("    condition:")
            ohd_lines.extend(conditions)
            ohd_lines.append("}")
            
            return "\n".join(ohd_lines)
            
        except Exception as e:
            logger.error(f"Error converting Sigma rule to OHD: {e}")
            return None

    def convert_file(self, input_file: str, output_dir: str) -> int:
        """Convert a Sigma file to OHD rules."""
        sigma_rules = self.load_sigma_rules(input_file)
        converted_count = 0
        
        for sigma_rule in sigma_rules:
            ohd_rule = self.convert_sigma_to_ohd(sigma_rule)
            if ohd_rule:
                # Generate output filename
                rule_name = self.generate_rule_name(sigma_rule)
                rule_id = sigma_rule.get('id', rule_name)
                
                output_file = os.path.join(output_dir, f"{rule_name}.ohd")
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                
                try:
                    with open(output_file, 'w', encoding='utf-8') as f:
                        f.write(ohd_rule)
                    
                    logger.info(f"Converted: {input_file} -> {output_file}")
                    converted_count += 1
                    
                except Exception as e:
                    logger.error(f"Error writing OHD rule to {output_file}: {e}")
        
        return converted_count

    def convert_directory(self, input_dir: str, output_dir: str) -> int:
        """Convert all Sigma files in a directory to OHD rules."""
        total_converted = 0
        
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.lower().endswith(('.yml', '.yaml')):
                    input_file = os.path.join(root, file)
                    
                    # Maintain directory structure in output
                    rel_path = os.path.relpath(root, input_dir)
                    output_subdir = os.path.join(output_dir, rel_path)
                    
                    converted = self.convert_file(input_file, output_subdir)
                    total_converted += converted
        
        return total_converted


def main():
    """Main entry point for the converter."""
    # Check for the correct number of command-line arguments
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <sigma_rules_directory> <ohd_output_directory>")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2]
    
    # --- MODIFIED LOGIC ---
    # Check if the input path is a directory. If not, exit.
    if not os.path.isdir(input_path):
        logger.error(f"Input path '{input_path}' is not a directory. Please provide a directory.")
        sys.exit(1)
        
    # Create the output directory if it doesn't exist
    os.makedirs(output_path, exist_ok=True)
    
    # Initialize and run the converter
    converter = SigmaToOHDConverter()
    
    logger.info(f"Converting directory: {input_path} -> {output_path}")
    total = converter.convert_directory(input_path, output_path)
    logger.info(f"✅ Successfully converted {total} Sigma rules to OHD format.")


if __name__ == "__main__":
    main()