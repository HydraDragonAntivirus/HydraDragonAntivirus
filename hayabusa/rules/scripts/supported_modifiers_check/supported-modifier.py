import argparse
import os
import glob
import re
import datetime
import logging
import time
from pathlib import Path

import ruamel.yaml
import pandas as pd
from collections import Counter

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def extract_keys_recursive(d) -> list[str]:
    keys = []
    for k, v in d.items():
        if '|' in k:
            k = re.sub(r'^.*?\|', '', k)
            keys.append(k)
        if isinstance(v, dict):
            keys.extend(extract_keys_recursive(v))
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, dict):
                    keys.extend(extract_keys_recursive(item))
    return keys


def count_modifiers(counter: Counter, check_strings:list[str]) -> Counter:
    for key in check_strings:
        if not any(key in s for s in counter.keys()):
            counter[key] = 0
    return counter


def process_file(file: str, yml_detection_keys: list[str], yml_correlation_keys: list[str]):
    with open(file, 'r') as f:
        contents = ruamel.yaml.YAML().load_all(f)
        for content in contents:
            if content.get('logsource', {}).get('product') == 'windows':
                if content.get('ruletype', "") == "Sigma":
                    continue
                else:
                    yml_detection_keys.extend(extract_keys_recursive(content.get('detection', {})))
            elif 'correlation' in content:
                cor_type = content['correlation']['type']
                if 'group-by' in content['correlation']:
                    yml_correlation_keys.append(cor_type + " (with group-by)")
                else:
                    yml_correlation_keys.append(cor_type)

def get_yml_detection_counts(dir_path: str) -> (Counter, Counter):
    logging.info(f'Starting to process YAML files in directory: {dir_path}')
    yml_files = glob.glob(os.path.join(dir_path, '**', '*.yml'), recursive=True)
    yml_files = [file for file in yml_files if '/tests' not in file]
    yml_detection_keys = []
    yml_correlation_keys = []
    for file in yml_files:
        process_file(file, yml_detection_keys, yml_correlation_keys)
    logging.info('Finished processing YAML files')

    sigma_modifiers = [
        'all', 'startswith', 'endswith', 'contains', 'exists', 'cased', "contains|cased", "startswith|cased", "endswith|cased", 'windash', 're', 're|i', 're|m', 're|s',
        'base64', 'base64|contains','base64offset', 'utf16le|base64offset|contains', 'utf16be|base64offset|contains', 'utf16|base64offset|contains', 'wide|base64offset|contains',
        'lt', 'lte', 'gt', 'gte', 'cidr', 'expand', 'fieldref', 'fieldref|startswith', 'fieldref|contains','fieldref|endswith', 'equalsfield', 'endswithfield'
    ]
    sigma_correlations = [
        "value_count", "value_count (with group-by)", "event_count", "event_count (with group-by)",
        "temporal", "temporal (with group-by)", "temporal_ordered", "temporal_ordered (with group-by)"
    ]
    mod = count_modifiers(Counter(sorted(yml_detection_keys)), sigma_modifiers)
    cor = count_modifiers(Counter(sorted(yml_correlation_keys)), sigma_correlations)
    return mod, cor

def categorize_modifiers(sigma_key_counter, hayabusa_key_counter, hayabusa_supported):
    supported = []
    unsupported = []
    for k, v in sigma_key_counter.items():
        modifiers = [x for x in str(k).split('|') if x]
        supported_modifier = all(map(lambda x: True if x in hayabusa_supported else False, modifiers))
        supported_modifier = "Yes" if supported_modifier else "No"
        supported_modifier = "Yes" if k in hayabusa_supported else supported_modifier
        hayabusa_count = hayabusa_key_counter.get(k, 0)
        res = [k.strip('|').replace('|', 'ǀ'), v, hayabusa_count]
        if supported_modifier == "Yes":
            supported.append(res)
        else:
            unsupported.append(res)
    return supported, unsupported


if __name__ == '__main__':
    start_time = time.time()
    logging.info(f'Starting script execution: {os.path.basename(__file__)}')
    parser = argparse.ArgumentParser(description='Process Sigma YAML files and generate a markdown report.')
    parser.add_argument('sigma_path', type=str, help='Directory containing Sigma YAML files')
    parser.add_argument('hayabusa_path', type=str, help='Directory containing Hayabusa YAML files')
    parser.add_argument('out_path', type=str, help='Path to save the generated markdown file')
    args = parser.parse_args()

    sigma_mod_counter, sigma_col_counter = get_yml_detection_counts(args.sigma_path)
    hayabusa_mod_counter, hayabusa_col_counter = get_yml_detection_counts(args.hayabusa_path)

    hayabusa_supported_modifiers = {"all", "base64", "base64offset", "contains", "cidr", "windash", "endswith", "expand", "startswith", "re", "exists", "cased", "re", "re|i", "re|m", "re|s" , 'equalsfield', 'endswithfield', 'fieldref', 'gt', 'gte', 'lt', 'lte', 'utf16', 'utf16be', 'utf16le', 'wide'}
    mod_supported, mod_unsupported = categorize_modifiers(sigma_mod_counter, hayabusa_mod_counter, hayabusa_supported_modifiers)

    hayabusa_supported_modifiers = {"event_count", "event_count (with group-by)", "value_count", "value_count (with group-by)", "temporal", "temporal (with group-by)", "temporal_ordered", "temporal_ordered (with group-by)"}
    col_supported, col_unsupported = categorize_modifiers(sigma_col_counter, hayabusa_col_counter, hayabusa_supported_modifiers)

    markdown_str = "# Hayabusa supported field modifiers\n"
    markdown_str = markdown_str + pd.DataFrame(sorted(mod_supported), columns=["Field Modifier", "Sigma Count", "Hayabusa Count"]).to_markdown(index=False)
    markdown_str = markdown_str + "\n\n# Hayabusa unsupported field modifiers\n"
    if mod_unsupported:
        markdown_str = markdown_str + pd.DataFrame(sorted(mod_unsupported), columns=["Field Modifier", "Sigma Count", "Hayabusa Count"]).to_markdown(index=False)
    else:
        markdown_str = markdown_str + "Currently, everything is supported.\n"

    markdown_str = markdown_str + "\n\n# Hayabusa supported correlation rules\n"
    markdown_str = markdown_str + pd.DataFrame(sorted(col_supported), columns=["Correlation Rule", "Sigma Count", "Hayabusa Count"]).to_markdown(index=False)
    markdown_str = markdown_str + "\n\n# Hayabusa unsupported correlations rules\n"
    if col_unsupported:
        markdown_str = markdown_str + pd.DataFrame(sorted(col_unsupported), columns=["Correlation Rule", "Sigma Count", "Hayabusa Count"]).to_markdown(index=False)
    else:
        markdown_str = markdown_str + "Currently, everything is supported.\n"

    markdown_str = markdown_str + "\n\nThis document is being dynamically updated based on the latest rules.  \n"
    current_markdown = Path(args.out_path)
    if current_markdown.exists():
        current_str = current_markdown.read_text(encoding='utf-8')
        current_str = re.sub(r"Last Update:.*", "", current_str, flags=re.DOTALL).strip()
        if current_str == markdown_str.strip():
            logging.info("No changes detected in the report. Skipping file write.")
        else:
            markdown_str = f"{markdown_str}Last Update: {datetime.datetime.now().strftime('%Y/%m/%d')}  \nAuthor: Fukusuke Takahashi"
            Path(args.out_path).write_text(markdown_str)
            logging.info(f'Markdown report generated and saved to {args.out_path}')
    end_time = time.time()
    execution_time = end_time - start_time
    logging.info(f'Script execution completed in {execution_time:.2f} seconds')
