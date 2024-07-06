import re

def extract_yara_strings(yara_file, excluded_rules_path, output_file):
    try:
        with open(excluded_rules_path, "r", encoding='latin-1') as file:
            excluded_rules_content = file.read()
        print("YARA Excluded Rules Definitions loaded!")
        print("Excluded rules:", excluded_rules_content)
    except FileNotFoundError:
        print(f"Excluded rules file '{excluded_rules_path}' not found. Exiting...")
        return

    rule_pattern = re.compile(r'rule\s+(\w+)\s*\{([\s\S]+?)\}', re.MULTILINE)
    string_pattern = re.compile(r'\$[a-zA-Z0-9_]+\s*=\s*"([^"]+)"')
    condition_pattern = re.compile(r'condition:\s*(.*?)\s*\n\s*any\s+of\s+them', re.IGNORECASE)

    try:
        with open(yara_file, 'r', encoding='latin-1') as f:
            yara_content = f.read()
        print(f"Reading YARA file '{yara_file}'...")
    except FileNotFoundError:
        print(f"YARA file '{yara_file}' not found. Exiting...")
        return

    matches = rule_pattern.findall(yara_content)
    print(f"Found {len(matches)} rules in the YARA file.")

    strings_to_write = []

    for rule_name, rule_content in matches:
        if rule_name in excluded_rules_content:
            print(f"Rule '{rule_name}' is excluded. Skipping...")
            continue

        condition_match = condition_pattern.search(rule_content)
        if condition_match:
            print(f"Rule '{rule_name}' contains 'condition:' followed by 'any of them'. Extracting strings...")
            strings_found = string_pattern.findall(rule_content)
            if strings_found:
                print(f"Found strings: {strings_found}")
                strings_to_write.append((rule_name, strings_found))  # Store rule name with strings
            else:
                print(f"No strings found in rule '{rule_name}'.")
        else:
            print(f"Rule '{rule_name}' does not meet the criteria. Skipping...")

    if strings_to_write:
        try:
            with open(output_file, 'w', encoding='latin-1') as f:
                for rule_name, strings_found in strings_to_write:
                    f.write(f"Rule '{rule_name}':\n")
                    for string in strings_found:
                        f.write(f'"{string}",\n')
                    f.write("\n")
            print(f"Extraction complete. Output saved to '{output_file}'.")
        except IOError:
            print(f"Failed to write to output file '{output_file}'. Exiting...")
    else:
        print("No strings found or no valid output. Exiting...")

yara_file = 'compiled_rule.yar'
excluded_rules_path = 'excluded_rules.txt'
output_file = 'yarastrings.txt'

extract_yara_strings(yara_file, excluded_rules_path, output_file)