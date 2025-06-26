import re

def find_duplicate_rule_names(file1_path, file2_path):
    # Read the content of both files with UTF-8 encoding
    with open(file1_path, 'r', encoding='utf-8') as file1, open(file2_path, 'r', encoding='utf-8') as file2:
        file1_lines = file1.readlines()
        file2_lines = file2.readlines()

    # Set to store rule names from each file
    file1_rule_names = set()
    file2_rule_names = set()

    # Regular expression to match 'rule' followed by whitespace and a name
    rule_pattern = re.compile(r'^\s*rule\s+(\w+)')

    # Extract rule names from the first file
    for line in file1_lines:
        match = rule_pattern.match(line.strip())
        if match:
            file1_rule_names.add(match.group(1))  # Add the rule name (second word)

    # Extract rule names from the second file
    for line in file2_lines:
        match = rule_pattern.match(line.strip())
        if match:
            file2_rule_names.add(match.group(1))  # Add the rule name (second word)

    # Find duplicate rule names between both files
    duplicate_rule_names = file1_rule_names.intersection(file2_rule_names)

    return duplicate_rule_names

# Example usage
file1_path = 'compiled_rule.yar'  # Path to the first YARA file
file2_path = 'cleaned_united.yar'  # Path to the second YARA file

duplicates = find_duplicate_rule_names(file1_path, file2_path)

# Print duplicate rule names if any
if duplicates:
    print("Duplicate rule names found in both files:")
    for rule_name in duplicates:
        print(rule_name)
else:
    print("No duplicate rule names found between the two files.")
