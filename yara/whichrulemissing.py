import re

def extract_rule_names(file_path):
    """
    Extracts rule names from the file by matching the word that follows the keyword "rule" 
    or "private rule". Returns a list of rule names.
    """
    rule_names = []
    # Regular expression to match lines starting with either "rule" or "private rule"
    # followed by the rule name (e.g., private rule RULE_NAME { ... or rule RULE_NAME { ...)
    regex = re.compile(r'\b(?:private\s+)?rule\s+([^\s{]+)', re.IGNORECASE)
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            match = regex.search(line)
            if match:
                rule_name = match.group(1)
                rule_names.append(rule_name)
    return rule_names

def compare_rules(new_file, old_file):
    """
    Extracts rule names from the new_file, compares them with the rule names in the old_file,
    and returns a list of rules that are missing in the old_file.
    """
    new_rules = extract_rule_names(new_file)
    old_rules = extract_rule_names(old_file)
    
    missing_rules = [rule for rule in new_rules if rule not in old_rules]
    return missing_rules

if __name__ == '__main__':
    new_file = 'compiled_rule.yar'
    old_file = 'veryoldcompiled_rule.yar'
    
    missing = compare_rules(new_file, old_file)
    
    if missing:
        print("The following rules are not found in veryoldcompiled_rule.yar:")
        for rule in missing:
            print(" -", rule)
    else:
        print("All rules are present in both files.")
