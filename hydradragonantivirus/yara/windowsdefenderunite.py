import os
import yara

def clean_rule(rule):
    # Remove leading # and modify 'rule _#' to 'rule _'
    if rule.startswith('#'):
        rule = rule[1:].strip()  # Remove the leading #
    return rule.replace('rule _#', 'rule _')  # Replace 'rule _#' with 'rule _'

def compile_yara_rules(folder):
    valid_rules = []
    broken_rules = []

    for dirpath, _, filenames in os.walk(folder):
        for filename in filenames:
            rule_path = os.path.join(dirpath, filename)
            try:
                with open(rule_path, 'r+', encoding='utf-8') as rule_file:
                    content = rule_file.readlines()
                    cleaned_content = [clean_rule(line) for line in content]

                    # Write cleaned content back to the same file
                    rule_file.seek(0)  # Move the cursor to the start of the file
                    rule_file.writelines(cleaned_content)
                    rule_file.truncate()  # Remove any leftover content

                # Compile the Yara rule
                yara.compile(filepath=rule_path)
                valid_rules.append(''.join(cleaned_content))
            except Exception:
                with open(rule_path, 'r', encoding='utf-8') as rule_file:
                    broken_rules.append(rule_file.read())

    with open('WindowsDefender.yar', 'w', encoding='utf-8') as valid_file:
        for rule in valid_rules:
            valid_file.write(rule + '\n')

    with open('WindowsDefenderBroken.yar', 'w', encoding='utf-8') as broken_file:
        for rule in broken_rules:
            broken_file.write(rule + '\n')

compile_yara_rules('DefenderYara')
