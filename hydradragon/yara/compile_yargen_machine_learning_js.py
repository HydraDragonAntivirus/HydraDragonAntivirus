from yara_compile_utils import compile_yara_rule_safely

# Usage
input_yara_file = "machine_learning_js.yar"
output_yrc_file = "machine_learning_js.yrc"
rewritten_rules, skipped_rules, skipped_report = compile_yara_rule_safely(input_yara_file, output_yrc_file)

print(f"{input_yara_file} has been successfully compiled to {output_yrc_file}.")
if rewritten_rules:
    print(f"Normalized {rewritten_rules} invalid or duplicate rule identifiers before compilation.")
if skipped_rules:
    print(f"Skipped {skipped_rules} malformed rules while building {output_yrc_file}.")
    if skipped_report is not None:
        print(f"Skipped-rule report written to {skipped_report}.")
