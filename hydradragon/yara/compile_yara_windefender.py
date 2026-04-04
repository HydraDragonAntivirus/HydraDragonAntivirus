import yara

def compile_yara_rule(rule_path):
    try:
        compiled_rule = yara.compile(filepath=rule_path)
        return compiled_rule
    except FileNotFoundError:
        print(f"Error: Rule file '{rule_path}' not found.")
        return None
    except yara.SyntaxError as e:
        print("Error compiling YARA rule:", e)
        return None

def save_compiled_rule(compiled_rule, output_path):
    try:
        compiled_rule.save(output_path)
        print(f"Compiled rule saved to '{output_path}'")
    except Exception as e:
        print("Error saving compiled rule:", e)

def main():
    rule_path = "WindowsDefender.yar"
    output_path = "WindowsDefender.yarc"

    compiled_rule = compile_yara_rule(rule_path)
    if compiled_rule is None:
        print("Error: YARA rule compilation failed.")
        return

    save_compiled_rule(compiled_rule, output_path)
    print("YARA rule compiled and saved successfully.")

if __name__ == "__main__":
    main()
