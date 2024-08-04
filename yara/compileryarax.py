import yara_x

def compile_yara_rule(rule_path):
    try:
        with open(rule_path, 'r', encoding='utf-8') as f:
            rule = f.read()
        compiled_rule = yara_x.compile(rule)
        return compiled_rule
    except FileNotFoundError:
        print(f"Error: Rule file '{rule_path}' not found.")
        return None
    except yara_x.CompileError as e:
        print("Error compiling YARA rule: ", e)
        return None

def save_compiled_rule(compiled_rule, output_path):
    try:
        with open(output_path, 'wb') as f:
            compiled_rule.serialize_into(f)
        print(f"Compiled rule saved to '{output_path}'")
    except Exception as e:
        print("Error saving compiled rule: ", e)

def main():
    rule_path = "yaraxtr.yar"
    output_path = "yaraxtr.yrc"

    compiled_rule = compile_yara_rule(rule_path)
    if compiled_rule is None:
        print("Error: YARA rule compilation failed.")
        return

    save_compiled_rule(compiled_rule, output_path)
    print("YARA rule compiled and saved successfully.")

if __name__ == "__main__":
    main()