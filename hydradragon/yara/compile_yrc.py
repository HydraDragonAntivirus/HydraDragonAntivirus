import yara

def compile_yara_rule(input_file, output_file):
    # Compile the YARA rule
    rules = yara.compile(filepath=input_file)
    
    # Save the compiled rule to a .yrc file
    with open(output_file, 'wb') as f:
        rules.save(file=f)

# Usage
input_yara_file = 'clean_rules.yar'
output_yrc_file = 'clean_rules.yrc'
compile_yara_rule(input_yara_file, output_yrc_file)

print(f"{input_yara_file} has been successfully compiled to {output_yrc_file}.")