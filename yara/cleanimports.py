def process_file(input_file_path, output_file_path):
    # Define the lines to exclude
    lines_to_exclude = {
        'import "pe"',
        'import "hash"',
        'import "elf"',
        'import "console"',
        'import "dotnet"',
        'import "math"'
    }

    with open(input_file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # Keep only lines that are not in the lines_to_exclude set
    filtered_lines = [line for line in lines if line.strip() not in lines_to_exclude]

    with open(output_file_path, 'w', encoding='utf-8') as file:
        file.writelines(filtered_lines)

# Example usage
input_file_path = 'compiled_rule.yar'  # Specify the path to your input file
output_file_path = 'compiled_rule_output.yar'  # Specify the path to your output file
process_file(input_file_path, output_file_path)