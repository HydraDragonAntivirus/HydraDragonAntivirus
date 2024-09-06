# Define the input and output file names
input_file = 'WindowsDefender.yar'
output_file = 'output.yar'

# Open the input file and read the lines with UTF-8 encoding
with open(input_file, 'r', encoding='utf-8') as infile:
    lines = infile.readlines()

# Process the lines
filtered_lines = []
buffer = ""

for line in lines:
    line = line.rstrip()  # Remove trailing whitespace
    if line.startswith(' '):
        continue  # Skip lines starting with white spaces

    if line.startswith('rule') and line.endswith('{'):
        if buffer:
            filtered_lines.append(buffer + '\n')
        buffer = line[:-1]  # Remove the last character and buffer the line
    else:
        if buffer:
            filtered_lines.append(buffer + '\n')
            buffer = ""
        filtered_lines.append(line + '\n')

# If there's any buffered line left, append it
if buffer:
    filtered_lines.append(buffer + '\n')

# Write the processed lines to the output file with UTF-8 encoding
with open(output_file, 'w', encoding='utf-8') as outfile:
    outfile.writelines(filtered_lines)

print(f'Processed lines have been saved to {output_file}')
