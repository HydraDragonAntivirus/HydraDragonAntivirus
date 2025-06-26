def remove_duplicates(input_file, output_file):
    # Set to store unique lines
    unique_lines = set()
    
    # Read lines from the input file and add to the set
    with open(input_file, 'r') as file:
        for line in file:
            unique_lines.add(line)
    
    # Write the unique lines to the output file
    with open(output_file, 'w') as file:
        for line in unique_lines:
            file.write(line)

# Example usage
input_file = 'newwhitelist.txt'
output_file = 'newwhitelist_output.txt'
remove_duplicates(input_file, output_file)