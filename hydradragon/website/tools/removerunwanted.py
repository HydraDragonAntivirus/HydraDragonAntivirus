import re  # Import the regular expression module

# File names
input_file = 'Domains.txt'
output_file_filtered = 'DomainsUpdated.txt'
output_file_unwanted = 'ContainsUnWanted.txt'

# Open and read Domains.txt
with open(input_file, 'r') as file:
    lines = file.readlines()

# Filter and separate lines
filtered_lines = [line for line in lines if '/' not in line]  # Lines without '/'
unwanted_lines = [line for line in lines if '/' in line]      # Lines with '/'

# Write to DomainsUpdated.txt for filtered lines
with open(output_file_filtered, 'w') as file:
    file.writelines(filtered_lines)

# Write to ContainsUnWanted.txt for lines with '/'
with open(output_file_unwanted, 'w') as file:
    file.writelines(unwanted_lines)

print("Lines containing '/' have been written to ContainsUnWanted.txt, lines without '/' have been written to DomainsUpdated.txt.")