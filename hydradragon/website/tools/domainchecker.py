import re  # Import the regular expression module

# File names
input_file = 'Domains.txt'
output_file_filtered = 'DomainsUpdated.txt'
output_file_big_char = 'BigCharacter.txt'

# Open and read Domains.txt
with open(input_file, 'r') as file:
    lines = file.readlines()

# Filter and separate lines based on presence of uppercase letters
filtered_lines = [line for line in lines if not re.search(r'[A-Z]', line)]  # Lines without uppercase letters
big_char_lines = [line for line in lines if re.search(r'[A-Z]', line)]      # Lines with uppercase letters

# Write to DomainsUpdated.txt for lines without uppercase letters
with open(output_file_filtered, 'w') as file:
    file.writelines(filtered_lines)

# Write to BigCharacter.txt for lines with uppercase letters
with open(output_file_big_char, 'w') as file:
    file.writelines(big_char_lines)

print("Lines containing uppercase letters have been written to BigCharacter.txt, lines without uppercase letters have been written to DomainsUpdated.txt.")