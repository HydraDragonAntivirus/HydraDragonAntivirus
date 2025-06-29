# Open and read the ALLOW_CIDR4.txt file
with open('ALLOW_CIDR4.txt', 'r') as file:
    lines = file.readlines()

# Remove the /8 part from the CIDR notation
modified_lines = [line.split('/')[0] + '\n' for line in lines]

# Write the modified lines back to the file
with open('ALLOW_CIDR4.txt', 'w') as file:
    file.writelines(modified_lines)

print("File successfully updated.")