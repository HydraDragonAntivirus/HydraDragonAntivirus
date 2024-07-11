# Open and read Domains.txt file
with open('Domains.txt', 'r') as file:
    lines = file.readlines()

# Filter lines starting with '#' and keep other lines
problematic_lines = [line for line in lines if line.startswith('#')]
remaining_lines = [line for line in lines if not line.startswith('#')]

# Write problematic lines to problematicwebsites.txt
with open('problematicwebsites.txt', 'w') as file:
    file.writelines(problematic_lines)

# Write remaining lines back to Domains.txt
with open('Domains.txt', 'w') as file:
    file.writelines(remaining_lines)