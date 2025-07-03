# Open and read the flake8 results file
with open('flake8results.txt', 'r') as file:
    lines = file.readlines()

# Filter lines that are from antivirus.py and contain ': f'
filtered = [line for line in lines if 'antivirus.py' in line and ': f' in line]

# Print the filtered lines
for line in filtered:
    print(line, end='')
