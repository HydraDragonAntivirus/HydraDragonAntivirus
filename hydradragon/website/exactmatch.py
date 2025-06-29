def find_exact_match(filename, target):
    with open(filename, 'r') as file:
        for line_number, line in enumerate(file, start=1):
            if line.strip() == target:
                return line_number
    return None

filename = 'Domains.txt'
target = 'com.tr'

line_number = find_exact_match(filename, target)
if line_number:
    print(f'Exact match found at line: {line_number}')
else:
    print('Exact match not found')