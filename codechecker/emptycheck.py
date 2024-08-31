def find_non_empty_looking_empty_lines(file_path):
    non_empty_looking_lines = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for i, line in enumerate(file, start=1):
                stripped_line = line.strip()
                if stripped_line == '':
                    # Line contains only whitespace or is completely empty
                    if line.strip() == '':
                        # Ignore completely empty lines
                        continue
                    non_empty_looking_lines.append(i)
    except Exception as e:
        print(f"Error reading file: {e}")

    if non_empty_looking_lines:
        print(f"Lines that appear empty but contain only whitespace or similar: {non_empty_looking_lines}")
    else:
        print("No lines with only whitespace or similar content found.")

# Example usage
file_path = 'antivirus.py'
find_non_empty_looking_empty_lines(file_path)
