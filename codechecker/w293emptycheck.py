def clean_whitespace_only_lines(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        cleaned_lines = []
        for line in lines:
            # If the line has only whitespace (but not already just '\n'), replace with a true empty line
            if line != '\n' and line.strip() == '':
                cleaned_lines.append('\n')
            else:
                cleaned_lines.append(line)

        with open(file_path, 'w', encoding='utf-8') as file:
            file.writelines(cleaned_lines)

        print("Whitespace-only lines converted to empty lines.")
    except Exception as e:
        print(f"Error cleaning file: {e}")

# Example usage
file_path = 'antivirus.py'
clean_whitespace_only_lines(file_path)
