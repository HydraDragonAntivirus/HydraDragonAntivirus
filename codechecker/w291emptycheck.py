
def fix_trailing_whitespace(file_path):
    fixed_lines = []
    changes_made = False

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

        for i, line in enumerate(lines, start=1):
            stripped = line.rstrip('\n')
            if stripped != stripped.rstrip():
                print(f"Fixing trailing whitespace at line {i}")
                changes_made = True
                stripped = stripped.rstrip()
            fixed_lines.append(stripped + '\n')

        if changes_made:
            with open(file_path, 'w', encoding='utf-8') as file:
                file.writelines(fixed_lines)
            print(f"Trailing whitespace fixed in: {file_path}")
        else:
            print("No trailing whitespace found. File is clean.")

    except Exception as e:
        print(f"Error processing file: {e}")

# Example usage
if __name__ == "__main__":
    file_path = "antivirus.py"  # You can change this to any Python file path
    fix_trailing_whitespace(file_path)
