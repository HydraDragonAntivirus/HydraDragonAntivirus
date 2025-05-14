def find_trailing_whitespace_lines(file_path):
    trailing_ws_lines = []

    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            for i, line in enumerate(file, start=1):
                if line.rstrip('\n') != line.rstrip():
                    trailing_ws_lines.append(i)

    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if trailing_ws_lines:
        print(f"W291 Warning - Trailing whitespace found on lines: {trailing_ws_lines}")
    else:
        print("No trailing whitespace found (W291 check passed).")

# Example usage
if __name__ == "__main__":
    file_path = "antivirus.py"  # Change if needed
    find_trailing_whitespace_lines(file_path)
