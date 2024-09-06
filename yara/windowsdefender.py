def clean_yar_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    cleaned_lines = []
    for line in lines:
        # Remove empty lines and lines starting with spaces
        if line.strip() == "" or line.lstrip().startswith(" "):
            continue
        
        # For lines starting with "rule" and ending with "{", move "{" to the next line
        if line.strip().startswith("rule") and line.strip().endswith("{"):
            cleaned_lines.append(line.strip()[:-1] + "\n")  # Remove "{" and add the line
            cleaned_lines.append("{\n")  # Add "{" on a new line
        else:
            cleaned_lines.append(line)

    with open(file_path, 'w', encoding='utf-8') as file:
        file.writelines(cleaned_lines)

# Clean the WindowsDefender.yar file
clean_yar_file("WindowsDefender.yar")
