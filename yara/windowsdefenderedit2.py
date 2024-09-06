def remove_leading_spaces(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        lines = file.readlines()

    # Remove leading spaces from each line
    cleaned_lines = [line.lstrip() for line in lines]

    # Write the cleaned lines back to the file with UTF-8 encoding
    with open(file_path, 'w', encoding='utf-8') as file:
        file.writelines(cleaned_lines)

# Specify the path to the WindowsDefenderEdited.yar file
file_path = 'WindowsDefenderEdited.yar'
remove_leading_spaces(file_path)
