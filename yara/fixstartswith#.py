import re

def remove_hash_from_words(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()

    # Remove the # symbol from words starting with #
    updated_content = re.sub(r'\b#(\w+)', r'\1', content)

    # Write the updated content back to the file
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(updated_content)

# Specify the path to the WindowsDefender.yar file
file_path = 'WindowsDefender.yar'
remove_hash_from_words(file_path)
