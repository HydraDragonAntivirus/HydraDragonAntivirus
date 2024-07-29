import re

def remove_leading_spaces_from_words(text):
    # Replace leading spaces before each word with an empty string
    # This regex matches leading spaces followed by a word character
    cleaned_text = re.sub(r'(?<=\s)\s+', '', text)
    return cleaned_text

def process_file(input_file_path, output_file_path):
    # Read the content from the input file
    with open(input_file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    
    # Process the content to remove leading spaces from words
    processed_content = remove_leading_spaces_from_words(content)
    
    # Write the processed content to the output file
    with open(output_file_path, 'w', encoding='utf-8') as file:
        file.write(processed_content)

# Example usage
input_file_path = 'intezer.yar'  # Specify the path to your input file
output_file_path = 'cleaned_intzer.yar'  # Specify the path to your output file
process_file(input_file_path, output_file_path)