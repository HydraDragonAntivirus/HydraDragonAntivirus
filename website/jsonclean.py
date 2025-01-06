import json

# Define the input and output file paths
input_file = 'phishing_domains.txt'
output_file = 'phishing_domains_clean.txt'

# Open and read the JSON data from the file, specifying the encoding (use 'utf-8' or 'latin-1' based on your file)
with open(input_file, 'r', encoding='utf-8') as file:
    data = json.load(file)

# Extract the 'data' part which contains the list of domains
domains = data.get('data', [])

# Write the list of domains to a new file
with open(output_file, 'w', encoding='utf-8') as output:
    for domain in domains:
        output.write(f"{domain}\n")

print(f"Domains extracted and saved to {output_file}")
