# Read from the file whitelist.txt
with open('whitelist.txt', 'r') as f:
    lines = f.readlines()

# Append a dot to each domain and write to DomainsUpdated.txt
with open('DomainsUpdated.txt', 'w') as f:
    for line in lines:
        domain = line.strip()  # Remove any leading/trailing whitespace
        if domain:  # Process non-empty lines
            modified_domain = f".{domain}\n"  # Prepend dot to the domain and add newline
            f.write(modified_domain)

print("DomainsUpdated.txt file created.")