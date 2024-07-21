def remove_allowed_domains(allowed_file, domains_file, output_file):
    # Set to store allowed domains
    allowed_domains = set()
    
    # Read allowed domains from the allowed file and add to the set
    with open(allowed_file, 'r') as file:
        for line in file:
            allowed_domains.add(line.strip())
    
    # Read domains from the domains file and write to output file if not in allowed domains
    with open(domains_file, 'r') as file, open(output_file, 'w') as output:
        for line in file:
            if line.strip() not in allowed_domains:
                output.write(line)

# Example usage
allowed_file = 'newwhitelist.txt'
domains_file = 'Domains.txt'
output_file = 'Domains_output.txt'
remove_allowed_domains(allowed_file, domains_file, output_file)