def process_domains(domains_file, whitelist_file, output_file, fullymatch_file):
    # Set to store whitelist domains
    whitelist_domains = set()
    
    # Read whitelist domains from the whitelist file and add to the set
    with open(whitelist_file, 'r') as file:
        for line in file:
            whitelist_domains.add(line.strip().lstrip('.'))
    
    # Read domains from the domains file, remove the leading dot, write to output file if not fully matched,
    # and write to fully match file if fully matched
    with open(domains_file, 'r') as file, \
         open(output_file, 'w') as output, \
         open(fullymatch_file, 'w') as fullymatch:
        
        for line in file:
            domain = line.strip().lstrip('.')
            if domain in whitelist_domains:
                fullymatch.write(line)
            else:
                output.write(line)

# Example usage
domains_file = 'Domains.txt'
whitelist_file = 'whitelister.txt'
output_file = 'Domains_output.txt'
fullymatch_file = 'fullymatch.txt'
process_domains(domains_file, whitelist_file, output_file, fullymatch_file)