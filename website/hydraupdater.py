def merge_unique_domains(file1, file2, output_file):
    # Read domains from both files into sets to ensure uniqueness
    with open(file1, 'r') as f1, open(file2, 'r') as f2:
        domains1 = set(f1.read().splitlines())
        domains2 = set(f2.read().splitlines())
    
    # Merge the sets to get unique entries
    unique_domains = domains1.union(domains2)
    
    # Write the unique domains to the output file
    with open(output_file, 'w') as out:
        for domain in sorted(unique_domains):
            out.write(domain + '\n')
    
    print(f"Unique domains merged into {output_file}")

# Specify the input and output file names
file1 = 'BLOCK_DOMAIN.txt'
file2 = 'Domains.txt'
output_file = 'Domains_pro.txt'

# Call the function to merge domains
merge_unique_domains(file1, file2, output_file)