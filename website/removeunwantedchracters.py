def filter_domains(input_file, output_file, unwanted_file):
    with open(input_file, 'r') as infile, open(output_file, 'w') as outfile, open(unwanted_file, 'w') as unwantedfile:
        for line in infile:
            domain = line.strip()
            if not domain.startswith("["):
                outfile.write(domain + '\n')
            else:
                unwantedfile.write(domain + '\n')

input_file = 'Domains.txt'
output_file = 'Domains_Updated.txt'
unwanted_file = 'Unwantedomains.txt'

filter_domains(input_file, output_file, unwanted_file)

print(f"Filtered domains saved to {output_file} and unwanted domains saved to {unwanted_file}.")