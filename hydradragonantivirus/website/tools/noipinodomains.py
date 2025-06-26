import re

def extract_and_remove_ip_addresses(input_file, output_ip_file, output_domains_file):
    with open(input_file, 'r') as file:
        data = file.read()

    # Use a regex pattern to find IP addresses
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ip_addresses = ip_pattern.findall(data)
    
    # Remove IP addresses from the text
    data_without_ips = ip_pattern.sub('', data)

    # Save extracted IP addresses to output_ip_file
    with open(output_ip_file, 'w') as ip_file:
        for ip in ip_addresses:
            ip_file.write(ip + '\n')

    # Save the text without IP addresses to output_domains_file
    with open(output_domains_file, 'w') as domains_file:
        domains_file.write(data_without_ips)

    return ip_addresses, data_without_ips

# File paths
input_file_path = 'Domains.txt'
output_ip_file_path = 'traship.txt'
output_domains_file_path = 'Domains_output.txt'

# Extract IP addresses and save to files
ip_addresses, data_without_ips = extract_and_remove_ip_addresses(input_file_path, output_ip_file_path, output_domains_file_path)

print(f'IP addresses have been saved to {output_ip_file_path}.')
print(f'IP addresses have been removed from Domains.txt, and the remaining content has been saved to {output_domains_file_path}.')