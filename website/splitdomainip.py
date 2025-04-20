import re

def is_ip(line):
    # Check for valid IPv4
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}$', line.strip()) is not None

def split_whitelist_file(input_file, domain_output, ip_output):
    with open(input_file, 'r') as infile:
        lines = infile.readlines()

    domains = []
    ips = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if is_ip(stripped):
            ips.append(stripped)
        else:
            domains.append(stripped)

    with open(domain_output, 'w') as d_out:
        d_out.write('\n'.join(domains))

    with open(ip_output, 'w') as ip_out:
        ip_out.write('\n'.join(ips))

# Usage
split_whitelist_file('WhiteListDomainsIPs.txt', 'BenignDomains.txt', 'BenignIPs.txt')
