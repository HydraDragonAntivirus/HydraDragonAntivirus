with open('Unwantedomains.txt', 'r') as f:
    lines = f.readlines()

modified_domains = []
for line in lines:
    domain = line.strip().strip('[]')  # Remove square brackets and strip whitespace
    if domain:
        modified_domains.append(f".{domain}")

with open('DomainsUpdated.txt', 'w') as f:
    for domain in modified_domains:
        f.write(domain + '\n')

print("DomainsUpdated.txt file created.")