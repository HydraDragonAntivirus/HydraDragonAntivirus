# ALLOW_DOMAIN_output.txt dosyasını oku
with open('ALLOW_DOMAIN_output.txt', 'r') as file:
    allow_domains = set(file.read().splitlines())

# Domains_output.txt dosyasını oku
with open('Domains_output.txt', 'r') as file:
    known_domains = set(file.read().splitlines())

# Domains.txt dosyasını oku
with open('Domains.txt', 'r') as file:
    all_domains = set(file.read().splitlines())

# ALLOW_DOMAIN_output.txt ve Domains_output.txt dosyalarında olmayan
unknown_domains = all_domains - (allow_domains | known_domains)

# Domains_unknown.txt dosyasına yaz
with open('Domains_unknown.txt', 'w') as file:
    for domain in unknown_domains:
        file.write(f"{domain}\n")