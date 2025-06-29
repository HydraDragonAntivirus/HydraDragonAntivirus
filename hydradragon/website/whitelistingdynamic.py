import time
import concurrent.futures

# Read the files
with open("Domains.txt", "r") as domains_file:
    domains = domains_file.read().splitlines()

with open("ALLOW_DOMAIN.txt", "r") as allow_domain_file:
    allow_domains = allow_domain_file.read().splitlines()

# Select single-dot domains from ALLOW_DOMAIN.txt and add a leading dot
allow_domains = [f".{domain}" for domain in allow_domains if domain.count('.') == 1]

# Function to get the top-level domain
def get_top_level_domain(domain):
    parts = domain.split('.')
    if len(parts) >= 2:
        return f".{parts[-2]}.{parts[-1]}"
    return domain

# Create output files
open("ALLOW_DOMAIN_output.txt", "w").close()
open("Domains_output.txt", "w").close()

# Domain processing function
def process_domains(start_index, end_index):
    for index in range(start_index, end_index):
        domain = domains[index]
        tld = get_top_level_domain(domain)
        if tld in allow_domains:
            with open("ALLOW_DOMAIN_output.txt", "a") as allow_output_file:
                allow_output_file.write(domain + "\n")
        else:
            with open("Domains_output.txt", "a") as domains_output_file:
                domains_output_file.write(domain + "\n")

# Start time
start_time = time.time()

# Process domains
batch_size = 1000
with concurrent.futures.ThreadPoolExecutor() as executor:
    futures = []
    for i in range(0, len(domains), batch_size):
        end_index = min(i + batch_size, len(domains))
        futures.append(executor.submit(process_domains, i, end_index))
    
    for i, future in enumerate(concurrent.futures.as_completed(futures)):
        future.result()
        if (i + 1) % (1000 // batch_size) == 0:
            elapsed_time = time.time() - start_time
            processed_domains = (i + 1) * batch_size
            total_domains = len(domains)
            remaining_domains = total_domains - processed_domains
            avg_time_per_domain = elapsed_time / processed_domains
            remaining_time = avg_time_per_domain * remaining_domains
            remaining_hours = remaining_time / 3600
            
            print(f"{processed_domains} domains processed. Estimated remaining time: {remaining_hours:.2f} hours.")

print("Processing complete.")