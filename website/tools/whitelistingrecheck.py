import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import os

def process_domain(domain, whitelist_set):
    """
    Process a domain to determine if it ends with or exactly matches any domain in the whitelist.
    """
    for whitelist_domain in whitelist_set:
        if domain.endswith(whitelist_domain) or domain == whitelist_domain:
            return domain, True
    return domain, False

def filter_domains(domains_file, whitelist_file, output_file, exact_output_file):
    """
    Filter domains in Domains.txt based on endswith or exact matches in whitelister.txt.
    Write matched and unmatched domains to separate files.
    """
    with open(whitelist_file, 'r') as f:
        whitelist = {line.strip() for line in f}

    filtered_domains = []
    matched_domains = []
    progress_counter = 0

    def print_progress(total_domains):
        nonlocal progress_counter
        with threading.Lock():
            progress_counter += 1
            if progress_counter % 1000 == 0 or progress_counter == total_domains:
                percentage = (progress_counter / total_domains) * 100
                print(f"Processed: {progress_counter}/{total_domains} ({percentage:.2f}%)")

    with ThreadPoolExecutor(max_workers=os.cpu_count() * 2) as executor:
        futures = []
        with open(domains_file, 'r') as f:
            domains = [line.strip() for line in f]

        total_domains = len(domains)

        for domain in domains:
            future = executor.submit(process_domain, domain, whitelist)
            future.add_done_callback(lambda p: print_progress(total_domains))
            futures.append(future)

        for future in as_completed(futures):
            domain, is_matched = future.result()
            if is_matched:
                matched_domains.append(domain)
            else:
                filtered_domains.append(domain)

    with open(output_file, 'w') as f:
        f.write("\n".join(filtered_domains) + "\n")

    with open(exact_output_file, 'w') as f:
        f.write("\n".join(matched_domains) + "\n")

# File names
domains_file = 'newwhitelistverybig.txt'
whitelist_file = 'whitelister.txt'
output_file = 'whitelistverynew.txt'
exact_output_file = 'verynewwhitelist.txt'

# Filter domains
filter_domains(domains_file, whitelist_file, output_file, exact_output_file)