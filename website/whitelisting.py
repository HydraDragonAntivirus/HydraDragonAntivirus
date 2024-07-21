import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def process_domain(domain, whitelist_set):
    """
    Process a domain to determine if it ends with or exactly matches any domain in the whitelist.
    """
    for whitelist_domain in whitelist_set:
        if domain == whitelist_domain:
            return domain, True
        if whitelist_domain.startswith('.'):
            if domain.endswith(whitelist_domain):
                return domain, True
    return domain, False

def filter_domains(domains_file, whitelist_file, output_file, exact_output_file, batch_size=1000, max_workers=10):
    """
    Filter domains in Domains.txt based on endswith or exact matches in whitelister.txt.
    Write matched and unmatched domains to separate files.
    """
    with open(whitelist_file, 'r') as f:
        whitelist = {line.strip() for line in f}

    progress_counter = 0
    progress_lock = threading.Lock()

    def print_progress(total_domains):
        nonlocal progress_counter
        with progress_lock:
            progress_counter += 1
            if progress_counter % 1000 == 0 or progress_counter == total_domains:
                percentage = (progress_counter / total_domains) * 100
                print(f"Processed: {progress_counter}/{total_domains} ({percentage:.2f}%)")

    def process_batch(batch):
        with open(output_file, 'a') as filtered_file, open(exact_output_file, 'a') as matched_file:
            for domain in batch:
                domain, is_matched = process_domain(domain, whitelist)
                if is_matched:
                    matched_file.write(domain + "\n")
                else:
                    filtered_file.write(domain + "\n")
                print_progress(total_domains)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        with open(domains_file, 'r') as f:
            domains = [line.strip() for line in f]

        total_domains = len(domains)

        for i in range(0, total_domains, batch_size):
            batch = domains[i:i + batch_size]
            futures.append(executor.submit(process_batch, batch))

        for future in as_completed(futures):
            future.result()  # Handle any exceptions

# File names
domains_file = 'Domains.txt'
whitelist_file = 'whitelister.txt'
output_file = 'whitelist.txt'
exact_output_file = 'newwhitelist.txt'

# Ensure output files are empty before starting
open(output_file, 'w').close()
open(exact_output_file, 'w').close()

# Filter domains
filter_domains(domains_file, whitelist_file, output_file, exact_output_file)