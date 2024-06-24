import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

def is_exact_match(domain, whitelist_set):
    """
    Check if a given domain exactly matches any domain in the whitelist.
    """
    domain = domain.lstrip('.')
    return domain in whitelist_set

def is_subdomain_match(domain, whitelist_set):
    """
    Check if a given domain is a subdomain of any domain in the whitelist.
    """
    domain = domain.lstrip('.')
    for whitelist_domain in whitelist_set:
        if domain.endswith("." + whitelist_domain):
            return True
    return False

def process_domain(domain, whitelist_set):
    """
    Check a given domain against the whitelist and return the result.
    """
    if is_exact_match(domain, whitelist_set) or is_subdomain_match(domain, whitelist_set):
        return domain, True
    else:
        return domain, False

def filter_domains(domains_file, whitelist_file, output_file, exact_output_file, max_workers=4):
    """
    Filter domains in Domains.txt based on domains in whitelister.txt.
    Write exact or subdomain matches to newwhitelist.txt and others to whitelist.txt.
    """
    with open(whitelist_file, 'r') as f:
        whitelist = {line.strip().lstrip('.') for line in f}

    filtered_domains = []
    matched_domains = []
    progress_lock = threading.Lock()
    processed_count = 0

    def print_progress():
        nonlocal processed_count
        with progress_lock:
            processed_count += 1
            if processed_count % 100 == 0 or processed_count == total_domains:
                percentage = (processed_count / total_domains) * 100
                print(f"Processed: {processed_count}/{total_domains} ({percentage:.2f}%)")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        with open(domains_file, 'r') as f:
            domains = [line.strip() for line in f]
        
        total_domains = len(domains)

        for domain in domains:
            future = executor.submit(process_domain, domain, whitelist)
            future.add_done_callback(lambda p: print_progress())
            futures.append(future)

        for future in as_completed(futures):
            domain, is_matched = future.result()
            if is_matched:
                matched_domains.append(domain)
            else:
                filtered_domains.append(domain)

    with open(output_file, 'w') as f:
        for domain in filtered_domains:
            f.write(domain + '\n')

    with open(exact_output_file, 'w') as f:
        for domain in matched_domains:
            f.write(domain + '\n')

# File names
domains_file = 'Domains.txt'
whitelist_file = 'whitelister.txt'
output_file = 'whitelist.txt'
exact_output_file = 'newwhitelist.txt'

# Filter domains
filter_domains(domains_file, whitelist_file, output_file, exact_output_file, max_workers=8)