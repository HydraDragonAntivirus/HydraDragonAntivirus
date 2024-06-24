from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

def is_exact_match(domain, whitelist_set):
    """
    Check if a given domain exactly matches any domain in the whitelist.
    """
    # Remove leading dot from the domain if it exists
    if domain.startswith('.'):
        domain = domain[1:]

    # Check for exact match or if the domain ends with a whitelist domain
    for whitelist_domain in whitelist_set:
        if domain == whitelist_domain or domain.endswith("." + whitelist_domain):
            return True
    return False

def is_subdomain_match(domain, whitelist_set):
    """
    Check if a given domain is a subdomain of any domain in the whitelist.
    """
    # Remove leading dot from the domain if it exists
    if domain.startswith('.'):
        domain = domain[1:]

    # Check if the domain is a subdomain of any whitelist domain
    for whitelist_domain in whitelist_set:
        if domain.endswith("." + whitelist_domain) and len(domain) > len(whitelist_domain):
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
    # Read whitelist file and convert to set
    with open(whitelist_file, 'r') as f:
        whitelist = {line.strip().lstrip('.') for line in f}

    # Count total number of domains
    with open(domains_file, 'r') as f:
        total_domains = sum(1 for _ in f)

    # Lists to hold filtered and matched domains
    filtered_domains = []
    matched_domains = []
    processed_count = 0

    # Lock to track the number of processed domains
    progress_lock = threading.Lock()

    def print_progress():
        """
        Function to print progress.
        """
        with progress_lock:
            nonlocal processed_count
            processed_count += 1
            percentage = (processed_count / total_domains) * 100
            if processed_count % 100 == 0 or processed_count == total_domains:
                print(f"Processed: {processed_count}/{total_domains} ({percentage:.2f}%)")

    # Use ThreadPoolExecutor to process domains in parallel
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        with open(domains_file, 'r') as f:
            for domain in f:
                domain = domain.strip()
                future = executor.submit(process_domain, domain, whitelist)
                future.add_done_callback(lambda p: print_progress())
                futures.append(future)

        for future in as_completed(futures):
            domain, is_matched = future.result()
            if is_matched:
                matched_domains.append(domain)
            else:
                filtered_domains.append(domain)

    # Write filtered domains to output file
    with open(output_file, 'w') as f:
        for domain in filtered_domains:
            f.write(domain + '\n')

    # Write exact or subdomain matches to exact output file
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