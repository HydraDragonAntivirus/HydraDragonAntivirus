import json

def convert_domains_to_text():
    # Define the file paths
    domains_json_file = "domains.json"
    phishing_domains_file = "phishing_domains.txt"
    
    # Load the JSON file
    with open(domains_json_file, "r", encoding="utf-8") as file:
        domains = json.load(file)

    # Check if the domains are in a list format
    if isinstance(domains, list):
        # Write the domains to phishing_domains.txt
        with open(phishing_domains_file, "w", encoding="utf-8") as file:
            for domain in domains:
                file.write(f"{domain}\n")

        print(f"Domains have been written to {phishing_domains_file}.")
    else:
        print("Error: The content in domains.json is not a list.")

if __name__ == "__main__":
    convert_domains_to_text()
