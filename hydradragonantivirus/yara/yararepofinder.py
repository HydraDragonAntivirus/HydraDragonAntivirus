import re

def extract_github_urls_from_file(filename):
    unique_urls = set()
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            content = f.read()
            # Use findall to search the entire file content for GitHub URLs.
            # This regex finds urls that start with http or https and contain "github.com"
            urls = re.findall(r'https?://(?:[\w\-]+\.)*github\.com\S*', content, re.IGNORECASE)
            unique_urls.update(urls)
    except FileNotFoundError:
        print(f"Warning: File '{filename}' not found.")
    except Exception as e:
        print(f"An error occurred while reading '{filename}': {e}")
    return unique_urls

def write_unique_urls(urls, output_file):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for url in sorted(urls):
                f.write(url + "\n")
        print(f"Unique GitHub URLs written to {output_file}")
    except Exception as e:
        print(f"Error writing to '{output_file}': {e}")

def main():
    input_files = ['comment_lines.txt', 'comment_lines2.txt']
    all_urls = set()
    for filename in input_files:
        urls = extract_github_urls_from_file(filename)
        all_urls.update(urls)
    
    output_filename = 'yara_rule_repo_list.txt'
    write_unique_urls(all_urls, output_filename)

if __name__ == "__main__":
    main()
