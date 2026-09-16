#include <stdio.h>
#include <stdlib.h>
#include "openedr_static.h"

int main(int argc, char* argv[]) {
    const char* rules_dir = "OpenMalwareScannerPortable";
    const char* target_file = (argc > 1) ? argv[1] : "OpenMalwareScannerPortable/openedr_static.dll";

    printf("[*] Initializing OpenEDR Engine from: %s\n", rules_dir);
    if (openedr_static_init(rules_dir) != 0) {
        fprintf(stderr, "[-] Failed to initialize OpenEDR static scanner!\n");
        return 1;
    }
    printf("[+] Scanner initialized successfully!\n\n");

    // 1. Scan File
    printf("--- 1. Scanning File: %s ---\n", target_file);
    char* json_report = openedr_static_scan_file(target_file);
    if (json_report != NULL) {
        printf("%s\n\n", json_report);
        openedr_static_free_string(json_report);
    } else {
        fprintf(stderr, "[-] Scan returned NULL.\n");
    }

    // 2. Scan URL
    const char* test_url = "http://suspicious-paypal-login.com";
    printf("--- 2. Scanning URL: %s ---\n", test_url);
    char* url_report = openedr_static_scan_url(test_url);
    if (url_report != NULL) {
        printf("%s\n\n", url_report);
        openedr_static_free_string(url_report);
    }

    // 3. Comodo FLS Query
    const char* test_sha1 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4";
    printf("--- 3. Comodo FLS Query: %s ---\n", test_sha1);
    int32_t fls_code = openedr_static_check_fls_sha1(test_sha1);
    printf("FLS Code: %d (1=Safe, 2=Malicious, 0=Unknown, -1=Error)\n\n", fls_code);

    return 0;
}
