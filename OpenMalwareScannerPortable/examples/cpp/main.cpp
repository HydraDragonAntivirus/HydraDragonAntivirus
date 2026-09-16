#include <iostream>
#include "openedr.hpp"

int main() {
    try {
        openedr::Scanner scanner("OpenMalwareScannerPortable");
        std::cout << "[+] Scanner initialized successfully in C++!\n\n";

        // File Scan
        std::string report = scanner.scan_file("OpenMalwareScannerPortable/openedr_static.dll");
        std::cout << "--- File Scan Report ---\n" << report << "\n\n";

        // URL Scan
        std::string url_report = scanner.scan_url("https://malicious-site.example.com/payload.exe");
        std::cout << "--- URL Scan Report ---\n" << url_report << "\n";

    } catch (const std::exception& ex) {
        std::cerr << "[-] Error: " << ex.what() << "\n";
        return 1;
    }
    return 0;
}
