package main

import (
	"fmt"
	"log"
	"openedr_example/openedr"
)

func main() {
	dllPath := "../../OpenMalwareScannerPortable/openedr_static.dll"
	rulesDir := "../../OpenMalwareScannerPortable"

	fmt.Println("[*] Initializing OpenEDR Scanner in Go...")
	scanner, err := openedr.NewScanner(dllPath, rulesDir)
	if err != nil {
		log.Fatalf("[-] Failed to init scanner: %v", err)
	}
	fmt.Println("[+] Scanner Initialized Successfully!\n")

	// 1. File Scan
	target := "../../OpenMalwareScannerPortable/openedr_static.dll"
	fmt.Printf("--- 1. Scanning File: %s ---\n", target)
	report, err := scanner.ScanFile(target)
	if err != nil {
		log.Printf("Scan error: %v", err)
	} else {
		fmt.Println(report)
	}
	fmt.Println()

	// 2. URL Scan
	url := "https://malicious-test-link.com/auth"
	fmt.Printf("--- 2. Scanning URL: %s ---\n", url)
	urlReport, err := scanner.ScanURL(url)
	if err == nil {
		fmt.Println(urlReport)
	}
	fmt.Println()

	// 3. FLS Cloud Query
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4"
	fmt.Printf("--- 3. Querying FLS Cloud: %s ---\n", hash)
	verdict, _ := scanner.QueryFLS(hash)
	fmt.Printf("FLS Verdict: %d (1=Safe, 2=Malicious, 0=Unknown)\n", verdict)
}
