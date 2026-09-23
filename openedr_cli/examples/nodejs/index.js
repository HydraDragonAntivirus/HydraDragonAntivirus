const path = require('path');
const { OpenEdrScanner } = require('./openedr');

function main() {
    const rulesDir = path.resolve(__dirname, '../../OpenMalwareScannerPortable');
    const dllPath = path.join(rulesDir, 'openedr_static.dll');

    console.log(`[*] Initializing OpenEDR Scanner in Node.js...`);
    const scanner = new OpenEdrScanner(dllPath, rulesDir);
    console.log(`[+] Scanner Initialized Successfully!\n`);

    // 1. File Scan
    const targetFile = dllPath;
    console.log(`--- 1. File Scan: ${targetFile} ---`);
    const report = scanner.scanFile(targetFile);
    console.log(`Verdict:`, report?.verdict);
    console.log(`Detections:`, report?.detections?.length || 0);
    console.log();

    // 2. URL Scan
    const testUrl = 'https://fake-login-bank.com';
    console.log(`--- 2. URL Scan: ${testUrl} ---`);
    const urlReport = scanner.scanUrl(testUrl);
    console.log(`URL Verdict:`, urlReport?.verdict);
    console.log(`Malware Probability:`, (urlReport?.malware_probability * 100).toFixed(2) + '%');
}

if (require.main === module) {
    main();
}
