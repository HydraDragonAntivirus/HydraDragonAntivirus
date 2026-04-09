#include "ClamAVScanner.h"

#include <chrono>
#include <iostream>
#include <memory>
#include <thread>

int wmain() {
    const std::wstring dll_path = LR"(C:\ClamAV\libclamav.dll)";
    const std::wstring db_path = LR"(C:\ClamAV\database)";
    const std::wstring file_to_scan = LR"(C:\Temp\sample.bin)";

    auto scanner = clamav::Scanner::CreateAsync(dll_path, db_path);

    while (scanner->IsInitializing()) {
        std::cout << "Initialization stage: " << scanner->GetInitStage() << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    if (!scanner->WaitUntilReady()) {
        std::cerr << "Scanner init failed: " << scanner->GetInitError() << std::endl;
        return 1;
    }

    const auto result = scanner->ScanFile(file_to_scan);

    if (result.IsClean()) {
        std::cout << "File is clean." << std::endl;
        return 0;
    }

    if (result.IsVirus()) {
        std::cout << "Virus detected: " << result.virus_name << std::endl;
        return 2;
    }

    std::cout << "Scan failed with code: " << result.result_code << std::endl;
    return 3;
}
