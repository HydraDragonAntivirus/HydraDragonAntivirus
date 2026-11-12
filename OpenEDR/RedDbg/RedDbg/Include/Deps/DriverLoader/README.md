# DriverLoader
it's a driver injector or driver loader header lib(Windows)

# Usage example
You need to include header file(like in boost) and for example you can write this:

1)
```cpp
//CPP 20
#include "include/DriverLoader.hpp"

#include <Windows.h>

#include <iostream>
#include <string>

int main() {
    std::unique_ptr<DRIVER> Driver; Driver = std::make_unique<DRIVER>();
    std::string Wait;

    Driver.InitSvc((LPTSTR)L"C:\\HelloWorldDriver.sys", (LPTSTR)L"driver", (LPTSTR)L"driver", SERVICE_DEMAND_START);
    std::cout << "Driver Loaded!" << std::endl;

    Driver.CreateSvc();
    std::cout << "Driver Created!" << std::endl;

    Driver.StartSvc();
    std::cout << "Driver Started!" << std::endl;

    std::cout << "Press any key to unload driver...";
    getline(std::cin, Wait, '\n');

    Driver.UnloadSvc();
    std::cout << "Driver unloaded!" << std::endl;

    return 0;
}
```
2)
```cpp
//CPP 20
#include "include/DriverLoader.hpp"

#include <Windows.h>

#include <iostream>
#include <string>

int main() {
    std::unique_ptr<DRIVER> Driver; Driver = std::make_unique<DRIVER>();
    std::string Wait;

    Driver->LoadDriver((LPTSTR)L"C:\\HelloWorldDriver.sys", (LPTSTR)L"driver", (LPTSTR)L"driver", SERVICE_DEMAND_START);
    std::cout << "Driver Started!" << std::endl;

    std::cout << "Press any key to unload driver...";
    getline(std::cin, Wait, '\n');

    Driver->UnloadDriver();
    std::cout << "Driver unloaded!" << std::endl;

    return 0;
}
```
