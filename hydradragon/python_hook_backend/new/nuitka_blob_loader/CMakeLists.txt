cmake_minimum_required(VERSION 3.10)
project(nuitka_blob_loader C)

set(CMAKE_C_STANDARD 11)

add_executable(blob_loader
    src/main.c
    src/blob_loader.c
    src/blob_export.c
    src/crc32.c
)

target_include_directories(blob_loader PRIVATE include)
target_compile_options(blob_loader PRIVATE -Wall -Wextra -O2)
target_link_libraries(blob_loader m)

# Place rcdata_10_3.bin in the build directory to run directly
message(STATUS "Build: place rcdata_10_3.bin next to the executable, then run ./blob_loader")
