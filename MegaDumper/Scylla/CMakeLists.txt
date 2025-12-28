cmake_minimum_required(VERSION 3.15)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")

project(Scylla
    VERSION 0.11.2
    LANGUAGES C CXX
)

option(SCYLLA_DOC "Enable documentation build" OFF)
option(SCYLLA_PYTHON "Enable Python bindings build" ON)

add_compile_definitions("UNICODE" "_UNICODE" "_SILENCE_STDEXT_HASH_DEPRECATION_WARNINGS")
# Static linkage with MSVC's runtime
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory("src")
add_subdirectory("thirdparty")
add_subdirectory("bindings")

if(SCYLLA_DOC)
  add_subdirectory("doc")
endif()
