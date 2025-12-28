# distorm
file(GLOB DISTORM_SRC_FILES "distorm/src/*.h" "distorm/src/*.c")
add_library(distorm STATIC ${DISTORM_SRC_FILES})
target_include_directories(distorm PUBLIC "distorm/include")

# pybind11
if (SCYLLA_PYTHON)
    add_subdirectory("pybind11")
endif (SCYLLA_PYTHON)

# tinyxml
file(GLOB TINYXML_SRC_FILES "tinyxml/*.h" "tinyxml/*.cpp")
add_library(tinyxml STATIC ${TINYXML_SRC_FILES})
target_include_directories(tinyxml PUBLIC "tinyxml")

# WTL
add_library(WTL INTERFACE)
target_include_directories(WTL INTERFACE "WTL/Include")