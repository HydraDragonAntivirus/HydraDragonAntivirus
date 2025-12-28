set(SCYLLA_HEADER_FILES
    "AboutGui.h"
    "AppInfo.h"
    "DeviceNameResolver.h "
    "DumpMemoryGui.h"
    "ImportRebuilder.h"
    "OptionsGui.h"
    "PluginLoader.h"
    "SystemInformation.h"
    "ApiReader.h"
    "DisassemblerGui.h"
    "DumpSectionGui.h"
    "ImportsHandling.h"
    "PeParser.h"
    "ProcessAccessHelp.h"
    "Thunks.h"
    "Architecture.h"
    "DllInjection.h"
    "FunctionExport.h"
    "Logger.h"
    "PeRebuild.h"
    "ProcessLister.h"
    "TreeImportExport.h"
    "Configuration.h"
    "DllInjectionPlugin.h"
    "IATReferenceScan.h"
    "MainGui.h"
    "PickApiGui.h"
    "Scylla.h"
    "hexedit.h"
    "ConfigurationHolder.h"
    "DonateGui.h"
    "IATSearch.h"
    "NativeWinApi.h"
    "PickDllGui.h"
    "StringConversion.h"
    "multitree.h"
)
set(SCYLLA_SRC_FILES
    "AboutGui.cpp"
    "ApiReader.cpp"
    "Architecture.cpp"
    "Configuration.cpp"
    "ConfigurationHolder.cpp"
    "DeviceNameResolver.cpp"
    "DisassemblerGui.cpp"
    "DllInjection.cpp"
    "DllInjectionPlugin.cpp"
    "DonateGui.cpp"
    "DumpMemoryGui.cpp"
    "DumpSectionGui.cpp"
    "FunctionExport.cpp"
    "IATReferenceScan.cpp"
    "IATSearch.cpp"
    "ImportRebuilder.cpp"
    "ImportsHandling.cpp"
    "Logger.cpp"
    "MainGui.cpp"
    "NativeWinApi.cpp"
    "OptionsGui.cpp"
    "PeParser.cpp"
    "PeRebuild.cpp"
    "PickApiGui.cpp"
    "PickDllGui.cpp"
    "PluginLoader.cpp"
    "ProcessAccessHelp.cpp"
    "ProcessLister.cpp"
    "Scylla.cpp"
    "StringConversion.cpp"
    "SystemInformation.cpp"
    "TreeImportExport.cpp"
)
set(SCYLLA_RSRC_FILES
    "resource.h"
    "MainGui.rc"
)

# Static library
add_library(ScyllaLib STATIC ${SCYLLA_HEADER_FILES} ${SCYLLA_SRC_FILES})
target_include_directories(ScyllaLib PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(ScyllaLib PUBLIC distorm tinyxml WTL)
target_compile_definitions(ScyllaLib PRIVATE
    APPNAME_S="${CMAKE_PROJECT_NAME}"
    APPVERSION_S="v${CMAKE_PROJECT_VERSION}"
)

# DLL
add_library(Scylla MODULE
    ${SCYLLA_RSRC_FILES}
    "main.cpp"
    "scylla_export_functions.def"
)
target_link_libraries(Scylla PRIVATE ScyllaLib)

# Standalone executable
add_executable(ScyllaExe WIN32
    ${SCYLLA_RSRC_FILES}
    "main.cpp"
)
target_link_libraries(ScyllaExe PRIVATE ScyllaLib)

if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(STATUS "Configuring 32-bit build - Renaming outputs to *_x86")
    set_target_properties(Scylla PROPERTIES OUTPUT_NAME "Scylla_x86")
    set_target_properties(ScyllaExe PROPERTIES OUTPUT_NAME "ScyllaExe_x86")
    set_target_properties(ScyllaLib PROPERTIES OUTPUT_NAME "ScyllaLib_x86")
endif()