#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "log4cplus::log4cplusS" for configuration "Release"
set_property(TARGET log4cplus::log4cplusS APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(log4cplus::log4cplusS PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELEASE "CXX;RC"
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/log4cplusS.lib"
  )

list(APPEND _cmake_import_check_targets log4cplus::log4cplusS )
list(APPEND _cmake_import_check_files_for_log4cplus::log4cplusS "${_IMPORT_PREFIX}/lib/log4cplusS.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
