#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "log4cplus::log4cplusSU" for configuration "Debug"
set_property(TARGET log4cplus::log4cplusSU APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(log4cplus::log4cplusSU PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "CXX;RC"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/log4cplusSUD.lib"
  )

list(APPEND _cmake_import_check_targets log4cplus::log4cplusSU )
list(APPEND _cmake_import_check_files_for_log4cplus::log4cplusSU "${_IMPORT_PREFIX}/lib/log4cplusSUD.lib" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
