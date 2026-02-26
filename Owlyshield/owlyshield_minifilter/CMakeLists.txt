cmake_minimum_required(VERSION 3.28)

project(rwatch_superbuild NONE)

set(
  _rwatch_hyperdbg_required
  "${CMAKE_CURRENT_SOURCE_DIR}/HyperDbg/hyperdbg/dependencies/pdbex/Source/CMakeLists.txt"
)
set(_rwatch_hyperdbg_default ON)
if(NOT EXISTS "${_rwatch_hyperdbg_required}")
  set(_rwatch_hyperdbg_default OFF)
endif()

option(RWATCH_ENABLE_HYPERDBG "Include HyperDbg CMake targets." ${_rwatch_hyperdbg_default})
option(RWATCH_ENABLE_OWLYSHIELD_DRIVER "Add an MSBuild target for OwlyshieldRansomFilter." ON)

set(
  RWATCH_PLATFORM
  ""
  CACHE STRING
  "MSBuild platform for OwlyshieldRansomFilter (default: current VS platform or x64)."
)
set(
  RWATCH_SINGLE_CONFIG
  "Debug"
  CACHE STRING
  "Fallback configuration for single-config generators."
)

if(RWATCH_ENABLE_HYPERDBG)
  if(NOT EXISTS "${_rwatch_hyperdbg_required}")
    message(
      FATAL_ERROR
        "HyperDbg dependencies are incomplete. Run `git submodule update --init --recursive` in "
        "owlyshield_minifilter/HyperDbg, or configure with -DRWATCH_ENABLE_HYPERDBG=OFF."
    )
  endif()
  add_subdirectory(HyperDbg/hyperdbg)
elseif(NOT _rwatch_hyperdbg_default)
  message(
    STATUS
      "RWATCH_ENABLE_HYPERDBG is OFF by default because HyperDbg submodules are not initialized."
  )
endif()

if(RWATCH_ENABLE_OWLYSHIELD_DRIVER)
  if(NOT WIN32)
    message(FATAL_ERROR "OwlyshieldRansomFilter can only be built on Windows.")
  endif()

  if(CMAKE_VS_MSBUILD_COMMAND)
    set(_rwatch_msbuild "${CMAKE_VS_MSBUILD_COMMAND}")
  else()
    find_program(
      _rwatch_msbuild
      NAMES msbuild.exe msbuild
      PATHS
        "$ENV{ProgramFiles(x86)}/Microsoft Visual Studio"
        "$ENV{ProgramFiles}/Microsoft Visual Studio"
      PATH_SUFFIXES
        "2022/BuildTools/MSBuild/Current/Bin"
        "2022/Community/MSBuild/Current/Bin"
        "2022/Professional/MSBuild/Current/Bin"
        "2022/Enterprise/MSBuild/Current/Bin"
        "2019/BuildTools/MSBuild/Current/Bin"
        "2019/Community/MSBuild/Current/Bin"
        "2019/Professional/MSBuild/Current/Bin"
        "2019/Enterprise/MSBuild/Current/Bin"
    )
  endif()

  if(NOT _rwatch_msbuild)
    message(
      FATAL_ERROR
        "MSBuild was not found. Use a Visual Studio generator or ensure msbuild.exe is on PATH."
    )
  endif()

  if(RWATCH_PLATFORM)
    set(_rwatch_platform "${RWATCH_PLATFORM}")
  elseif(CMAKE_VS_PLATFORM_NAME)
    set(_rwatch_platform "${CMAKE_VS_PLATFORM_NAME}")
  else()
    set(_rwatch_platform "x64")
  endif()

  if(CMAKE_CONFIGURATION_TYPES)
    set(_rwatch_config "$<CONFIG>")
  elseif(CMAKE_BUILD_TYPE)
    set(_rwatch_config "${CMAKE_BUILD_TYPE}")
  else()
    set(_rwatch_config "${RWATCH_SINGLE_CONFIG}")
  endif()

  set(
    _rwatch_driver_project
    "${CMAKE_CURRENT_SOURCE_DIR}/OwlyshieldRansomFilter/OwlyshieldRansomFilter.vcxproj"
  )

  add_custom_target(
    owlyshield_ransom_filter
    COMMAND
      "${_rwatch_msbuild}"
      "${_rwatch_driver_project}"
      /m
      /nologo
      /t:Build
      "/p:Configuration=${_rwatch_config}"
      "/p:Platform=${_rwatch_platform}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/OwlyshieldRansomFilter"
    COMMENT "Building OwlyshieldRansomFilter (${_rwatch_platform})"
    VERBATIM
  )
endif()

add_custom_target(rwatch_all)
if(TARGET hyperdbg-cli)
  add_dependencies(rwatch_all hyperdbg-cli)
endif()
if(TARGET owlyshield_ransom_filter)
  add_dependencies(rwatch_all owlyshield_ransom_filter)
endif()
