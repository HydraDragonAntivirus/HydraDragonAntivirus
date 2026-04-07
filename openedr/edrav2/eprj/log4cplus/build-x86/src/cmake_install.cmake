# Install script for directory: C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "C:/Program Files (x86)/log4cplus")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Release")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/generated/log4cplusConfig.cmake"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/generated/log4cplusConfigVersion.cmake"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(EXISTS "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus/log4cplusTargets.cmake")
    file(DIFFERENT _cmake_export_file_changed FILES
         "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus/log4cplusTargets.cmake"
         "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/CMakeFiles/Export/77af70a4c098b0d53cb4a1c823501ddb/log4cplusTargets.cmake")
    if(_cmake_export_file_changed)
      file(GLOB _cmake_old_config_files "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus/log4cplusTargets-*.cmake")
      if(_cmake_old_config_files)
        string(REPLACE ";" ", " _cmake_old_config_files_text "${_cmake_old_config_files}")
        message(STATUS "Old export file \"$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus/log4cplusTargets.cmake\" will be replaced.  Removing files [${_cmake_old_config_files_text}].")
        unset(_cmake_old_config_files_text)
        file(REMOVE ${_cmake_old_config_files})
      endif()
      unset(_cmake_old_config_files)
    endif()
    unset(_cmake_export_file_changed)
  endif()
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus" TYPE FILE FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/CMakeFiles/Export/77af70a4c098b0d53cb4a1c823501ddb/log4cplusTargets.cmake")
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus" TYPE FILE FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/CMakeFiles/Export/77af70a4c098b0d53cb4a1c823501ddb/log4cplusTargets-debug.cmake")
  endif()
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus" TYPE FILE FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/CMakeFiles/Export/77af70a4c098b0d53cb4a1c823501ddb/log4cplusTargets-minsizerel.cmake")
  endif()
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus" TYPE FILE FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/CMakeFiles/Export/77af70a4c098b0d53cb4a1c823501ddb/log4cplusTargets-relwithdebinfo.cmake")
  endif()
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib/cmake/log4cplus" TYPE FILE FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/CMakeFiles/Export/77af70a4c098b0d53cb4a1c823501ddb/log4cplusTargets-release.cmake")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  if(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Dd][Ee][Bb][Uu][Gg])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/Debug/log4cplusSD.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ee][Aa][Ss][Ee])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/Release/log4cplusS.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Mm][Ii][Nn][Ss][Ii][Zz][Ee][Rr][Ee][Ll])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/MinSizeRel/log4cplusS.lib")
  elseif(CMAKE_INSTALL_CONFIG_NAME MATCHES "^([Rr][Ee][Ll][Ww][Ii][Tt][Hh][Dd][Ee][Bb][Ii][Nn][Ff][Oo])$")
    file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/lib" TYPE STATIC_LIBRARY FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/RelWithDebInfo/log4cplusS.lib")
  endif()
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/appender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/asyncappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/callbackappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/clogger.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/config.hxx"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/configurator.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/consoleappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/fileappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/fstreams.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/hierarchy.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/hierarchylocker.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/initializer.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/layout.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/log4cplus.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/log4judpappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/logger.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/loggingmacros.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/loglevel.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/mdc.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/ndc.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/nteventlogappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/nullappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/socketappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/streams.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/syslogappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/tchar.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/tracelogger.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/tstring.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/version.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/win32debugappender.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/win32consoleappender.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/boost" TYPE FILE FILES "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/boost/deviceappender.hxx")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/helpers" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/appenderattachableimpl.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/connectorthread.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/fileinfo.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/lockfile.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/loglog.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/pointer.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/property.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/queue.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/snprintf.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/socket.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/socketbuffer.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/stringhelper.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/thread-config.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/helpers/timehelper.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/internal" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/internal/env.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/internal/internal.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/internal/socket.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/spi" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/appenderattachable.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/factory.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/filter.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/loggerfactory.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/loggerimpl.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/loggingevent.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/objectregistry.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/spi/rootlogger.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/thread/impl" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/impl/syncprims-cxx11.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/impl/syncprims-impl.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/impl/syncprims-pmsm.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/impl/threads-impl.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/impl/tls.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/thread" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/syncprims-pub-impl.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/syncprims.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/thread/threads.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "Unspecified" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/log4cplus/config" TYPE FILE FILES
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/config/macosx.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/config/win32.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/src/../include/log4cplus/config/windowsh-inc.h"
    "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/include/log4cplus/config/defines.hxx"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "C:/Users/semae/OneDrive/Belgeler/GitHub/HydraDragonAntivirus/openedr/edrav2/eprj/log4cplus/build-x86/src/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
