find_package(Sphinx)

if(NOT SPHINX_FOUND)
  message(WARNING "Doc disabled: sphinx-build not found")
  return()
endif()

message(STATUS "Sphinx: ${SPHINX_EXECUTABLE}")

add_custom_target(scylla-sphinx
    COMMAND ${CMAKE_COMMAND} -E env
      "PYTHONPATH=${CMAKE_BINARY_DIR}/bindings/python/$<CONFIGURATION>/;ENV{PYTHONPATH}"
      "${SPHINX_EXECUTABLE}" -a -E -w "${CMAKE_BINARY_DIR}/sphinx-warn.log" "${CMAKE_SOURCE_DIR}/doc/sphinx" sphinx-doc
      DEPENDS pyscylla
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Generating Sphinx Documentation" VERBATIM)

add_custom_target(scylla-doc ALL
    DEPENDS scylla-sphinx
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Generating documentation with Sphinx" VERBATIM)