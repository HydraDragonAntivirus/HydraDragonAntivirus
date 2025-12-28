pybind11_add_module(pyscylla "module.cpp")
target_link_libraries(pyscylla PRIVATE ScyllaLib)