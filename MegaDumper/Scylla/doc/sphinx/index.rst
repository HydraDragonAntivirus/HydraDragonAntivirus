Welcome to Scylla's documentation!
==================================

Introduction
------------

The purpose of this project is to provide an interface that's easy to use for
dumping PEs from memory and for reconstructing import tables of dumped PEs on
Windows.

A typical use case of this project is the reverse engineering of a packed PE for
example.

Main features:
 - Works on Windows 7 and later
 - x64 and x86 support
 - Unicode support
 - Plugin support
 - Can be used in C, C++ and Python
 - Can be used inside of `x64dbg`

.. toctree::
  :caption: API
  :maxdepth: 1

  c/index
  python/index
