C
=

C API for Scylla.

Note: All of the C APIs use the ``WINAPI`` calling convention.
   
.. c:function:: BOOL ScyllaDumpCurrentProcessW(const WCHAR *fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR *fileResult)

   Dump a PE from the current process's address space.

.. c:function:: BOOL ScyllaDumpCurrentProcessA(const char *fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char *fileResult)

   ANSI version of :c:func:`ScyllaDumpCurrentProcessW`.

.. c:function:: BOOL ScyllaDumpProcessW(DWORD_PTR pid, const WCHAR *fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const WCHAR *fileResult)

   Dump a PE from the given process's address space.
   
.. c:function:: BOOL ScyllaDumpProcessA(DWORD_PTR pid, const char *fileToDump, DWORD_PTR imagebase, DWORD_PTR entrypoint, const char *fileResult)

   ANSI version of :c:func:`ScyllaDumpProcessW`.
   
.. c:function:: BOOL ScyllaRebuildFileW(const WCHAR *fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)

   Apply minor fixes to a PE file.
   
.. c:function:: BOOL ScyllaRebuildFileA(const char *fileToRebuild, BOOL removeDosStub, BOOL updatePeHeaderChecksum, BOOL createBackup)

   ANSI version of :c:func:`ScyllaRebuildFileW`.
   
.. c:function:: const WCHAR *ScyllaVersionInformationW()

   Return Scylla's version as a pointer to a constant *static* null-terminated string.
   The string's format is of the form "Scylla x64 v0.9.8".
   
.. c:function:: const char *ScyllaVersionInformationA()

   ANSI version of :c:func:`ScyllaVersionInformationW`.
   
.. c:function:: INT ScyllaStartGui(DWORD dwProcessId, HINSTANCE mod, DWORD_PTR entrypoint)

   Initialize and display Scylla's GUI.
   
.. c:function:: int ScyllaIatSearch(DWORD dwProcessId, DWORD_PTR *iatStart, DWORD *iatSize, DWORD_PTR searchStart, BOOL advancedSearch)

   Try to find an import address table in the given process's address space.
   In case of success, the IAT address and size are returned through the ``iatStart`` and ``iatSize`` arguments.
   
.. c:function:: int ScyllaIatFixAutoW(DWORD dwProcessId, DWORD_PTR iatAddr, DWORD iatSize, BOOL createNewIat, const WCHAR* dumpFile, const WCHAR* iatFixFile)

   Fix the import table of a PE previously dumped with Scylla.
   