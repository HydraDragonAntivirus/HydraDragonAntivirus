:: Export the current local V8 patch.
cmd /c "cd /d c:\src\depot_tools\v8 && git diff HEAD > C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\View8\Disassembler\14.6.202.33.patch"

:: Required in:
::   c:\src\depot_tools\v8\out.gn\x64.release\args.gn
::
:: Recommended args.gn:
:: dcheck_always_on = false
:: is_component_build = false
:: is_debug = false
:: target_cpu = "x64"
:: use_custom_libcxx = false
:: v8_monolithic = true
:: v8_use_external_startup_data = false
:: v8_static_library = true
:: v8_enable_disassembler = true
:: v8_enable_object_print = true
:: v8_enable_pointer_compression = false
:: treat_warnings_as_errors = false

:: Regenerate GN files with the args.gn above.
cmd /c "set PATH=c:\src\depot_tools;%PATH% && set DEPOT_TOOLS_WIN_TOOLCHAIN=0 && cd /d c:\src\depot_tools\v8 && gn gen out.gn/x64.release"

:: Build V8 monolith library.
cmd /c "set PATH=c:\src\depot_tools;%PATH% && set DEPOT_TOOLS_WIN_TOOLCHAIN=0 && cd /d c:\src\depot_tools\v8 && ninja -C out.gn/x64.release v8_monolith"

:: Build the real View8 disassembler executable from v8dasm.cpp using MSVC STL.
cmd /c "set PATH=c:\src\depot_tools;%PATH% && cd /d C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\View8\Disassembler && cl /nologo /EHsc /std:c++20 /Zc:__cplusplus /O2 /Ob3 /Oi /Ot /GL /DNDEBUG /I c:\src\depot_tools\v8 /I c:\src\depot_tools\v8\include v8dasm.cpp /Fe:v8dasm.exe /link /LTCG /LIBPATH:c:\src\depot_tools\v8\out.gn\x64.release\obj v8_monolith.lib winmm.lib dbghelp.lib shlwapi.lib ws2_32.lib advapi32.lib userenv.lib shell32.lib ole32.lib oleaut32.lib uuid.lib version.lib delayimp.lib"

:: Also copy it to the View8 Bin folder, where view8.py expects it.
cmd /c "copy /Y C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\View8\Disassembler\v8dasm.exe C:\Users\semae\OneDrive\Belgeler\GitHub\View8\Bin\14.6.202.33.exe"
