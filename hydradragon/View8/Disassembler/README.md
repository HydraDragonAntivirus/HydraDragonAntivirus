# View8 Disassembler Build

> **Note:** `cl` is only available in **x64 Native Tools Command Prompt for VS 2022**. It will not work in normal CMD or PowerShell unless the one-line `cmd /c` command below calls `vcvars64.bat`.

## Export the current local V8 patch

```bat
cmd /c "cd /d c:\src\depot_tools\v8 && git diff HEAD > C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\View8\Disassembler\14.6.202.33.patch"
```

## Required in: `c:\src\depot_tools\v8\out.gn\x64.release\args.gn`

```gn
dcheck_always_on = false
is_component_build = false
is_debug = false
target_cpu = "x64"
use_custom_libcxx = false
v8_monolithic = true
v8_use_external_startup_data = false
v8_static_library = true
v8_enable_disassembler = true
v8_enable_object_print = true
v8_enable_pointer_compression = false
v8_enable_temporal_support = false
treat_warnings_as_errors = false
```

## Mandatory: Rebuild V8 after every args.gn change

Changing `args.gn` has **no effect** until you re-run `gn gen` and `ninja`. The old `v8_monolith.lib` stays on disk with the old settings until you rebuild.

**Always run the regenerate and build commands again after editing `args.gn`.**

---

## Regenerate GN files with the args.gn above

```bat
cmd /c "set ""PATH=C:\src\depot_tools;%PATH%"" && set ""DEPOT_TOOLS_WIN_TOOLCHAIN=0"" && cd /d C:\src\depot_tools\v8 && gn gen out.gn/x64.release && ninja -C out.gn/x64.release v8_monolith"
```

## Build V8 monolith library

```bat
cmd /c "set ""PATH=C:\src\depot_tools;%PATH%"" && set ""DEPOT_TOOLS_WIN_TOOLCHAIN=0"" && cd /d C:\src\depot_tools\v8 && gn gen out.gn/x64.release && ninja -C out.gn/x64.release v8_monolith"
```

## Build the real View8 disassembler executable from v8dasm.cpp using MSVC STL

```bat
set "PATH=C:\src\depot_tools;%PATH%"
```
```bat
cd /d "C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\View8\Disassembler"
```
```bat
cl /nologo /EHsc /std:c++20 /Zc:__cplusplus /O2 /Ob3 /Oi /Ot /GL /MT /DNDEBUG /I"C:\src\depot_tools\v8" /I"C:\src\depot_tools\v8\include" v8dasm.cpp /Fe:v8dasm.exe /link /LTCG /LIBPATH:"C:\src\depot_tools\v8\out.gn\x64.release\obj" v8_monolith.lib winmm.lib dbghelp.lib shlwapi.lib ws2_32.lib advapi32.lib userenv.lib shell32.lib ole32.lib oleaut32.lib uuid.lib version.lib delayimp.lib
```

## Copy exe to View8 Bin folder where view8.py expects it

```bat
cmd /c "copy /Y C:\Users\semae\OneDrive\Belgeler\GitHub\HydraDragonAntivirus\hydradragon\View8\Disassembler\v8dasm.exe C:\Users\semae\OneDrive\Belgeler\GitHub\View8\Bin\14.6.202.33.exe"
```
