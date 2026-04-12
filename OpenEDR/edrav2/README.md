# EDR Agent v2

EDR Agent v2.5

## Building from Source

This project has been updated to build natively using **Visual Studio 2022**. A master build script is provided to automate compiling both the HydraDragon EDR codebase and all third-party dependencies (`boost`, `openssl`, `curl`, `jsoncpp`, etc.).

### Using `build_all.cmd`

The master build script is located in the Visual Studio 2022 solution directory:
`build\vs2022\build_all.cmd`

> [!WARNING]
> **Clean Build Behavior**: Running `build_all.cmd` will automatically delete the old `out/` directory (`rd /s /q out`) before starting the build process. This is mandatory to ensure compilation consistency and prevent stale object file contamination, but it will remove all existing build artifacts and logs.

#### 1. Full Dependency Rebuild (`--full`)

If you are cloning the repository for the first time or if you have modified third-party libraries in the `eprj` directory, you **must** build the dependencies first. This can take several minutes (15-25m).

```cmd
cd build\vs2022
.\build_all.cmd --full
```

This will:
* Build all components via CMake using Visual Studio 2022 (v143)
* Install the resulting static libraries (`.lib`) into the root `lib\` folder
* Build the main `edrav2.sln` automatically

#### 2. Fast Build

If the dependencies (`lib\win-*`) have already been built, and you are only making changes to the local C++ agent codebase, you can skip the lengthy dependency compilation:

```cmd
cd build\vs2022
.\build_all.cmd
```

This acts as a fast-path that will invoke MSBuild directly on `edrav2.sln`.
