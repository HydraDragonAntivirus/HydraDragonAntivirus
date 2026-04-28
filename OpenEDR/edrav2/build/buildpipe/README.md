# buildpipe

## Overview
Buildpipe builds the local EDRAv2 checkout. It uses only local files and leaves generated output in the checkout.

Build output is written directly to:

```
OpenEDR\edrav2\out
```

## Requirements
  * **Git** must be installed and configured
  * **Git-LFS** must be installed if this checkout contains LFS-managed files
  * **Visual Studio 2022** must be installed and configured
  * **WIX Toolset** must be installed

## Launching
  * _builder.cmd_ - builds the current local checkout
  * _builder.cmd /force_ - cleans a previous failed run marker and builds the current local checkout
  * _build_installer.cmd b.123_ - builds installer packages using build number 123

## Script Flow
  * Checks whether another build is already running
  * Handles a previous failed build marker (_.error_)
  * Reads version data
  * Temporarily writes _build_info.h_ plus _BuildInfo.wxi_ for the build, then restores their previous contents
  * Builds binaries and setup projects
  * Runs unit tests where applicable
  * Leaves generated output in _OpenEDR\edrav2\out_
  * Cleans buildpipe logs and markers on success

## Error Handling
In case of error on any stage:
  * file _.error_ is created
  * logs are left under _Logs_
  * script exits with an error

Cleanup is not performed after an error, so the failure can be investigated.
