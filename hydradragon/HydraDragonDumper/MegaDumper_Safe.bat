@echo off
REM MegaDumper Launcher with Scylla CSE Protection
REM This launcher ensures the COMPlus_legacyCorruptedStateExceptionsPolicy is set
REM before the .NET runtime starts, enabling AccessViolationException to be caught.

set COMPlus_legacyCorruptedStateExceptionsPolicy=1

REM Start MegaDumper
"%~dp0MegaDumper.exe" %*
