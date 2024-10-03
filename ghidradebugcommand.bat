@echo off
REM Run analyzeHeadless.bat using the current directory

REM Check if necessary directories exist, and create them if they don't
if not exist "%cd%\ghidra_projects" (
    mkdir "%cd%\ghidra_projects"
)

if not exist "%cd%\scripts" (
    mkdir "%cd%\scripts"
)

if not exist "%cd%\ghidra_logs" (
    mkdir "%cd%\ghidra_logs"
)

REM Path to Ghidra's analyzeHeadless.bat
"%cd%\ghidra\support\analyzeHeadless.bat" "%cd%\ghidra_projects" "TestProject" ^
-import "%cd%\ilspycmd.exe" ^
-postScript DecompileAndSave.java ^
-scriptPath "%cd%\scripts" ^
-log "%cd%\ghidra_logs\analyze.log"

REM Check if the last command was successful
IF ERRORLEVEL 1 (
    echo An error occurred while running analyzeHeadless.bat
    exit /b 1
)

echo Analysis completed successfully.
