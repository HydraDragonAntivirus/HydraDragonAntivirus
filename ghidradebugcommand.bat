@echo off
REM Run analyzeHeadless.bat using the current directory

REM Path to Ghidra's analyzeHeadless.bat
"%cd%\ghidra\support\analyzeHeadless.bat" "%cd%\ghidra_projects" "TestProject" ^
-import "%cd%\iilspycmd.exe" ^
-postScript DecompileAndSave.java ^
-scriptPath "%cd%\scripts" ^
-log "%cd%\ghidra_logs\analyze.log"

REM Check if the last command was successful
IF ERRORLEVEL 1 (
    echo An error occurred while running analyzeHeadless.bat
    exit /b 1
)

echo Analysis completed successfully.
