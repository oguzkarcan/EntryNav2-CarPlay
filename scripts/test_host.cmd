@echo off
setlocal
set "TOOLS_DIR=%~dp0..\..\EntryNav2-CarPlay-Assets\tools"
if exist "%TOOLS_DIR%\w64devkit\bin\g++.exe" set "PATH=%TOOLS_DIR%\w64devkit\bin;%PATH%"
if exist "%TOOLS_DIR%\mingit\cmd\git.exe" set "PATH=%TOOLS_DIR%\mingit\cmd;%PATH%"
pushd "%~dp0.."
make clean
if errorlevel 1 exit /b %errorlevel%
make test-host BIN_EXT=.exe
set "RC=%errorlevel%"
make clean
popd
exit /b %RC%
