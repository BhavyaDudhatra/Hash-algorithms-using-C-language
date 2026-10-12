@echo off
REM Windows one-command build (MinGW gcc assumed on PATH)
REM Usage: build.bat  -> produces hasher.exe
gcc -O2 -Wall -Wextra -o hasher.exe main.c
if %errorlevel% neq 0 (
  echo BUILD FAILED
  exit /b 1
)
echo BUILD OK: hasher.exe
hasher.exe < nul > nul 2>&1
