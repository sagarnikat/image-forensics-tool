@echo off
rem PixelProof - one command -> PDF report for one image (Windows).
rem
rem Runs the analysis models that exist in this build (file analysis,
rem EXIF / metadata and Error Level Analysis), writes a PDF evidence report
rem and prints its path. It does not launch a viewer.
rem
rem Usage:
rem   report.bat samples\tampered\spliced_demo.jpg
rem   report.bat photo.jpg --examiner "Sagar" -o C:\tmp\evidence.pdf
rem
rem Works from cmd.exe and PowerShell (.\report.bat ...).

setlocal

set "HERE=%~dp0"

if "%~1"=="" goto usage
if "%~1"=="-h" goto usage
if "%~1"=="--help" goto usage

rem 1) Project virtual environment
set "PYEXE="
if exist "%HERE%.venv\Scripts\python.exe" set "PYEXE=%HERE%.venv\Scripts\python.exe"
if defined PYEXE goto run

rem 2) Windows Python launcher
where py >nul 2>nul
if not errorlevel 1 (
    py -3 "%HERE%report.py" %*
    exit /b %errorlevel%
)

rem 3) python on PATH
where python >nul 2>nul
if not errorlevel 1 set "PYEXE=python"
if defined PYEXE goto run

echo error: no Python interpreter found. Create .venv first:>&2
echo   py -m venv .venv ^&^& .venv\Scripts\pip install -r requirements.txt>&2
exit /b 2

:run
"%PYEXE%" "%HERE%report.py" %*
exit /b %errorlevel%

:usage
echo usage: report.bat ^<image^> [extra options]
echo        report.bat samples\tampered\spliced_demo.jpg
echo.
echo extra options:
echo   -o PATH            PDF path or directory
echo   --examiner NAME    examiner printed on the report
echo   --case-id ID       override the generated case id
if "%~1"=="" exit /b 2
exit /b 0
