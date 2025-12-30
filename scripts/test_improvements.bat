@echo off
REM Memory Analyzer - Quick Test Script
REM Run this to validate improvements without full analysis

echo ======================================================================
echo MEMORY ANALYZER - VALIDATION TEST
echo ======================================================================
echo.

python test_analyzer.py

echo.
echo ======================================================================
echo.
echo To run full analysis (once you have memdump.mem):
echo   python memory_analyzer.py -f memdump.mem
echo.
echo To run with GUI:
echo   python memory_analyzer_gui.py
echo.
echo ======================================================================
pause
