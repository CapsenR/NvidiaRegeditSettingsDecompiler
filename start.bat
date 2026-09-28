@echo off
REM Startet die GUI. Benoetigt Python 3.10+ (mit tkinter, Standard beim Windows-Installer).
cd /d "%~dp0"
py -3 -m nvregdecomp 2>nul || python -m nvregdecomp
if errorlevel 1 pause
