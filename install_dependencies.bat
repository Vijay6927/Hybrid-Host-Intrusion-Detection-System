@echo off
echo Installing HIDS dependencies in virtual environment...
.\hids_env\Scripts\pip.exe install flask-cors wmi yara-python watchdog pywin32
echo.
echo Installation complete!
echo.
echo To run HIDS:
echo 1. Open PowerShell as Administrator
echo 2. cd C:\HIDS_Project
echo 3. .\hids_env\Scripts\Activate.ps1
echo 4. python hids.py
pause
