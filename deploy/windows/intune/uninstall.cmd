@echo off
REM BAD uninstall entry point for Intune Win32 packaging.
REM Intune runs this; it calls the real uninstaller.
REM
REM Uninstall-BAD.ps1 must sit next to this script (see README.md: the intune
REM folder is packaged as a self-contained bundle, so copy the ps1 files in).
REM Pass the account you added at install time so its Event Log Readers
REM membership gets revoked too, e.g. via the Intune uninstall command line:
REM   uninstall.cmd -ServiceAccount BADSVC

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0Uninstall-BAD.ps1" %*
exit /b %ERRORLEVEL%