@echo off
REM BAD install entry point for Intune Win32 packaging.
REM Intune runs this; it calls the real installer, which is PowerShell,
REM because .bat is where escaping goes to die.
REM
REM Bundle Install-BAD.ps1, Uninstall-BAD.ps1 and bad-windows.exe next to this
REM script (copy the ps1 files from the parent folder) so the client never
REM has to reach GitHub. Build the .intunewin with the Microsoft Win32
REM Content Prep Tool:
REM   IntuneWinAppUtil.exe -c . -s install.cmd -o .
REM See README.md in this folder for the full recipe.

powershell -NoProfile -ExecutionPolicy Bypass ^
  -File "%~dp0Install-BAD.ps1" -ArtifactPath "%~dp0bad-windows.exe" %*
exit /b %ERRORLEVEL%