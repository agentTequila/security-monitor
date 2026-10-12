$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

python -m pip install --quiet -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "pip install failed" }

python -m PyInstaller --onefile --clean --noconfirm --uac-admin --icon (Join-Path $Root "assets\icon.ico") --name security-monitor --paths $Root (Join-Path $Root "security_monitor\__main__.py")
if ($LASTEXITCODE -ne 0) { throw "PyInstaller build failed" }

Write-Host "Built: $Root\dist\security-monitor.exe"
