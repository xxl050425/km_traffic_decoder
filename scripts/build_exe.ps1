param(
    [string]$Entry = ".\app.py",
    [string]$Name = "km_traffic_decoder"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Entry)) {
    throw "Entry file not found: $Entry"
}

pyinstaller --noconfirm --clean --onefile --windowed --name $Name $Entry

Write-Host "Build complete: dist\$Name.exe"
