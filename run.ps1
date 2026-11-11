param(
    [int]$Port = 8787
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Virtual environment not found. Create it with: py -3 -m venv .venv"
}

Write-Host "Starting RiskLens at http://127.0.0.1:$Port"
& $python -m uvicorn backend.main:app --host 127.0.0.1 --port $Port --reload
