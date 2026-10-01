$ErrorActionPreference = "Stop"

$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $venvPython)) {
    $venvPython = "python"
}

if (-not $env:ADMIN_PASSWORD) {
    $env:ADMIN_PASSWORD = "LocalDevPassword123"
}

if ($env:ADMIN_PASSWORD.Length -lt 12) {
    throw "ADMIN_PASSWORD must be at least 12 characters long."
}

if (-not $env:FLASK_SECRET_KEY) {
    $env:FLASK_SECRET_KEY = "dev-flask-secret-" + [System.Guid]::NewGuid().ToString("N")
}

& $venvPython app.py
