#Requires -Version 5.1
<#
.SYNOPSIS
    Builds FSLogix Log Analyzer as a standalone single-file Windows executable.
.DESCRIPTION
    Requires Python 3.9+ on PATH. Installs PyInstaller if not present,
    then produces dist\FSLogixLogAnalyzer.exe (no install required to run).
.EXAMPLE
    .\build.ps1
    .\build.ps1 -Clean
#>
param(
    [switch]$Clean   # Remove build artefacts before building
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Sanity checks ─────────────────────────────────────────────────────────────
if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python not found on PATH. Install Python 3.9+ and try again."
    exit 1
}

$pyVer = python -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')"
Write-Host "Python version: $pyVer" -ForegroundColor Cyan

# ── Optional clean ────────────────────────────────────────────────────────────
if ($Clean) {
    foreach ($dir in @("build", "dist", "__pycache__")) {
        if (Test-Path $dir) {
            Write-Host "Removing $dir..." -ForegroundColor Yellow
            Remove-Item $dir -Recurse -Force
        }
    }
    Get-ChildItem -Filter "*.spec" | Remove-Item -Force
}

# ── Install / upgrade PyInstaller ─────────────────────────────────────────────
Write-Host "Ensuring PyInstaller is installed..." -ForegroundColor Cyan
python -m pip install --quiet --upgrade pyinstaller

# ── Build ─────────────────────────────────────────────────────────────────────
Write-Host "Building executable..." -ForegroundColor Cyan

$buildArgs = @(
    "-m", "PyInstaller",
    "--onefile",                          # single .exe
    "--windowed",                         # no console window
    "--name", "FSLogixLogAnalyzer",
    "--add-data", "issues.py;.",          # bundle issues module
    "--add-data", "parser.py;.",          # bundle parser module
    "--clean",
    "main.py"
)

python @buildArgs

# ── Result ────────────────────────────────────────────────────────────────────
$exe = "dist\FSLogixLogAnalyzer.exe"
if (Test-Path $exe) {
    $size = [math]::Round((Get-Item $exe).Length / 1MB, 1)
    Write-Host ""
    Write-Host "Build succeeded!" -ForegroundColor Green
    Write-Host "  Output : $((Resolve-Path $exe).Path)" -ForegroundColor Green
    Write-Host "  Size   : ${size} MB" -ForegroundColor Green
    Write-Host ""
    Write-Host "Drop FSLogixLogAnalyzer.exe on any AVD host — no install required." -ForegroundColor Cyan
} else {
    Write-Error "Build failed — $exe not found. Check PyInstaller output above."
    exit 1
}
