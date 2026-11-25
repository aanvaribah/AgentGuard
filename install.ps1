# requires -version 5.1
$ErrorActionPreference = "Stop"

# Native commands don't stop the script on failure, even with "Stop"; check their exit codes.
function Invoke-Checked {
    & $args[0] $args[1..($args.Length - 1)]
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
}

$PyName = $null
foreach ($candidate in @("py", "python", "python3")) {
    if (Get-Command $candidate -ErrorAction SilentlyContinue) {
        $PyName = $candidate
        break
    }
}

if (-not $PyName) {
    Write-Error "No python binary found on PATH."
    exit 1
}

& $PyName -c "import sys; sys.exit(sys.version_info < (3, 11))"
if ($LASTEXITCODE -ne 0) {
    Write-Error "AgentGuard needs Python 3.11 or newer ($PyName is $(& $PyName -V 2>&1))."
    exit 1
}

if (-not (Get-Command "ollama" -ErrorAction SilentlyContinue)) {
    Write-Host "Ollama is required but not installed. Install it with Ollama's official installer:" -ForegroundColor Red
    Write-Host "  https://ollama.com/download"
    Write-Host "then start it and rerun this script."
    exit 1
}

Invoke-Checked $PyName -m venv venv
Invoke-Checked "venv\Scripts\python.exe" -m pip install -r requirements.txt

# Pulls the pinned models and checks their digests.
Invoke-Checked "venv\Scripts\python.exe" -m agent_guard.analyst.models

$Banner = @'

    _                    _    ____                     _
   / \   __ _  ___ _ __ | |_ / ___|_   _  __ _ _ __ __| |
  / _ \ / _` |/ _ \ '_ \| __| |  _| | | |/ _` | '__/ _` |
 / ___ \ (_| |  __/ | | | |_| |_| | |_| | (_| | | | (_| |
/_/   \_\__, |\___|_| |_|\__|\____|\__,_|\__,_|_|  \__,_|
        |___/
'@

Write-Output $Banner
Write-Output ""
& "venv\Scripts\python.exe" main.py -h

Write-Host "`nRemember to run venv\Scripts\Activate.ps1!" -ForegroundColor Red
