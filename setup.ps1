param(
    [switch]$InstallSkill
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = Join-Path $root '.venv'
$python = Join-Path $venv 'Scripts\python.exe'

python -c "import platform,struct,sys; ok=sys.platform == 'win32' and sys.version_info >= (3,9) and struct.calcsize('P') == 8 and platform.machine().lower() in {'amd64','x86_64'} and sys.getwindowsversion().build >= 22000; raise SystemExit(0 if ok else 2)"
if ($LASTEXITCODE -ne 0) { throw 'Windows setup requires Windows 11 x64 and 64-bit Python 3.9 or newer.' }
python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw 'Failed to create the repository virtual environment.' }
& $python -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw 'Failed to upgrade pip in the repository virtual environment.' }
& $python -m pip install -r (Join-Path $root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Failed to install repository dependencies.' }
& $python -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Repository dependencies failed pip check.' }

if ($InstallSkill) {
    & $python (Join-Path $root 'scripts\install_skill.py')
    if ($LASTEXITCODE -ne 0) { throw 'Codex Skill installation failed.' }
}

& $python (Join-Path $root 'wechat_manager.py') preflight
$preflightExit = $LASTEXITCODE
if ($preflightExit -ne 0) {
    Write-Host 'Dependencies are installed. Preflight needs attention before configuration.' -ForegroundColor Yellow
}
Write-Host 'After preflight is unambiguous and supported, run .\manage.cmd preflight --configure and follow README.md.'
exit 0
