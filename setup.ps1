param(
    [switch]$InstallSkill
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$venv = Join-Path $root '.venv'
$python = Join-Path $venv 'Scripts\python.exe'

python -m venv $venv
& $python -m pip install --upgrade pip
& $python -m pip install -r (Join-Path $root 'requirements.txt')

if ($InstallSkill) {
    & $python (Join-Path $root 'scripts\install_skill.py')
    if ($LASTEXITCODE -ne 0) { throw 'Codex Skill installation failed.' }
}

& $python (Join-Path $root 'wechat_manager.py') preflight
$preflightExit = $LASTEXITCODE
if ($preflightExit -ne 0) {
    Write-Host 'Dependencies are installed. Preflight needs attention before configuration.' -ForegroundColor Yellow
}
Write-Host 'Next: run wechat_manager.py preflight --configure, then follow the platform key instructions in README.md.'
