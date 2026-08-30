param(
    [ValidateSet('debug', 'release')]
    [string]$Configuration = 'release'
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$output = Join-Path $root "target\$Configuration"
New-Item -ItemType Directory -Force -Path $output | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Build Tools were not found' }
$installation = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installation) { throw 'MSVC x64 tools were not found' }
$vcvars = Join-Path $installation 'VC\Auxiliary\Build\vcvars64.bat'
$source = Join-Path $PSScriptRoot 'phone-auth-windows-webauthn-plugin.cpp'
$exe = Join-Path $output 'phone-auth-windows-webauthn-plugin.exe'
$object = Join-Path $output 'phone-auth-windows-webauthn-plugin.obj'
$pdb = Join-Path $output 'phone-auth-windows-webauthn-plugin.pdb'
$optimize = if ($Configuration -eq 'release') { '/O2 /DNDEBUG' } else { '/Od /Zi' }

$command = "call `"$vcvars`" >nul && cl.exe /nologo /std:c++20 /EHsc /W4 /DUNICODE /D_UNICODE $optimize `"$source`" /Fo:`"$object`" /Fd:`"$pdb`" /Fe:`"$exe`""

# vcvars64 writes benign notes to stderr (it looks for vswhere on PATH and says
# so when it is not there). Under `$ErrorActionPreference = 'Stop'` PowerShell
# turns any stderr line from a native command into a terminating error, so the
# build died before cl.exe ever ran — on a machine where cl.exe works. Judge the
# compiler by its exit code, which is the thing that actually answers.
$previous = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
$log = cmd.exe /d /c $command 2>&1
$code = $LASTEXITCODE
$ErrorActionPreference = $previous
if ($code -ne 0) {
    $log | ForEach-Object { Write-Output $_ }
    throw "MSVC failed with exit code $code"
}
Write-Output $exe
