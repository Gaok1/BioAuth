$ErrorActionPreference = 'Stop'
$here = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$script = Join-Path $here 'file-manager\phone-auth-file-manager.ps1'
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ("phoneauth-fm-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  $plain = Join-Path $tmp 'report with spaces.txt'
  $locked = "$plain.balock"
  Set-Content -LiteralPath $plain -Value plain
  Set-Content -LiteralPath $locked -Value locked
  $env:PHONEAUTH_RECOVERY_OUT = Join-Path $tmp 'offline code.recovery'

  $lock = & $script -Action auto -DryRun -PhoneAuth 'C:\PhoneAuth\phone-auth.exe' $plain |
    ConvertFrom-Json
  if ($lock.arguments[0] -ne 'locker' -or $lock.arguments[1] -ne 'lock') {
    throw 'plain file did not plan a lock'
  }
  if ('--keep-original' -notin $lock.arguments) {
    throw 'file-manager lock was destructive by default'
  }

  $cmd = Join-Path $here 'file-manager\phone-auth-file-manager.cmd'
  $dragPlan = & cmd.exe /d /c "`"$cmd`" -DryRun `"$plain`"" | ConvertFrom-Json
  if ($dragPlan.arguments[1] -ne 'lock') {
    throw 'the drag-and-drop .cmd did not forward its path'
  }

  $unlock = & $script -Action auto -DryRun -PhoneAuth 'C:\PhoneAuth\phone-auth.exe' $locked |
    ConvertFrom-Json
  if ($unlock.arguments[1] -ne 'unlock' -or '--keep-container' -notin $unlock.arguments) {
    throw 'locked file did not plan a reversible unlock'
  }

  $failed = $false
  try { & $script -Action auto -DryRun $plain $locked | Out-Null } catch { $failed = $true }
  if (-not $failed) { throw 'mixed lock/unlock selection was accepted' }
} finally {
  Remove-Item -LiteralPath $tmp -Recurse -Force
  Remove-Item Env:PHONEAUTH_RECOVERY_OUT -ErrorAction SilentlyContinue
}
