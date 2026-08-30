param(
  [ValidateSet('auto', 'lock', 'unlock')]
  [string]$Action = 'auto',
  [string]$PhoneAuth,
  [switch]$DryRun,
  [Parameter(Position = 0, ValueFromRemainingArguments = $true)]
  [string[]]$Paths
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2

Add-Type -AssemblyName System.Windows.Forms

function Fail([string]$Message) {
  if ($DryRun) { throw $Message }
  [System.Windows.Forms.MessageBox]::Show(
    $Message, 'PhoneAuth File Locker', 'OK', 'Error'
  ) | Out-Null
  exit 2
}

if (-not $Paths -or $Paths.Count -eq 0) {
  Fail 'Select at least one regular file.'
}

$Files = @($Paths | ForEach-Object {
  $resolved = [System.IO.Path]::GetFullPath($_)
  if (-not [System.IO.File]::Exists($resolved)) {
    Fail "Not a regular file: $resolved"
  }
  $resolved
})

$allLocked = @($Files | Where-Object {
  [System.IO.Path]::GetExtension($_) -ieq '.balock'
}).Count -eq $Files.Count
$noneLocked = @($Files | Where-Object {
  [System.IO.Path]::GetExtension($_) -ieq '.balock'
}).Count -eq 0
if ($Action -eq 'auto') {
  if ($allLocked) { $Action = 'unlock' }
  elseif ($noneLocked) { $Action = 'lock' }
  else { Fail 'Lock and unlock selections cannot be mixed.' }
}
if (($Action -eq 'lock' -and -not $noneLocked) -or
    ($Action -eq 'unlock' -and -not $allLocked)) {
  Fail "The selected files do not match the requested $Action action."
}

if (-not $PhoneAuth) {
  $PhoneAuth = Join-Path (Split-Path $PSScriptRoot -Parent) 'bin\phone-auth.exe'
}
if (-not $DryRun -and -not [System.IO.File]::Exists($PhoneAuth)) {
  Fail "phone-auth.exe was not found at $PhoneAuth"
}

$Arguments = @('locker', $Action) + $Files
if ($Files.Count -gt 1) { $Arguments += '--batch' }

if ($Action -eq 'lock') {
  $recovery = $env:PHONEAUTH_RECOVERY_OUT
  if (-not $recovery -and -not $DryRun) {
    if ($Files.Count -eq 1) {
      $dialog = New-Object System.Windows.Forms.SaveFileDialog
      $dialog.Title = 'Save the offline recovery code somewhere separate'
      $dialog.FileName = ([System.IO.Path]::GetFileName($Files[0]) + '.recovery')
      $dialog.Filter = 'Recovery code (*.recovery)|*.recovery|All files (*.*)|*.*'
      if ($dialog.ShowDialog() -ne 'OK') { exit 1 }
      $recovery = $dialog.FileName
    } else {
      $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
      $dialog.Description = 'Choose a directory for one recovery code per file'
      if ($dialog.ShowDialog() -ne 'OK') { exit 1 }
      $recovery = $dialog.SelectedPath
    }
  }
  if (-not $recovery) { $recovery = 'RECOVERY_PATH' }
  $Arguments += @('--recovery-out', [System.IO.Path]::GetFullPath($recovery))
  # File-manager actions default to the reversible choice. The user can delete
  # the original after opening the new container and moving the recovery code.
  $Arguments += '--keep-original'
} else {
  # Same rule on unlock: leave the container until the restored file was
  # inspected. The CLI remains available for explicitly destructive use.
  $Arguments += '--keep-container'
}

if ($DryRun) {
  [pscustomobject]@{ executable = $PhoneAuth; arguments = $Arguments } |
    ConvertTo-Json -Compress
  exit 0
}

& $PhoneAuth @Arguments
$exitCode = $LASTEXITCODE
if ($exitCode -ne 0) {
  [System.Windows.Forms.MessageBox]::Show(
    "The File Locker command failed (exit $exitCode).",
    'PhoneAuth File Locker', 'OK', 'Error'
  ) | Out-Null
}
exit $exitCode
