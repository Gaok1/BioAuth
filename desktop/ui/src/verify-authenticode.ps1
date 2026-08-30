param([Parameter(Mandatory = $true)][string]$Path)

$ErrorActionPreference = 'Stop'
$signature = Get-AuthenticodeSignature -LiteralPath $Path
$valid = $signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate
$fileVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo(
  (Resolve-Path -LiteralPath $Path).Path
).FileVersion
[pscustomobject]@{
  valid = $valid
  status = [string]$signature.Status
  publicKey = if ($valid) { $signature.SignerCertificate.GetPublicKeyString() } else { '' }
  thumbprint = if ($valid) { $signature.SignerCertificate.Thumbprint } else { '' }
  subject = if ($valid) { $signature.SignerCertificate.Subject } else { '' }
  fileVersion = if ($valid) { [string]$fileVersion } else { '' }
} | ConvertTo-Json -Compress
