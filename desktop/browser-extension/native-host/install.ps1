[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [ValidateSet('Install', 'Uninstall')]
    [string]$Action = 'Install',
    [string]$HostPath,
    [string]$ChromeExtensionId,
    [string]$EdgeExtensionId,
    [string]$FirefoxExtensionId = 'webauthn@bioauth.local',
    [ValidateSet('Chrome', 'Edge', 'Firefox')]
    [string[]]$Browsers = @('Chrome', 'Edge', 'Firefox'),
    [string]$ManifestDirectory = (Join-Path $env:LOCALAPPDATA 'PhoneAuth\NativeMessagingHosts'),
    [string]$RegistryRoot = 'HKCU:\Software'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$hostName = 'com.bioauth.webauthn'
$browserInfo = @{
    Chrome = @{
        Registry = 'Google\Chrome\NativeMessagingHosts'
        Manifest = "$hostName.chrome.json"
        Id = $ChromeExtensionId
        Allowlist = 'allowed_origins'
    }
    Edge = @{
        Registry = 'Microsoft\Edge\NativeMessagingHosts'
        Manifest = "$hostName.edge.json"
        Id = $EdgeExtensionId
        Allowlist = 'allowed_origins'
    }
    Firefox = @{
        Registry = 'Mozilla\NativeMessagingHosts'
        Manifest = "$hostName.firefox.json"
        Id = $FirefoxExtensionId
        Allowlist = 'allowed_extensions'
    }
}

function Write-JsonWithoutBom([string]$Path, [hashtable]$Info, [string]$Executable) {
    # `@(...)` around the whole conditional, not around each branch. PowerShell
    # unwraps a one-element array on its way out of a block, so
    # `$allowed = if (...) { @('one') }` assigns the *string* -- and both engines
    # require a list here. A manifest whose allowlist is a bare string is
    # rejected outright, and what the browser then reports is that the native
    # messaging host was not found: indistinguishable from never having
    # installed it, which is the worst possible way for this to fail. `install.sh`
    # prints the brackets literally and was never wrong; this is one rule that
    # two platforms implement and only one of them kept.
    $allowed = @(if ($Info.Allowlist -eq 'allowed_origins') {
        "chrome-extension://$($Info.Id)/"
    } else {
        $Info.Id
    })
    $manifest = [ordered]@{
        name = $hostName
        description = 'PhoneAuth WebAuthn bridge'
        path = $Executable
        type = 'stdio'
        $Info.Allowlist = $allowed
    }
    $temporary = "$Path.tmp-$PID"
    [IO.File]::WriteAllText($temporary, ($manifest | ConvertTo-Json -Depth 3), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

if ($Action -eq 'Install') {
    if (-not $HostPath) { throw '-HostPath is required for installation.' }
    $hostFile = Get-Item -LiteralPath $HostPath
    if ($hostFile.PSIsContainer) { throw 'HostPath must point to a file.' }
    $executable = $hostFile.FullName
    if ([IO.Path]::GetFileName($executable) -notin @('phone-auth-webauthn-host', 'phone-auth-webauthn-host.exe')) {
        throw 'HostPath must point to phone-auth-webauthn-host(.exe).'
    }
    # A file that exists is not a file that runs. A binary built for another
    # architecture, or half-copied, passes every check above and then fails at
    # each launch the browser makes -- which a browser reports as nothing at
    # all.
    #
    # Launched the way a browser launches it, with nothing on stdin: the host
    # reads end-of-stream and stops. `cmd /c` because the redirection is the
    # point and PowerShell has no operator for standard input.
    & cmd.exe /c "`"$executable`" >NUL 2>&1 <NUL"
    if ($LASTEXITCODE -ne 0) { throw "HostPath will not run: $executable" }

    foreach ($browser in $Browsers) {
        $info = $browserInfo[$browser]
        if ($info.Allowlist -eq 'allowed_origins' -and $info.Id -notmatch '^[a-p]{32}$') {
            throw "-$($browser)ExtensionId must be the 32-character Chromium extension ID."
        }
        if ($info.Allowlist -eq 'allowed_extensions' -and $info.Id -notmatch '^[^\s"\\]{1,255}$') {
            throw '-FirefoxExtensionId is invalid.'
        }
    }

    if ($PSCmdlet.ShouldProcess($ManifestDirectory, 'Install native messaging host')) {
        New-Item -ItemType Directory -Path $ManifestDirectory -Force | Out-Null
        foreach ($browser in $Browsers) {
            $info = $browserInfo[$browser]
            $manifestPath = [IO.Path]::GetFullPath((Join-Path $ManifestDirectory $info.Manifest))
            Write-JsonWithoutBom $manifestPath $info $executable
            $registryPath = Join-Path (Join-Path $RegistryRoot $info.Registry) $hostName
            New-Item -Path $registryPath -Force | Out-Null
            Set-Item -Path $registryPath -Value $manifestPath
        }
    }
    return
}

if ($PSCmdlet.ShouldProcess($ManifestDirectory, 'Uninstall native messaging host')) {
    foreach ($browser in $Browsers) {
        $info = $browserInfo[$browser]
        $registryPath = Join-Path (Join-Path $RegistryRoot $info.Registry) $hostName
        if (Test-Path -Path $registryPath) { Remove-Item -Path $registryPath -Recurse -Force }
        $manifestPath = Join-Path $ManifestDirectory $info.Manifest
        if (Test-Path -LiteralPath $manifestPath) { Remove-Item -LiteralPath $manifestPath -Force }
    }
    if ((Test-Path -LiteralPath $ManifestDirectory) -and
        -not (Get-ChildItem -LiteralPath $ManifestDirectory -Force | Select-Object -First 1)) {
        Remove-Item -LiteralPath $ManifestDirectory -Force
    }
}
