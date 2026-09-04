$ErrorActionPreference = 'Stop'
$installer = Join-Path $PSScriptRoot 'install.ps1'
$temporary = Join-Path ([IO.Path]::GetTempPath()) "bioauth-native-host-$([guid]::NewGuid().ToString('N'))"
$registryRoot = "HKCU:\Software\BioAuthNativeHostTest-$([guid]::NewGuid().ToString('N'))"
$manifestDirectory = Join-Path $temporary 'manifests'
$hostPath = Join-Path $temporary 'phone-auth-webauthn-host.exe'
$ids = @{ Chrome = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'; Edge = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' }

try {
    New-Item -ItemType Directory -Path $temporary | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSHOME 'powershell.exe') -Destination $hostPath

    # A file with the right name and the wrong contents: half a copy, or a
    # build for another architecture. Every check the installer makes on the
    # path itself passes, and every launch the browser makes would fail with
    # nothing said, so the installer has to refuse it here.
    $brokenDirectory = Join-Path $temporary 'broken'
    New-Item -ItemType Directory -Path $brokenDirectory | Out-Null
    $brokenHost = Join-Path $brokenDirectory 'phone-auth-webauthn-host.exe'
    Set-Content -LiteralPath $brokenHost -Value 'not a program' -Encoding utf8
    $refused = $false
    try {
        & $installer -Action Install -HostPath $brokenHost -ChromeExtensionId $ids.Chrome `
            -EdgeExtensionId $ids.Edge -ManifestDirectory $manifestDirectory -RegistryRoot $registryRoot
    } catch {
        $refused = $true
    }
    if (-not $refused) { throw 'The installer accepted a host that will not run.' }
    if (Test-Path -LiteralPath (Join-Path $manifestDirectory 'com.bioauth.webauthn.chrome.json')) {
        throw 'The installer left a manifest pointing at a host that will not run.'
    }
    & $installer -Action Install -HostPath $hostPath -ChromeExtensionId $ids.Chrome `
        -EdgeExtensionId $ids.Edge -ManifestDirectory $manifestDirectory -RegistryRoot $registryRoot

    foreach ($browser in @('Chrome', 'Edge', 'Firefox')) {
        $leaf = $browser.ToLowerInvariant()
        $manifestPath = Join-Path $manifestDirectory "com.bioauth.webauthn.$leaf.json"
        if (-not (Test-Path -LiteralPath $manifestPath)) { throw "$browser manifest was not installed." }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.path -ne $hostPath) { throw "$browser manifest has the wrong host path." }
        # Asserted as a *list*, which is the half the old check could not see.
        # `-ne` against a bare string compares strings and passes; against a
        # one-element array it filters and returns nothing, which is falsy and
        # also passes. Both worlds looked identical to it, and the one PowerShell
        # actually produced was the broken one -- a scalar allowlist that every
        # browser rejects.
        if ($browser -eq 'Firefox') {
            $allowlist = $manifest.allowed_extensions
            $expected = 'webauthn@bioauth.local'
        } else {
            $allowlist = $manifest.allowed_origins
            $expected = "chrome-extension://$($ids[$browser])/"
        }
        if ($allowlist -isnot [Array]) { throw "$browser allowlist must be a JSON array." }
        if ($allowlist.Count -ne 1) { throw "$browser allowlist must name exactly one caller." }
        if ($allowlist[0] -ne $expected) { throw "$browser allowlist is wrong." }
    }

    $registryPaths = @(
        'Google\Chrome\NativeMessagingHosts',
        'Microsoft\Edge\NativeMessagingHosts',
        'Mozilla\NativeMessagingHosts'
    )
    foreach ($path in $registryPaths) {
        $key = Join-Path (Join-Path $registryRoot $path) 'com.bioauth.webauthn'
        $value = (Get-Item -Path $key).GetValue('')
        if (-not [IO.Path]::IsPathRooted($value)) { throw "Registry value is not absolute: $value" }
    }

    & $installer -Action Uninstall -ManifestDirectory $manifestDirectory -RegistryRoot $registryRoot
    foreach ($path in $registryPaths) {
        if (Test-Path (Join-Path (Join-Path $registryRoot $path) 'com.bioauth.webauthn')) {
            throw "Registry key was not removed: $path"
        }
    }
    if (Test-Path -LiteralPath $manifestDirectory) { throw 'Manifest directory was not removed.' }
    Write-Output 'Windows native-host installer test passed.'
} finally {
    Remove-Item -Path $registryRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue
}
