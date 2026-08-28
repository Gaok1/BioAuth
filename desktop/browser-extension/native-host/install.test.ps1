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
    & $installer -Action Install -HostPath $hostPath -ChromeExtensionId $ids.Chrome `
        -EdgeExtensionId $ids.Edge -ManifestDirectory $manifestDirectory -RegistryRoot $registryRoot

    foreach ($browser in @('Chrome', 'Edge', 'Firefox')) {
        $leaf = $browser.ToLowerInvariant()
        $manifestPath = Join-Path $manifestDirectory "com.bioauth.webauthn.$leaf.json"
        if (-not (Test-Path -LiteralPath $manifestPath)) { throw "$browser manifest was not installed." }
        $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ($manifest.path -ne $hostPath) { throw "$browser manifest has the wrong host path." }
        if ($browser -eq 'Firefox') {
            if ($manifest.allowed_extensions -ne 'webauthn@bioauth.local') { throw 'Firefox allowlist is wrong.' }
        } else {
            $expected = "chrome-extension://$($ids[$browser])/"
            if ($manifest.allowed_origins -ne $expected) { throw "$browser allowlist is wrong." }
        }
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
