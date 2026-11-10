# Installs the latest meiosis release (mei and meiosisd.exe) for Windows by
# fetching the release zip and SHA256SUMS from GitHub, verifying the checksum,
# and installing into $env:LOCALAPPDATA\mei (added to PATH for the user).
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#   powershell -ExecutionPolicy Bypass -Command "irm https://<repo>/releases/latest/download/install.ps1 | iex"
#
# Env overrides:
#   $env:MEI_VERSION        - install a specific version (default: latest release)
#   $env:MEI_REPO           - GitHub repo to fetch from (default: subhranshus-mindfire/meiosis)
#   $env:MEI_PREFIX         - install directory (default: $env:LOCALAPPDATA\mei)

$ErrorActionPreference = "Stop"

$version = if ($env:MEI_VERSION) { $env:MEI_VERSION } else { "latest" }
$repo = if ($env:MEI_REPO) { $env:MEI_REPO } else { "subhranshus-mindfire/meiosis" }
$prefix = if ($env:MEI_PREFIX) { $env:MEI_PREFIX } else { Join-Path $env:LOCALAPPDATA "mei" }

$osArch = $env:PROCESSOR_ARCHITECTURE
if ($osArch -eq "AMD64") { $goarch = "amd64" }
elseif ($osArch -eq "ARM64") { $goarch = "arm64" }
else { throw "Unsupported architecture: $osArch (amd64/arm64 only)" }

if ($version -eq "latest") {
    $base = "https://github.com/$repo/releases/latest/download"
} else {
    $base = "https://github.com/$repo/releases/download/$version"
}
$archive = "mei-windows-$goarch.zip"

Write-Host "[mei install] platform: windows/$goarch, version: $version"
Write-Host "[mei install] downloading $archive from $repo..."

$tmp = Join-Path $env:TEMP ("mei-install-" + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    $zipPath = Join-Path $tmp $archive
    Invoke-WebRequest "$base/$archive" -OutFile $zipPath
    Invoke-WebRequest "$base/SHA256SUMS.txt" -OutFile (Join-Path $tmp "SHA256SUMS.txt")

    $expectedLine = Get-Content (Join-Path $tmp "SHA256SUMS.txt") | Where-Object { $_ -like "*  ./$archive" }
    if (-not $expectedLine) {
        $expectedLine = Get-Content (Join-Path $tmp "SHA256SUMS.txt") | Where-Object { $_ -like "*$archive" }
    }
    if (-not $expectedLine) { throw "Checksum for $archive not found in SHA256SUMS.txt" }
    $expected = ($expectedLine -split "\s+")[0]
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $expected.ToLowerInvariant()) { throw "Checksum mismatch for $archive" }
    Write-Host "[mei install] checksum verified"

    $extract = Join-Path $tmp "extract"
    Expand-Archive -LiteralPath $zipPath -DestinationPath $extract -Force

    New-Item -ItemType Directory -Path $prefix -Force | Out-Null
    Copy-Item "$extract\mei-windows-$goarch\mei.exe" $prefix -Force
    Copy-Item "$extract\mei-windows-$goarch\meiosisd.exe" $prefix -Force

    Write-Host "[mei install] installed to $prefix:"
    & (Join-Path $prefix "mei.exe") version
    & (Join-Path $prefix "meiosisd.exe") -version

    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -notlike "*$prefix*") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$prefix", "User")
        Write-Host "[mei install] added $prefix to your user PATH. Open a NEW terminal, then run: mei init --ide vscode"
    } else {
        Write-Host "[mei install] done. next: mei init --ide vscode"
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}