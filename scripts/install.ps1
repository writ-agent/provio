# Install provio into $HOME\.provio\bin (Windows x64).
#
#   irm https://raw.githubusercontent.com/writ-agent/provio/main/scripts/install.ps1 | iex
#
# Downloads provio-x86_64-pc-windows-msvc.exe from the GitHub release and
# checks it against the release's checksums.txt before installing. (Each
# binary also has a Sigstore bundle; see the release notes to verify it with
# cosign.) The install directory is added to your user PATH only if you set
# $env:PROVIO_ADD_TO_PATH = "1".
#
#   $env:PROVIO_VERSION = "v0.1.2"   a specific release (default: latest)
#   $env:PROVIO_BIN_DIR = "D:\tools" where to install

$ErrorActionPreference = "Stop"
$repo = if ($env:PROVIO_REPO) { $env:PROVIO_REPO } else { "writ-agent/provio" }
$version = if ($env:PROVIO_VERSION) { $env:PROVIO_VERSION } else { "latest" }
$binDir = if ($env:PROVIO_BIN_DIR) { $env:PROVIO_BIN_DIR } else { Join-Path $HOME ".provio\bin" }

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "provio ships a 64-bit Windows binary only"
}
$asset = "provio-x86_64-pc-windows-msvc.exe"
$base = if ($version -eq "latest") {
    "https://github.com/$repo/releases/latest/download"
} else {
    "https://github.com/$repo/releases/download/$version"
}

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("provio-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host "downloading $base/$asset"
    Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile (Join-Path $tmp $asset)
    Invoke-WebRequest -UseBasicParsing -Uri "$base/checksums.txt" -OutFile (Join-Path $tmp "checksums.txt")

    $want = $null
    foreach ($line in Get-Content (Join-Path $tmp "checksums.txt")) {
        $parts = $line -split '\s+', 2
        if ($parts.Count -eq 2 -and $parts[1].TrimStart('*') -eq $asset) { $want = $parts[0].ToLower() }
    }
    if (-not $want) { throw "$asset is not listed in the release's checksums.txt; not installing" }
    $got = (Get-FileHash -Algorithm SHA256 (Join-Path $tmp $asset)).Hash.ToLower()
    if ($got -ne $want) { throw "checksum mismatch for $asset (expected $want, got $got); not installing" }
    Write-Host "checksum ok ($want)"

    $dest = Join-Path $binDir "provio.exe"
    Move-Item -Force (Join-Path $tmp $asset) $dest
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$ver = try { & $dest --version } catch { "version unknown" }
Write-Host "installed: $dest ($ver)"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $binDir) {
    if ($env:PROVIO_ADD_TO_PATH -eq "1") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
        Write-Host "added $binDir to your user PATH (open a new terminal)"
    } else {
        Write-Host "add it to PATH:  `$env:Path += `";$binDir`"   (or rerun with `$env:PROVIO_ADD_TO_PATH = `"1`")"
    }
}
Write-Host "next:  provio scan    (what would provio have caught?)   then   provio init"
