# Install writ into $HOME\.writ\bin (Windows x64).
#
#   irm https://raw.githubusercontent.com/writ-agent/writ/main/scripts/install.ps1 | iex
#
# Downloads writ-x86_64-pc-windows-msvc.exe from the GitHub release and
# checks it against the release's checksums.txt before installing. (Each
# binary also has a Sigstore bundle; see the release notes to verify it with
# cosign.) The install directory is added to your user PATH only if you set
# $env:WRIT_ADD_TO_PATH = "1".
#
#   $env:WRIT_VERSION = "v0.1.2"   a specific release (default: latest)
#   $env:WRIT_BIN_DIR = "D:\tools" where to install

$ErrorActionPreference = "Stop"
$repo = if ($env:WRIT_REPO) { $env:WRIT_REPO } else { "writ-agent/writ" }
$version = if ($env:WRIT_VERSION) { $env:WRIT_VERSION } else { "latest" }
$binDir = if ($env:WRIT_BIN_DIR) { $env:WRIT_BIN_DIR } else { Join-Path $HOME ".writ\bin" }

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "writ ships a 64-bit Windows binary only"
}
$asset = "writ-x86_64-pc-windows-msvc.exe"
$base = if ($version -eq "latest") {
    "https://github.com/$repo/releases/latest/download"
} else {
    "https://github.com/$repo/releases/download/$version"
}

New-Item -ItemType Directory -Force -Path $binDir | Out-Null
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("writ-install-" + [Guid]::NewGuid())
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

    $dest = Join-Path $binDir "writ.exe"
    Move-Item -Force (Join-Path $tmp $asset) $dest
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

$ver = try { & $dest --version } catch { "version unknown" }
Write-Host "installed: $dest ($ver)"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $binDir) {
    if ($env:WRIT_ADD_TO_PATH -eq "1") {
        [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
        Write-Host "added $binDir to your user PATH (open a new terminal)"
    } else {
        Write-Host "add it to PATH:  `$env:Path += `";$binDir`"   (or rerun with `$env:WRIT_ADD_TO_PATH = `"1`")"
    }
}
Write-Host "next:  writ scan    (what would writ have caught?)   then   writ init"
