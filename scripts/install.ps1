param(
    [string]$Version = $env:PSIRTMAP_VERSION,
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\PSIRTMap",
    [switch]$NoPathUpdate
)

$ErrorActionPreference = "Stop"
$repository = "solongate/psirtmap"

if (-not $Version) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$repository/releases/latest"
    $Version = $release.tag_name
}
if (-not $Version) {
    throw "Could not determine the latest PSIRTMap release."
}
if (-not $Version.StartsWith("v")) {
    $Version = "v$Version"
}

$releaseVersion = $Version.TrimStart("v")
$package = "psirtmap_${releaseVersion}_windows_amd64"
$archive = "$package.zip"
$baseUrl = "https://github.com/$repository/releases/download/$Version"
$temporaryDir = Join-Path ([System.IO.Path]::GetTempPath()) ("psirtmap-install-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $temporaryDir | Out-Null

try {
    Write-Host "Downloading PSIRTMap $Version for windows/amd64..."
    Invoke-WebRequest "$baseUrl/$archive" -OutFile (Join-Path $temporaryDir $archive)
    Invoke-WebRequest "$baseUrl/checksums.txt" -OutFile (Join-Path $temporaryDir "checksums.txt")

    $checksumLine = Get-Content (Join-Path $temporaryDir "checksums.txt") |
        Where-Object { ($_ -split '\s+')[-1].TrimStart('.', '/') -eq $archive } |
        Select-Object -First 1
    if (-not $checksumLine) {
        throw "Release checksum for $archive was not found."
    }
    $expected = ($checksumLine -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash (Join-Path $temporaryDir $archive) -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "Checksum verification failed."
    }

    Expand-Archive (Join-Path $temporaryDir $archive) -DestinationPath $temporaryDir
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $temporaryDir "$package\psirtmap.exe") (Join-Path $InstallDir "psirtmap.exe") -Force

    if (-not $NoPathUpdate) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $entries = @($userPath -split ';' | Where-Object { $_ })
        if ($entries -notcontains $InstallDir) {
            $updatedPath = (($entries + $InstallDir) -join ';')
            [Environment]::SetEnvironmentVariable("Path", $updatedPath, "User")
            Write-Host "Added $InstallDir to your user PATH. Open a new terminal before running PSIRTMap."
        }
    }

    Write-Host "Installed PSIRTMap $Version to $InstallDir\psirtmap.exe"
    Write-Host "Run: psirtmap"
}
finally {
    if (Test-Path $temporaryDir) {
        Remove-Item -Recurse -Force $temporaryDir
    }
}
