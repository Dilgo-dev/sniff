# sniff installer for Windows.
# Usage: irm getsniff.sh/install.ps1 | iex

$ErrorActionPreference = "Stop"

$Repo = "Dilgo-dev/sniff"
$Binary = "sniff.exe"
$InstallDir = "$env:LOCALAPPDATA\sniff"

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "x86_64" }
        "ARM64" { return "aarch64" }
        default {
            Write-Error "unsupported architecture: $env:PROCESSOR_ARCHITECTURE"
            exit 1
        }
    }
}

function Main {
    $Arch = Get-Arch

    $Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
    $Tag = $Release.tag_name

    if (-not $Tag) {
        Write-Error "could not fetch latest release"
        exit 1
    }

    $Asset = "sniff-$Tag-windows-$Arch.zip"
    $Url = "https://github.com/$Repo/releases/download/$Tag/$Asset"

    Write-Host "sniff $Tag (windows/$Arch)"
    Write-Host "downloading $Url"

    $TmpDir = Join-Path $env:TEMP "sniff-install-$(Get-Random)"
    New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

    try {
        $ZipPath = Join-Path $TmpDir $Asset
        Invoke-WebRequest -Uri $Url -OutFile $ZipPath -UseBasicParsing

        Expand-Archive -Path $ZipPath -DestinationPath $TmpDir -Force

        if (-not (Test-Path (Join-Path $TmpDir $Binary))) {
            Write-Error "binary not found in archive"
            exit 1
        }

        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        Move-Item -Path (Join-Path $TmpDir $Binary) -Destination (Join-Path $InstallDir $Binary) -Force

        # Add to PATH if not already there
        $CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($CurrentPath -notlike "*$InstallDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$InstallDir", "User")
            Write-Host "added $InstallDir to PATH (restart terminal to take effect)"
        }

        Write-Host "installed sniff $Tag to $InstallDir\$Binary"
        Write-Host "run as administrator: $InstallDir\$Binary"
    }
    finally {
        Remove-Item -Path $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Main
