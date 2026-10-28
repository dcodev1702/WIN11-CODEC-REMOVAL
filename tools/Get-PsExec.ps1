<#
.SYNOPSIS
    On an Internet-connected computer: downloads Sysinternals PsTools, checks PsExec64.exe and PsExec.exe against
    the SHA256 hashes pinned in scripts\Codec-System.ps1 and copies them (and the license) into this folder. With
    -VerifyOnly: checks the files already here. Use it when the binaries are not kept in source control.

.DESCRIPTION
    The isolated network has no Internet; PsExec has to travel with the folder. Run this once on a connected
    computer, then copy the whole folder. The script refuses to keep a file whose hash is not the pinned one (a
    newer PsTools release changes the hash: update tools\THIRD-PARTY-NOTICES.md, tools\SHA256SUMS.txt and
    $CodecPsExecHash together, after checking the Authenticode signature).

.PARAMETER VerifyOnly
    Do not download; check the files in this folder against the pinned hashes and the Authenticode signature.

.PARAMETER Uri
    Where to download PSTools.zip from. Default https://download.sysinternals.com/files/PSTools.zip

.EXAMPLE
    .\tools\Get-PsExec.ps1
    Downloads, verifies, copies PsExec64.exe, PsExec.exe and Eula.txt (as Sysinternals-EULA.txt) into tools\.

.EXAMPLE
    .\tools\Get-PsExec.ps1 -VerifyOnly
    Checks the files in tools\ (on the isolated network, before the first -RunAsSystem run).

.NOTES
    Windows PowerShell 5.1 and PowerShell 7. ASCII-only source. Sysinternals license: tools\Sysinternals-EULA.txt.
#>
[CmdletBinding()]
param([switch]$VerifyOnly, [string]$Uri = 'https://download.sysinternals.com/files/PSTools.zip')
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\Codec-Common.ps1')
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'scripts\Codec-System.ps1')
$Failed = 0
function Show([string]$Name) {
    $R = Test-CodecPsExec -Path (Join-Path $PSScriptRoot $Name)
    if ($R.Ok) { Write-Host "OK    $Name $($R.Version) - SHA256 matches the pinned value - Authenticode $($R.SignatureStatus) ($($R.Signer))" -ForegroundColor Green }
    else { $script:Failed++; Write-Host "FAIL  $Name - $($R.Reason)" -ForegroundColor Red }
}
if (-not $VerifyOnly) {
    $Tmp = Join-Path ([IO.Path]::GetTempPath()) ('pstools-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -Path $Tmp -ItemType Directory -Force | Out-Null
    try {
        $Zip = Join-Path $Tmp 'PSTools.zip'
        Write-Host "Downloading $Uri ..."
        Invoke-WebRequest -Uri $Uri -OutFile $Zip -UseBasicParsing
        Expand-Archive -LiteralPath $Zip -DestinationPath (Join-Path $Tmp 'x') -Force
        foreach ($Name in @($CodecPsExecHash.Keys | Sort-Object)) {
            $Source = Join-Path (Join-Path $Tmp 'x') $Name
            if (-not (Test-Path -LiteralPath $Source -PathType Leaf)) { $Failed++; Write-Host "FAIL  $Name is not in the ZIP" -ForegroundColor Red; continue }
            $Check = Test-CodecPsExec -Path $Source
            if (-not $Check.Ok) { $Failed++; Write-Host "FAIL  $Name from the ZIP: $($Check.Reason). Not copied. If Sysinternals released a new version, verify its signature and update the pinned hashes." -ForegroundColor Red; continue }
            Copy-Item -LiteralPath $Source -Destination (Join-Path $PSScriptRoot $Name) -Force
        }
        $Eula = Join-Path (Join-Path $Tmp 'x') 'Eula.txt'
        if (Test-Path -LiteralPath $Eula -PathType Leaf) { Copy-Item -LiteralPath $Eula -Destination (Join-Path $PSScriptRoot 'Sysinternals-EULA.txt') -Force }
    }
    finally { Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue }
}
foreach ($Name in @($CodecPsExecHash.Keys | Sort-Object)) { Show $Name }
if ($Failed -gt 0) { Write-Host "$Failed file(s) failed verification." -ForegroundColor Red; exit 1 }
Write-Host 'Every PsExec file matches its pinned hash.' -ForegroundColor Green
