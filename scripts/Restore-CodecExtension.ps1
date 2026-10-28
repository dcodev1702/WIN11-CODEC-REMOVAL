<#
.SYNOPSIS
    Puts a removed codec package back on a computer that can reach the Microsoft Store: deletes the Deprovisioned
    key and installs the Store listing through Windows' app-install API (no Store window, no click). The undo for
    Remove-CodecExtension.ps1 on a test computer. Not usable on a network without Internet access: the package comes
    from the Store.

.DESCRIPTION
    Per package: the catalog entry (Codec-Common.ps1) gives the Store ID; the Deprovisioned key
    HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\<family> is deleted so a feature
    update may provision the package again; AppInstallManager.StartAppInstallAsync(<Store ID>) downloads and installs
    the current version for the signed-in user; the result is verified with Get-AppxPackage. The provisioning entry
    (new user profiles) does not come back this way - only Windows setup, the OEM image, or an Intune / Store for
    Business deployment provisions a package.

    Runs in Windows PowerShell 5.1 only (the app-install API is a Windows Runtime type that PowerShell 7 cannot load).
    Needs an elevated session for the registry key; the install itself runs under the signed-in user's Store account.

.PARAMETER Package
    Catalog names. Default: the removal script's default targets (WebP, HEVC, Raw, HEIF).

.PARAMETER NoConfirm
    No Y/N prompt.

.PARAMETER TimeoutMinutes
    How long to wait for each download and install. Default 10.

.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Restore-CodecExtension.ps1 -Package Microsoft.HEVCVideoExtension
    Reinstalls HEVC Video Extensions from Device Manufacturer (9N4WGH0Z6VHQ) after Continue? [Y/N].

.NOTES
    Windows PowerShell 5.1, elevated, Store reachable. ASCII-only source. Transcript in <repo>\Logs.
    Verified on 2026-10-28 on Windows 11 Enterprise 26H2 build 26300: HEVC 2.5.48.0 installed in 30 seconds.

    Generative AI was used in the creation and validation of this code; the result was reviewed and run by a person.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.HEVCVideoExtensions', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension', 'Microsoft.AV1VideoExtension', 'Microsoft.VP9VideoExtensions', 'Microsoft.MPEG2VideoExtension', 'Microsoft.WebMediaExtensions')]
    [string[]]$Package = @('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension'),
    [switch]$NoConfirm,
    [int]$TimeoutMinutes = 10,
    [string]$LogPath = ''
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Codec-Common.ps1')
. (Join-Path $PSScriptRoot 'Confirm-Change.ps1')
if (-not $LogPath) { $LogPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'Logs' }
if (-not (Test-Path -LiteralPath $LogPath -PathType Container)) { New-Item -Path $LogPath -ItemType Directory -Force -WhatIf:$false | Out-Null }
$LogBase = Join-Path $LogPath ('Restore-CodecExtension-{0:yyyyMMdd-HHmmss}' -f (Get-Date))
$StartNoWhatIf = @{}; if ((Get-Command Start-Transcript).Parameters.ContainsKey('WhatIf')) { $StartNoWhatIf = @{ WhatIf = $false } }
Start-Transcript -LiteralPath "$LogBase.log" @StartNoWhatIf | Out-Null
$Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Status, [string]$Check, [string]$Detail) { $Results.Add([pscustomobject]@{ When = (Get-Date).ToString('HH:mm:ss'); Status = $Status; Check = $Check; Detail = $Detail }); Write-Host ('{0}  {1,-4} {2} - {3}' -f (Get-Date).ToString('HH:mm:ss.fff'), $Status, $Check, $Detail) -ForegroundColor DarkGray }
try {
    if ($PSVersionTable.PSEdition -eq 'Core') { throw 'STOP: run this script in Windows PowerShell 5.1 (powershell.exe); the Store install API is a Windows Runtime type that PowerShell 7 cannot load. Nothing was changed.' }
    if (-not (Test-CodecElevated)) { throw 'STOP: run this script elevated (the Deprovisioned key is under HKLM). Nothing was changed.' }
    $Targets = @($Package | ForEach-Object { Get-CodecCatalogEntry $_ } | Where-Object { $null -ne $_ } | Select-Object -Unique)
    $Detail = New-Object System.Collections.Generic.List[string]
    $Detail.Add("Computer: $env:COMPUTERNAME, signed in as $([Security.Principal.WindowsIdentity]::GetCurrent().Name)")
    foreach ($T in $Targets) {
        if ($T.StoreId) { $Detail.Add("$($T.Name): delete the Deprovisioned key, then install $($T.DisplayName) (Store $($T.StoreId)) for this user") }
        else { $Detail.Add("$($T.Name): delete the Deprovisioned key only (no verified Store ID in the catalog)") }
    }
    $Detail.Add('Effect: the package is registered for this user and updated by the Store again; it is not provisioned for new profiles.')
    if ($WhatIfPreference) { Write-Host ''; Write-Host "WhatIf - the plan for $($env:COMPUTERNAME):" -ForegroundColor Yellow; foreach ($D in $Detail) { Write-Host "  $D" -ForegroundColor Yellow } }
    else { Confirm-Change -NoConfirm:$NoConfirm -Action "RESTORE $($Targets.Count) codec package(s) on $env:COMPUTERNAME from the Microsoft Store" -Detail $Detail.ToArray(); $ConfirmPreference = 'None' }
    $Manager = $null
    if (-not $WhatIfPreference) {
        Add-Type -AssemblyName System.Runtime.WindowsRuntime
        $null = [Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager, Windows.ApplicationModel.Store.Preview, ContentType = WindowsRuntime]
        $AsTask = @([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]
        $Manager = New-Object Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallManager
    }
    foreach ($T in $Targets) {
        $Key = Join-Path $CodecDeprovisionedKeyRoot "$($T.Name)_$($CodecPublisherId)"
        if (Test-Path -LiteralPath $Key) {
            if ($PSCmdlet.ShouldProcess($Key, 'Delete registry key')) { Remove-Item -LiteralPath $Key -Force; Add-Result OK "$($T.Name) key" "deleted $Key" }
            else { Add-Result OK "$($T.Name) key" "WhatIf: would delete $Key" }
        }
        else { Add-Result OK "$($T.Name) key" 'no Deprovisioned key present' }
        if (-not $T.StoreId) { Add-Result WARN "$($T.Name) install" 'no verified Store ID in the catalog; install it from the Store app'; continue }
        if (-not $PSCmdlet.ShouldProcess("$($T.DisplayName) ($($T.StoreId))", 'Install from the Microsoft Store')) { Add-Result OK "$($T.Name) install" "WhatIf: would install $($T.DisplayName) ($($T.StoreId))"; continue }
        $Task = $AsTask.MakeGenericMethod([Windows.ApplicationModel.Store.Preview.InstallControl.AppInstallItem]).Invoke($null, @($Manager.StartAppInstallAsync($T.StoreId, $null, $false, $false)))
        [void]$Task.Wait(-1)
        $Item = $Task.Result
        $Deadline = (Get-Date).AddMinutes($TimeoutMinutes)
        $Status = $null
        do {
            Start-Sleep -Seconds 3
            $Status = $Item.GetCurrentStatus()
            Write-Host ("  {0} {1} {2}% {3}" -f (Get-Date).ToString('HH:mm:ss'), $Status.InstallState, [int]$Status.PercentComplete, $(if ($Status.ErrorCode) { $Status.ErrorCode } else { '' })) -ForegroundColor DarkGray
        } while (@('Completed', 'Canceled', 'Error') -notcontains "$($Status.InstallState)" -and (Get-Date) -lt $Deadline)
        $Installed = @(Get-AppxPackage -Name $T.Name -ErrorAction SilentlyContinue)
        if ("$($Status.InstallState)" -eq 'Completed' -and $Installed.Count -gt 0) { Add-Result OK "$($T.Name) install" "installed $($Installed[0].PackageFullName) from the Store ($($T.StoreId))" }
        elseif ($Installed.Count -gt 0) { Add-Result WARN "$($T.Name) install" "the Store reported $($Status.InstallState) $($Status.ErrorCode), but $($Installed[0].PackageFullName) is registered" }
        else { Add-Result FAIL "$($T.Name) install" "the Store reported $($Status.InstallState) $($Status.ErrorCode) after $TimeoutMinutes minute(s) at most; the package is not registered. Is the Store reachable and signed in?" }
    }
}
catch { Add-Result FAIL 'Stopped' $_.Exception.Message }
finally {
    Write-Host ''
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $Results | Export-Csv -LiteralPath "$LogBase.csv" -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $FailCount = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    if ($FailCount -gt 0) { Write-Host "RESULT: FAILED ($FailCount failed) - $LogBase.log" -ForegroundColor Red } else { Write-Host "RESULT: PASSED - $LogBase.log" -ForegroundColor Green }
    try { Stop-Transcript | Out-Null } catch { }
}
if (@($Results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { exit 1 }
