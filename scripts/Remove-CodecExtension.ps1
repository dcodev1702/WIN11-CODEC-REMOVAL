<#
.SYNOPSIS
    Removes the Microsoft Store codec packages that keep showing up in vulnerability scans - WebP Image Extension,
    HEVC Video Extensions, Raw Image Extension and HEIF Image Extensions by default - from a Windows 10/11 computer
    or from a mounted golden image: for every user profile, from the provisioning list, and with the registry key
    that stops feature updates from bringing them back. Read-only by default (-Mode Check).

.DESCRIPTION
    WHAT THESE PACKAGES ARE AND WHERE THEY COME FROM
      They are Microsoft Store apps (publisher ID 8wekyb3d8bbwe) that Windows setup "provisions" into the image, so
      every new user profile gets them registered at first sign-in. The files live under
      C:\Program Files\WindowsApps\<PackageFullName>\ and plug into the Windows Imaging Component (image codecs) or
      Media Foundation (video codecs), so Photos, Paint, Explorer thumbnails, Media Player, Edge and every WebView2
      app pick them up. Microsoft moved these decoders out of the OS into Store packages so they could be updated
      and licensed separately (HEVC is patent-encumbered: the OEM pays for the "from Device Manufacturer" copy,
      retail users buy 9NMZLZ57R3T7). The consequence for an enterprise: they are updated ONLY by the Microsoft
      Store, never by Windows Update, WSUS or Configuration Manager, and they are parsers for hostile file formats
      written in C/C++ (libwebp, LibRaw, Microsoft's HEVC decoder), which is why a new remote-code-execution CVE
      against them appears every few months and why a fleet whose Store updates are off stays "vulnerable" forever.

      Default targets (the scanner hits, plus HEIF, which decodes nothing once HEVC is gone):
        Microsoft.WebpImageExtension   WebP Image Extension                          Store 9PG2DK419DRG
        Microsoft.HEVCVideoExtension   HEVC Video Extensions from Device Manufacturer Store 9N4WGH0Z6VHQ
        Microsoft.RawImageExtension    Raw Image Extension                            Store 9NCTDW2W1BH8
        Microsoft.HEIFImageExtension   HEIF Image Extensions                          Store 9PMMSR1CGPWG
      Also allowed with -Package: Microsoft.HEVCVideoExtensions (the paid listing), Microsoft.AV1VideoExtension,
      Microsoft.VP9VideoExtensions, Microsoft.MPEG2VideoExtension, Microsoft.WebMediaExtensions. Anything else is
      rejected by ValidateSet.

    WHAT THE SCRIPT DOES (online, the running OS)
      1. Pre-flight, nothing changed: elevation, Windows build 17134+ (10 1803, where a deprovisioned package stays
         removed across feature updates), one instance at a time (mutex), Appx + Dism modules (PowerShell 7 loads
         Dism through Windows PowerShell compatibility because the native import fails with "Class not registered").
      2. Inventory, read-only: every target package registered to any user (Get-AppxPackage -AllUsers), every
         target in the provisioning list (Get-AppxProvisionedPackage -Online), the Deprovisioned registry keys,
         and every running process that has a package file loaded - the cause of "the app is in use".
      3. -Mode Check stops here: FAIL rows (exit 1) for every target still present, WARN for a missing key.
      4. -Mode Remove shows the plan in yellow and asks Continue? [Y/N] (-NoConfirm for automation, -WhatIf for the
         plan only), writes an inventory file, then per package:
           Remove-AppxPackage -AllUsers           every user profile, including profiles that are not loaded
           Remove-AppxProvisionedPackage -Online  new profiles no longer get it
           Deprovisioned registry key             HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\
                                                  AppxAllUserStore\Deprovisioned\<PackageFamilyName>
         and finally re-reads all three from the system to verify. No reboot is needed.

    WHY "THE APP IS IN USE" AND WHY SYSTEM DOES NOT HELP
      Remove-AppxPackage fails with 0x80073D02 (ERROR_PACKAGES_IN_USE) when any process has a DLL from the package
      folder loaded. For the HEVC package that is normally Microsoft Edge and every WebView2 host (new Teams,
      new Outlook, Widgets, Copilot ...), which load hevcdecoder_store.dll when they enumerate Media Foundation
      decoders; for the image codecs it is Photos, Paint, a thumbnail COM surrogate (dllhost) or Explorer itself.
      Running as NT AUTHORITY\SYSTEM (psexec -s) changes nothing about those file locks - the same error comes back.
      An elevated administrator is all the rights the removal needs. What frees the files is closing those
      processes: -Mode Check lists them, and -StopBlockingProcesses stops them (Explorer is restarted afterwards;
      system, security and management processes are never killed - the run refuses instead). On a golden-image
      build in audit mode nothing holds the files and the removal just works.

    GOLDEN IMAGE
      Reference computer (audit mode, before sysprep /generalize): run -Mode Remove -NoConfirm there. Removing for
      every user AND deprovisioning is required, otherwise sysprep fails (Microsoft KB "Sysprep fails after you
      remove or update Microsoft Store apps").
      Offline WIM/VHDX: Mount-WindowsImage, then -Mode Remove -MountedImagePath <mount folder>. The script removes
      the provisioning and writes the Deprovisioned keys into the image's SOFTWARE hive (loaded with reg.exe and
      unloaded again). A captured image that already contains user profiles keeps their registrations; that case
      needs the online run on the reference computer.

    SAFETY
      Every STOP happens before the first change, or says precisely what was changed. Blocked packages are
      reported as FAIL and skipped; everything else is still done. The removal is reversible: reinstall from the
      Microsoft Store (or winget install --id <StoreId> -s msstore) and delete the Deprovisioned key. Users who can
      open the Store can reinstall a package on their own; the script warns when the Store is not blocked by policy.

    EVIDENCE
      Transcript and CSV of PASS/WARN/FAIL rows in -LogPath, an inventory JSON (before and after) in -OutputPath,
      and Application events from source CodecExtensionRemoval: 1000 run started, 1001 package removed, 1002
      nothing to do, 2001 package in use, 2002 warning, 3000 run stopped, 3001 removal failed.

.PARAMETER Mode
    Check (default) reports and changes nothing; exit code 1 when any target is still installed or provisioned.
    Remove performs the removal.

.PARAMETER Package
    Package names to handle. Default: Microsoft.WebpImageExtension, Microsoft.HEVCVideoExtension,
    Microsoft.RawImageExtension, Microsoft.HEIFImageExtension. Only the codec packages listed in the catalog are
    accepted. To keep HEIF, pass the first three names.

.PARAMETER MountedImagePath
    Offline servicing: the folder a Windows image is mounted at (Mount-WindowsImage -Path). Empty (default) means
    the running operating system. The running OS and its system drive are refused here.

.PARAMETER StopBlockingProcesses
    Stop the processes that have a package file loaded (Edge, WebView2 hosts, Photos, dllhost ...) before the
    removal; Explorer is stopped and started again. Without it a package in use is reported as FAIL and skipped.
    On a user's computer this closes their browser and WebView2-based apps - run it at logon or maintenance time.

.PARAMETER LogPath
    Folder for the transcript and the CSV. Default <repo>\Logs. Use a writable path when deploying from a
    read-only share.

.PARAMETER OutputPath
    Folder for the inventory JSON (state before and after). Default <repo>\Outputs.

.PARAMETER DeprovisionedKeyRoot
    The Deprovisioned registry key. Leave the default; the tests point it at a key under HKCU.

.PARAMETER NoConfirm
    No Y/N prompt (Intune, Configuration Manager, scheduled task, image build). The plan is still printed and
    transcribed. A non-interactive session without -NoConfirm stops before changing anything.

.PARAMETER WhatIf
    Shows the plan and changes nothing. No prompt.

.EXAMPLE
    .\Remove-CodecExtension.ps1
    Read-only: which of the four packages are installed (for whom), provisioned, keyed, and which processes hold
    them. Exit code 1 while any is present.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove -WhatIf
    The exact plan for this computer, nothing changed, nothing asked.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove
    Removes the four packages for every user, deprovisions them and writes the keys, after Continue? [Y/N].
    A package held by a running process is reported and skipped.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove -StopBlockingProcesses -NoConfirm
    Unattended removal that first closes Edge, WebView2 hosts and anything else holding a package file.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove -Package Microsoft.HEIFImageExtension -NoConfirm
    Only HEIF Image Extensions, for example on a computer where the other three are already gone. -Package limits
    the run to the names given.

.EXAMPLE
    Mount-WindowsImage -ImagePath D:\Images\install.wim -Index 3 -Path C:\Mount
    .\Remove-CodecExtension.ps1 -Mode Remove -MountedImagePath C:\Mount -NoConfirm
    Dismount-WindowsImage -Path C:\Mount -Save
    Golden image, offline: deprovision in the WIM and write the Deprovisioned keys into its SOFTWARE hive.

.INPUTS
    None. The script does not accept pipeline input.

.OUTPUTS
    PASS/WARN/FAIL table on the console, the same rows as CSV, a transcript, inventory JSON files. Exit code 1 when
    any row is FAIL (Check: a target is still present; Remove: a removal failed or was blocked).

.NOTES
    Written for PowerShell 7; also runs in Windows PowerShell 5.1. ASCII-only source. Run elevated.
    tests\Test-CodecRemoval.ps1 sets $CodecRemovalHarness in its scope; the script then uses the harness's mocked
    functions instead of dot-sourcing scripts\Codec-Common.ps1 and scripts\Confirm-Change.ps1.

    Generative AI was used in the creation and validation of this code; the result was reviewed and tested by a
    person (tests in both editions, plus a live run on a Windows 11 Enterprise computer).

.LINK
    https://learn.microsoft.com/windows/application-management/remove-provisioned-apps-during-update

.LINK
    https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps

.LINK
    https://learn.microsoft.com/windows/msix/group-policy-msix

.LINK
    https://learn.microsoft.com/troubleshoot/microsoft-edge/development/video-playback-issues
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [ValidateSet('Check', 'Remove')]
    [string]$Mode = 'Check',

    [ValidateSet('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.HEVCVideoExtensions', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension', 'Microsoft.AV1VideoExtension', 'Microsoft.VP9VideoExtensions', 'Microsoft.MPEG2VideoExtension', 'Microsoft.WebMediaExtensions')]
    [string[]]$Package = @('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension'),

    [string]$MountedImagePath = '',
    [switch]$StopBlockingProcesses,
    [string]$LogPath = '',
    [string]$OutputPath = '',

    [ValidatePattern('^HK(LM|CU):\\\S+$')]
    [string]$DeprovisionedKeyRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned',

    [switch]$NoConfirm
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$UnderHarness = $null -ne (Get-Variable -Name CodecRemovalHarness -ErrorAction SilentlyContinue)   # any visible scope: the harness calls through a function
if (-not $UnderHarness) {
    . (Join-Path $PSScriptRoot 'Codec-Common.ps1')
    . (Join-Path $PSScriptRoot 'Confirm-Change.ps1')
}
else {
    # Test harness mode: every command that could change this computer must resolve to a plain function the harness
    # defined, never to a cmdlet or a module function. A real Appx/Dism module loaded in the session once reached the
    # live package store through the mocks; this guard makes that impossible.
    foreach ($Guarded in 'Get-AppxPackage', 'Remove-AppxPackage', 'Get-AppxProvisionedPackage', 'Remove-AppxProvisionedPackage', 'Stop-Process', 'Initialize-CodecModules', 'Write-CodecEvent', 'Use-CodecOfflineHive') {
        $Resolved = Get-Command -Name $Guarded -ErrorAction SilentlyContinue
        if ($null -eq $Resolved -or $Resolved.CommandType -ne 'Function' -or $null -ne $Resolved.Module) {
            throw "STOP: test harness mode, but '$Guarded' would run for real ($(if ($null -eq $Resolved) { 'not defined' } else { "$($Resolved.CommandType) from $($Resolved.ModuleName)" })). Nothing was changed."
        }
    }
}
if (-not $LogPath) { $LogPath = Join-Path $Root 'Logs' }
if (-not $OutputPath) { $OutputPath = Join-Path $Root 'Outputs' }
foreach ($Dir in @($LogPath, $OutputPath)) { if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { New-Item -Path $Dir -ItemType Directory -Force -WhatIf:$false | Out-Null } }
$Stamp = '{0:yyyyMMdd-HHmmss}' -f (Get-Date)
$LogBase = Join-Path $LogPath "Remove-CodecExtension-$Mode-$Stamp"
# PowerShell 7 applies -WhatIf to Start-Transcript and Stop-Transcript (the transcript would never open or close);
# Windows PowerShell 5.1 has -WhatIf on Start-Transcript only. Pass -WhatIf:$false where the parameter exists.
$StartNoWhatIf = @{}; $StopNoWhatIf = @{}
if ((Get-Command Start-Transcript).Parameters.ContainsKey('WhatIf')) { $StartNoWhatIf = @{ WhatIf = $false } }
if ((Get-Command Stop-Transcript).Parameters.ContainsKey('WhatIf')) { $StopNoWhatIf = @{ WhatIf = $false } }
Start-Transcript -LiteralPath "$LogBase.log" @StartNoWhatIf | Out-Null

$Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Status, [string]$Check, [string]$Detail) { $Results.Add([pscustomobject]@{ Status = $Status; Check = $Check; Detail = $Detail }) }
$Hints = New-Object System.Collections.Generic.List[string]
$Mutex = $null; $MutexHeld = $false
$ExplorerStopped = $false
$Offline = [bool]"$MountedImagePath".Trim()
$DeprovisionedRelative = 'Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned'

function Format-Blocker([object[]]$Blocker) { return ((@($Blocker) | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" } | Select-Object -Unique) -join ', ') }

# Stops the processes that hold a package file (never the ones Get-CodecBlockerAction refuses). Explorer is
# remembered so it can be started again at the end.
function Stop-CodecBlocker([object[]]$Blocker) {
    $Ids = @(@($Blocker) | Where-Object { (Get-CodecBlockerAction $_.ProcessName) -ne 'refuse' } | ForEach-Object { [int]$_.Id } | Select-Object -Unique)
    foreach ($ProcessId in $Ids) {
        if ($ProcessId -eq $PID) { continue }
        $Name = "$((@($Blocker) | Where-Object { [int]$_.Id -eq $ProcessId } | Select-Object -First 1).ProcessName)"
        if ($null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { continue }   # already gone (child of one we stopped)
        if ($Name -ieq 'explorer') { $script:ExplorerStopped = $true }
        try { Stop-Process -Id $ProcessId -Force -ErrorAction Stop; Add-Result OK 'Stopped process' "$Name (PID $ProcessId) held a package file" }
        catch { Add-Result WARN 'Stop process' "$Name (PID $ProcessId): $($_.Exception.Message)" }
    }
    Start-Sleep -Seconds 2
}

# Reads the three facts from the system (not from variables): registered packages, provisioned packages, keys.
function Read-CodecState {
    if ($Offline) {
        $Prov = @(Get-AppxProvisionedPackage -Path $Image.Path -ErrorAction Stop | Where-Object { $Targets -contains "$($_.DisplayName)" })
        $Keys = @(Use-CodecOfflineHive -HivePath $Image.HivePath -Script {
            param($HiveRoot)
            $K = Join-Path $HiveRoot $DeprovisionedRelative
            if (Test-Path -LiteralPath $K) { Get-ChildItem -LiteralPath $K | ForEach-Object { "$($_.PSChildName)" } }
        })
        return [pscustomobject]@{ Installed = @(); Provisioned = $Prov; Keys = @($Keys | Where-Object { $_ }) }
    }
    $Inst = @()
    foreach ($T in $Targets) { $Inst += @(Get-AppxPackage -AllUsers -Name $T -ErrorAction Stop) }
    $Prov = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { $Targets -contains "$($_.DisplayName)" })
    $Keys = @()
    if (Test-Path -LiteralPath $DeprovisionedKeyRoot) { $Keys = @(Get-ChildItem -LiteralPath $DeprovisionedKeyRoot | ForEach-Object { "$($_.PSChildName)" }) }
    return [pscustomobject]@{ Installed = @($Inst | Where-Object { $null -ne $_ }); Provisioned = $Prov; Keys = $Keys }
}

function Write-CodecInventory([string]$Suffix, [object[]]$PlanRows, [object[]]$BlockerRows) {
    $Record = [ordered]@{
        Computer = $env:COMPUTERNAME; When = (Get-Date).ToString('o'); Mode = $Mode; Offline = $Offline; ImagePath = $(if ($Offline) { $Image.Path } else { '' })
        RunBy = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Packages = @(foreach ($P in @($PlanRows)) {
            [ordered]@{
                Name = $P.Name; FamilyName = $P.FamilyName; KeyPresent = $P.KeyPresent
                Installed = @(foreach ($I in @($P.Installed)) { [ordered]@{ PackageFullName = "$($I.PackageFullName)"; Version = "$($I.Version)"; InstallLocation = "$($I.InstallLocation)"; Users = (Get-CodecUserList $I) } })
                Provisioned = @(foreach ($V in @($P.Provisioned)) { [ordered]@{ PackageName = "$($V.PackageName)"; Version = "$($V.Version)" } })
            }
        })
        Blockers = @(foreach ($B in @($BlockerRows)) { [ordered]@{ ProcessName = $B.ProcessName; Id = $B.Id; Module = $B.Module; Package = $B.Package } })
        Transcript = "$LogBase.log"
    }
    $File = Join-Path $OutputPath "codec-inventory-$($env:COMPUTERNAME)-$Stamp-$Suffix.json"
    [IO.File]::WriteAllText($File, ([pscustomobject]$Record | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    return $File
}

try {
    # ---- 1. Preconditions - nothing changed yet
    Add-Result OK 'PowerShell' "$($PSVersionTable.PSVersion) ($($PSVersionTable.PSEdition))"
    if (-not (Test-CodecElevated)) { throw 'STOP: run this script elevated (Run as administrator). Nothing was changed.' }
    $RunAs = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    $IsSystem = Test-CodecSystemAccount
    Add-Result OK 'Elevation' "elevated session as $RunAs$(if ($IsSystem) { ' (LocalSystem)' })"
    $Os = Get-CodecOsInfo
    if ($Os.Build -lt $CodecMinimumBuild) { throw "STOP: this is Windows build $($Os.Build); build $($CodecMinimumBuild) (Windows 10 1803) or later is required so a deprovisioned package stays removed across feature updates. Nothing was changed." }
    Add-Result OK 'This computer' "$($Os.Caption) $($Os.DisplayVersion) build $($Os.Build) ($($Os.Edition)) - $env:COMPUTERNAME"
    $Mutex = New-Object System.Threading.Mutex($false, 'Global\Remove-CodecExtension')
    try { $MutexHeld = $Mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $MutexHeld = $true }
    if (-not $MutexHeld) { throw 'STOP: another instance of Remove-CodecExtension.ps1 is running on this computer. Wait for it to finish. Nothing was changed.' }
    $Modules = Initialize-CodecModules
    Add-Result OK 'Modules' "Appx: $($Modules.Appx); Dism: $($Modules.Dism)"
    $Targets = @($Package | ForEach-Object { (Get-CodecCatalogEntry $_).Name } | Select-Object -Unique)
    Add-Result OK 'Target packages' ($Targets -join ', ')
    $Image = $null
    if ($Offline) {
        $Image = Test-CodecOfflineImage -Path $MountedImagePath
        Add-Result OK 'Mounted image' "$($Image.Path) - Windows build $($Image.Build) ($($Image.Version)) - provisioning and Deprovisioned keys only; user registrations in a captured image need the online run"
    }

    # ---- 2. Current state (read-only) and the plan
    $State = Read-CodecState
    $Plan = @(Get-CodecPlan -Target $Targets -Installed $State.Installed -Provisioned $State.Provisioned -DeprovisionedKey $State.Keys)
    $Blockers = @()
    if (-not $Offline) { $Blockers = @(Get-CodecBlockingProcess -InstallLocation @($State.Installed | ForEach-Object { "$($_.InstallLocation)" } | Where-Object { $_ })) }
    $BlockedNames = @($Blockers | ForEach-Object { ("$($_.Package)" -split '_')[0] } | Select-Object -Unique)
    foreach ($P in $Plan) {
        $Facts = New-Object System.Collections.Generic.List[string]
        foreach ($I in $P.Installed) {
            $Facts.Add("installed $($I.Version) for $(Get-CodecUserList $I)")
            if ((Get-CodecFamilyName "$($I.PackageFullName)") -ne $P.FamilyName) { Add-Result WARN "$($P.Name) publisher" "$($I.PackageFullName) is not signed by the Microsoft Store publisher ID; it was sideloaded" }
        }
        foreach ($V in $P.Provisioned) { $Facts.Add("provisioned $($V.Version) (every new user profile gets it)") }
        if ($P.KeyPresent) { $Facts.Add('Deprovisioned key present') } else { $Facts.Add('no Deprovisioned key') }
        $Mine = @($Blockers | Where-Object { "$($_.Package)" -like "$($P.Name)_*" })
        if ($Mine.Count -gt 0) { $Facts.Add('IN USE by ' + ((@($Mine | ForEach-Object { "$($_.ProcessName) (PID $($_.Id)) $($_.Module)" }) | Select-Object -Unique) -join ', ')) }
        $Line = ($Facts.ToArray() -join '; ')
        if ($P.AlreadyClean) { Add-Result OK $P.Name 'not installed, not provisioned, Deprovisioned key present - nothing to do' }
        elseif ($P.Present) { if ($Mode -eq 'Check') { Add-Result FAIL $P.Name "PRESENT - $Line" } else { Add-Result OK "$($P.Name) before" $Line } }
        else { Add-Result WARN $P.Name "not installed and not provisioned, but $Line - a feature update may provision it again; -Mode Remove writes the key" }
    }
    if (-not $Offline) {
        $Store = Get-CodecStoreAccess
        if ($Store.StoreAppBlocked) { Add-Result OK 'Microsoft Store' "the Store app is blocked by policy, users cannot reinstall from it ($($Store.Detail))" }
        else { Add-Result WARN 'Microsoft Store' "users can open the Store and reinstall a removed package ($($Store.Detail)); block it with 'Turn off the Store application' or a packaged-app rule in AppLocker / App Control for Business" }
    }

    if ($Mode -eq 'Check') {
        $Present = @($Plan | Where-Object { $_.Present })
        if ($Present.Count -gt 0) {
            $Hints.Add("$($Present.Count) of $($Plan.Count) target package(s) still present. Remove them:  .\Remove-CodecExtension.ps1 -Mode Remove")
            if ($Blockers.Count -gt 0) { $Hints.Add("These processes hold a package file and would block the removal for users: $(Format-Blocker $Blockers). Close them, or add -StopBlockingProcesses.") }
        }
        else { $Hints.Add('Every target package is gone from this computer.') }
    }
    else {
        # ---- 3. Plan, refuse what cannot be done, confirm
        $Work = @($Plan | Where-Object { -not $_.AlreadyClean })
        if ($Work.Count -eq 0) {
            Add-Result OK 'Already current' 'every target package is removed, deprovisioned and keyed - nothing to change'
            if (-not $WhatIfPreference) { Write-CodecEvent -Id 1002 -EntryType Information -Message "Remove-CodecExtension: nothing to do for $($Targets -join ', ')" | Out-Null }
        }
        else {
            $Refused = @($Blockers | Where-Object { (Get-CodecBlockerAction $_.ProcessName) -eq 'refuse' })
            if ($StopBlockingProcesses -and $Refused.Count -gt 0) { throw "STOP: a process that must not be killed has a package file loaded: $(Format-Blocker $Refused). Stop the owning service, sign the users out, or run the removal in audit mode / at startup, then retry. Nothing was changed." }
            $Detail = New-Object System.Collections.Generic.List[string]
            $Detail.Add("Computer: $env:COMPUTERNAME$(if ($Offline) { ' - mounted image ' + $Image.Path })")
            foreach ($W in $Work) { foreach ($A in $W.Actions) { $Detail.Add("$($W.Name): $A") } }
            if ($Blockers.Count -gt 0) {
                if ($StopBlockingProcesses) { $Detail.Add("STOP these processes first, they have a package file loaded: $(Format-Blocker $Blockers)$(if (@($Blockers | Where-Object { $_.ProcessName -ieq 'explorer' }).Count -gt 0) { ' (Explorer is started again afterwards)' })") }
                else { $Detail.Add("NOT removed for users this run (in use, no -StopBlockingProcesses): $($BlockedNames -join ', ') - held by $(Format-Blocker $Blockers)") }
            }
            $Detail.Add('Effect: Photos, Paint, Explorer thumbnails, Media Player, Edge and WebView2 apps can no longer decode these formats on this computer. Browsers keep their own WebP decoder; Teams/Zoom calls, JPEG/PNG/H.264 are not affected.')
            $Detail.Add('Undo: reinstall from the Microsoft Store (' + ((@($Work | ForEach-Object { $E = Get-CodecCatalogEntry $_.Name; "$($E.DisplayName) $($E.StoreId)".Trim() })) -join '; ') + ') and delete the Deprovisioned key to let setup provision it again.')
            if (-not $WhatIfPreference) {
                Confirm-Change -NoConfirm:$NoConfirm -Action "REMOVE $($Work.Count) codec package(s) on $env:COMPUTERNAME$(if ($Offline) { ' (mounted image)' })" -Detail $Detail.ToArray()
                $ConfirmPreference = 'None'
            }
            else { Write-Host ''; Write-Host "WhatIf - the plan for $($env:COMPUTERNAME):" -ForegroundColor Yellow; foreach ($D in $Detail) { Write-Host "  $D" -ForegroundColor Yellow } }

            # ---- 4. Evidence before, then apply
            $Before = Write-CodecInventory -Suffix 'before' -PlanRows $Plan -BlockerRows $Blockers
            Add-Result OK 'Inventory before' $Before
            if (-not $WhatIfPreference) { Write-CodecEvent -Id 1000 -EntryType Information -Message "Remove-CodecExtension: removal started by $RunAs for $(($Work | ForEach-Object { $_.Name }) -join ', ')$(if ($Offline) { ' in mounted image ' + $Image.Path })" | Out-Null }
            if (-not $Offline -and $StopBlockingProcesses -and $Blockers.Count -gt 0 -and -not $WhatIfPreference) {
                Stop-CodecBlocker $Blockers
                $Blockers = @(Get-CodecBlockingProcess -InstallLocation @($State.Installed | ForEach-Object { "$($_.InstallLocation)" } | Where-Object { $_ }))
                $BlockedNames = @($Blockers | ForEach-Object { ("$($_.Package)" -split '_')[0] } | Select-Object -Unique)
                if ($Blockers.Count -gt 0) { Add-Result WARN 'Still in use' "after stopping: $(Format-Blocker $Blockers) - the removal is retried per package" }
            }
            $Failed = New-Object System.Collections.Generic.List[string]
            foreach ($W in $Work) {
                $Check = $W.Name
                # 4a. every user profile (online only)
                foreach ($I in $W.Installed) {
                    $Full = "$($I.PackageFullName)"
                    if (-not $StopBlockingProcesses -and ($BlockedNames -contains $W.Name)) {
                        $Held = Format-Blocker @($Blockers | Where-Object { "$($_.Package)" -eq $Full })
                        Add-Result FAIL "$Check users" "NOT removed: $Full is in use by $Held. Close those apps (or sign the users out) and run again, or add -StopBlockingProcesses."
                        if (-not $WhatIfPreference) { Write-CodecEvent -Id 2001 -EntryType Warning -Message "Remove-CodecExtension: $Full not removed, in use by $Held" | Out-Null }
                        $Failed.Add($W.Name)
                        continue
                    }
                    if (-not $PSCmdlet.ShouldProcess($Full, 'Remove package for every user')) { Add-Result OK "$Check users" "WhatIf: would remove $Full for every user"; continue }
                    $Done = $false; $Why = $null
                    for ($Try = 1; $Try -le 3 -and -not $Done; $Try++) {
                        try { Remove-AppxPackage -Package $Full -AllUsers -ErrorAction Stop; $Done = $true }
                        catch {
                            $Why = ConvertTo-CodecHresultText "$($_.Exception.Message)"
                            if ($Why.Code -eq '0x80073CF1') { $Done = $true; break }
                            if ($Why.Code -eq '0x80073D02' -and $StopBlockingProcesses -and $Try -lt 3) {
                                $Again = @(Get-CodecBlockingProcess -InstallLocation @("$($I.InstallLocation)"))
                                Add-Result WARN "$Check users" "try $Try - still in use by $(Format-Blocker $Again); stopping and retrying"
                                if ($Again.Count -gt 0) { Stop-CodecBlocker $Again } else { Start-Sleep -Seconds 3 }
                                continue
                            }
                            break
                        }
                    }
                    if ($Done -and $null -ne $Why -and $Why.Code -eq '0x80073CF1') { Add-Result WARN "$Check users" "$Full was already gone ($($Why.Text))" }
                    elseif ($Done) { Add-Result OK "$Check users" "removed $Full for every user" }
                    else {
                        Add-Result FAIL "$Check users" "Remove-AppxPackage $Full failed: $($Why.Text)"
                        Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: Remove-AppxPackage $Full failed: $($Why.Text)" | Out-Null
                        $Failed.Add($W.Name)
                    }
                }
                # 4b. provisioning
                foreach ($V in $W.Provisioned) {
                    $ProvName = "$($V.PackageName)"
                    if (-not $PSCmdlet.ShouldProcess($ProvName, 'Remove provisioned package')) { Add-Result OK "$Check provisioning" "WhatIf: would deprovision $ProvName"; continue }
                    try {
                        if ($Offline) { Remove-AppxProvisionedPackage -Path $Image.Path -PackageName $ProvName -ErrorAction Stop | Out-Null }
                        else { Remove-AppxProvisionedPackage -Online -PackageName $ProvName -ErrorAction Stop | Out-Null }
                        Add-Result OK "$Check provisioning" "deprovisioned $ProvName"
                    }
                    catch {
                        $Why = ConvertTo-CodecHresultText "$($_.Exception.Message)"
                        Add-Result FAIL "$Check provisioning" "Remove-AppxProvisionedPackage $ProvName failed: $($Why.Text)"
                        Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: Remove-AppxProvisionedPackage $ProvName failed: $($Why.Text)" | Out-Null
                        $Failed.Add($W.Name)
                    }
                }
                # 4c. Deprovisioned key (online; offline keys are written in one hive session below)
                if (-not $W.KeyPresent -and -not $Offline) {
                    $KeyResult = Set-CodecDeprovisionedKey -Root $DeprovisionedKeyRoot -FamilyName $W.FamilyName
                    switch ($KeyResult) {
                        'created' { Add-Result OK "$Check key" "created $DeprovisionedKeyRoot\$($W.FamilyName)" }
                        'present' { Add-Result OK "$Check key" "already present $DeprovisionedKeyRoot\$($W.FamilyName)" }
                        default { Add-Result OK "$Check key" "WhatIf: would create $DeprovisionedKeyRoot\$($W.FamilyName)" }
                    }
                }
            }
            if ($Offline) {
                $KeyWork = @($Work | Where-Object { -not $_.KeyPresent })
                if ($KeyWork.Count -gt 0) {
                    if ($PSCmdlet.ShouldProcess($Image.HivePath, "Write $($KeyWork.Count) Deprovisioned key(s) into the image hive")) {
                        $Written = @(Use-CodecOfflineHive -HivePath $Image.HivePath -Script {
                            param($HiveRoot)
                            $K = Join-Path $HiveRoot $DeprovisionedRelative
                            foreach ($W in $KeyWork) { "$($W.FamilyName)=$(Set-CodecDeprovisionedKey -Root $K -FamilyName $W.FamilyName)" }
                        })
                        foreach ($Line in $Written) { Add-Result OK 'Deprovisioned key (image)' "$Line" }
                    }
                    else { foreach ($W in $KeyWork) { Add-Result OK "$($W.Name) key" "WhatIf: would create $($W.FamilyName) in the image hive" } }
                }
            }
            if ($ExplorerStopped -and -not $IsSystem -and -not $WhatIfPreference) {
                Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') | Out-Null
                Add-Result OK 'Explorer' 'started again'
            }
            elseif ($ExplorerStopped) { Add-Result WARN 'Explorer' 'was stopped and not started again (LocalSystem session); the user can start it from Task Manager or sign in again' }

            # ---- 5. Verify from the system
            if (-not $WhatIfPreference) {
                $After = Read-CodecState
                $PlanAfter = @(Get-CodecPlan -Target @($Work | ForEach-Object { $_.Name }) -Installed $After.Installed -Provisioned $After.Provisioned -DeprovisionedKey $After.Keys)
                foreach ($P in $PlanAfter) {
                    $Left = New-Object System.Collections.Generic.List[string]
                    foreach ($I in $P.Installed) { $Left.Add("still registered: $($I.PackageFullName) for $(Get-CodecUserList $I)") }
                    foreach ($V in $P.Provisioned) { $Left.Add("still provisioned: $($V.PackageName)") }
                    if (-not $P.KeyPresent) { $Left.Add("key missing: $($P.FamilyName)") }
                    if ($Left.Count -eq 0) {
                        Add-Result OK "$($P.Name) verified" 'not registered to any user, not provisioned, Deprovisioned key present'
                        Write-CodecEvent -Id 1001 -EntryType Information -Message "Remove-CodecExtension: $($P.Name) removed for every user, deprovisioned and keyed on $env:COMPUTERNAME$(if ($Offline) { ' (mounted image ' + $Image.Path + ')' })" | Out-Null
                    }
                    elseif ($Failed -contains $P.Name) { Add-Result WARN "$($P.Name) verified" ($Left.ToArray() -join '; ') }
                    else {
                        Add-Result FAIL "$($P.Name) verified" ($Left.ToArray() -join '; ')
                        Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: $($P.Name) verification failed on $env:COMPUTERNAME - $($Left.ToArray() -join '; ')" | Out-Null
                    }
                }
                $AfterFile = Write-CodecInventory -Suffix 'after' -PlanRows $PlanAfter -BlockerRows @()
                Add-Result OK 'Inventory after' $AfterFile
                if ($Failed.Count -gt 0) { $Hints.Add("Not finished for: $(@($Failed | Select-Object -Unique) -join ', '). Close the apps that hold the files (see the rows above), then run the same command again; it only does what is still missing.") }
                else { $Hints.Add('Done. No reboot is needed. Confirm any time with:  .\Remove-CodecExtension.ps1 -Mode Check') }
            }
            else { $Hints.Add('WhatIf: nothing was changed. Run without -WhatIf to perform the removal.') }
        }
    }
}
catch {
    Add-Result FAIL 'Stopped' $_.Exception.Message
    if ($Mode -eq 'Remove' -and -not $WhatIfPreference) { Write-CodecEvent -Id 3000 -EntryType Error -Message "Remove-CodecExtension: stopped - $($_.Exception.Message)" | Out-Null }
}
finally {
    Write-Host ''
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $Results | Export-Csv -LiteralPath "$LogBase.csv" -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $FailCount = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $WarnCount = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    if ($FailCount -gt 0) { Write-Host "RESULT: FAILED ($FailCount failed, $WarnCount warning(s)) - $LogBase.log" -ForegroundColor Red }
    elseif ($WarnCount -gt 0) { Write-Host "RESULT: PASSED with $WarnCount warning(s) - $LogBase.log" -ForegroundColor Yellow }
    else { Write-Host "RESULT: PASSED - $LogBase.log" -ForegroundColor Green }
    foreach ($H in $Hints) { Write-Host $H -ForegroundColor Cyan }
    if ($null -ne $Mutex) { if ($MutexHeld) { try { $Mutex.ReleaseMutex() } catch { } }; $Mutex.Dispose() }
    try { Stop-Transcript @StopNoWhatIf | Out-Null } catch { }
}
if (@($Results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { exit 1 }
