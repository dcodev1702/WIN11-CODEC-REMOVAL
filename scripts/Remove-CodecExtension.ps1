<#
.SYNOPSIS
    Removes the Microsoft Store codec packages that keep showing up in vulnerability scans - WebP Image Extension,
    HEVC Video Extensions, Raw Image Extension and HEIF Image Extensions by default - from a Windows 10/11 computer
    or from a mounted golden image: for every user profile, from the provisioning list, and with the registry key
    that stops feature updates from bringing them back. Read-only by default (-Mode Check). -ListPackages shows
    every codec package the script can handle, its state, and the exact name to pass to -Package. -RunAsSystem
    runs the removal as NT AUTHORITY\SYSTEM (PsExec from tools\, pinned by hash, or a one-shot scheduled task).

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
         and every running process that holds a package file - found two ways, the loaded-module scan (which file
         of which package, in which process) and Windows' Restart Manager (the API Windows Installer uses to ask
         "which applications are using these files"; it also sees open handles, services and processes whose
         modules cannot be read).
      3. -Mode Check stops here: FAIL rows (exit 1) for every target still present, WARN for a missing key.
      4. -Mode Remove shows the plan in yellow and asks Continue? [Y/N] (-NoConfirm for automation, -WhatIf for the
         plan only), writes an inventory file, then per package:
           Remove-AppxPackage -AllUsers           every user profile, including profiles that are not loaded
           Remove-AppxProvisionedPackage -Online  new profiles no longer get it
           Deprovisioned registry key             HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\
                                                  AppxAllUserStore\Deprovisioned\<PackageFamilyName>
         and finally re-reads all three from the system to verify. No reboot is needed.

    WHEN A PACKAGE IS IN USE
      A process that has a file from the package folder loaded is what makes Remove-AppxPackage answer 0x80073D02
      ERROR_PACKAGES_IN_USE on the builds that check for it. For the HEVC package that is normally Microsoft Edge
      and every WebView2 host (new Teams, new Outlook, Widgets, Copilot ...), which load hevcdecoder_store.dll when
      they enumerate Media Foundation decoders; for the image codecs it is Photos, Paint, a thumbnail COM surrogate
      (dllhost) or Explorer. The script:
        - names those processes before anything happens (PID, module or handle, package);
        - tries the removal anyway: on the builds seen so far (Windows 11 build 28000 and 26300) the deployment
          service moves the package folder to WindowsApps\Deleted and finishes while Edge still has the DLL mapped;
        - if Windows answers 0x80073D02: with -StopBlockingProcesses it stops the holders and retries (three tries
          in all; Explorer is started again; system, security and management processes are never killed), without
          the switch the package is reported FAIL "in use by ..." and the run continues with the next package;
        - with -RunAsSystem it runs the removal as NT AUTHORITY\SYSTEM: this elevated session does the pre-flight,
          shows the plan and asks Y/N, then starts a child run in session 0 through PsExec -s (tools\PsExec64.exe,
          SHA256 pinned to the copy that was verified) or, when PsExec is absent or blocked, through a one-shot
          scheduled task; it shows the child's progress from the child's own step log, merges the child's result
          rows into its table, verifies from the system and restarts Explorer if the SYSTEM session had to stop it.
          The child runs Windows PowerShell 5.1 with the native Appx and Dism modules and -NoConfirm.
      Whether SYSTEM alone gets past an in-use refusal depends on the build; both runs leave their logs, so the
      Logs folder shows which it was. When nothing may be closed on the computer, run before anyone signs in
      (startup script, or -RunAsSystem -StopBlockingProcesses in a maintenance window).

    ACCESS DENIED (0x80070005) ALTHOUGH THE SESSION IS ELEVATED
      The script checks elevation first, so this code comes from the app deployment service itself. Seen on
      Windows 11 build 28000: Remove-AppxPackage -AllUsers on a package that was still provisioned removed it for the
      other accounts and Windows deprovisioned it, but the service returned 0x80070005 for the signed-in account
      (step "OptionalDependenciesHandled"). Running the same command again removed the remaining registration. The
      FAIL row names the AppX activity; Get-AppPackageLog -ActivityID <id> shows Windows' own log of it.

    GOLDEN IMAGE
      Reference computer (audit mode, before sysprep /generalize): run -Mode Remove -NoConfirm there. Removing for
      every user AND deprovisioning is required, otherwise sysprep fails (Microsoft KB "Sysprep fails after you
      remove or update Microsoft Store apps").
      Offline WIM/VHDX: Mount-WindowsImage, then -Mode Remove -MountedImagePath <mount folder>. The script removes
      the provisioning and writes the Deprovisioned keys into the image's SOFTWARE hive (loaded with reg.exe and
      unloaded again). A captured image that already contains user profiles keeps their registrations; that case
      needs the online run on the reference computer.

    SAFETY
      Every STOP happens before the first change, or says precisely what was changed. A package that fails is
      reported as FAIL and skipped; everything else is still done. The removal is reversible: reinstall from the
      Microsoft Store (or winget install --id <StoreId> -s msstore) and delete the Deprovisioned key. Users who can
      open the Store can reinstall a package on their own; the script warns when the Store is not blocked by policy.
      PsExec is run only when its SHA256 equals the pinned hash of the verified copy; -RunAsSystem refuses a script
      or log folder on a network drive, which a SYSTEM session could not reach.

    LOGS OF THE WHOLE RUN (in -LogPath and -OutputPath)
      <LogPath>\Remove-CodecExtension-<Check|Remove|List>-<timestamp>[-<tag>].log          transcript of the console
      <LogPath>\Remove-CodecExtension-...-<timestamp>[-<tag>].steps.log                     every step with a
                                                                                            millisecond timestamp:
                                                                                            each command sent to
                                                                                            Windows, its result,
                                                                                            the holders found, the
                                                                                            processes stopped, the
                                                                                            SYSTEM launch and exit
      <LogPath>\Remove-CodecExtension-...-<timestamp>[-<tag>].csv                           the result rows (When,
                                                                                            Status, Check, Detail)
      <LogPath>\Remove-CodecExtension-Remove-<timestamp>[-<tag>].appx-events.csv            Windows' own AppX
                                                                                            deployment events
                                                                                            during the run
      <OutputPath>\codec-inventory-<computer>-<timestamp>[-<tag>]-before|after.json         packages, users,
                                                                                            provisioning, keys,
                                                                                            holders
      A -RunAsSystem run leaves two sets: the parent's and the child's (tag system-<parent timestamp>).
      Application events from source CodecExtensionRemoval: 1000 run started, 1001 package removed, 1002 nothing
      to do, 2001 package in use (not removed), 2002 warning, 3000 run stopped, 3001 removal failed.

.PARAMETER Mode
    Check (default) reports and changes nothing; exit code 1 when any target is still installed or provisioned.
    Remove performs the removal.

.PARAMETER Package
    Package names to handle. Default: Microsoft.WebpImageExtension, Microsoft.HEVCVideoExtension,
    Microsoft.RawImageExtension, Microsoft.HEIFImageExtension. Only the codec packages listed in the catalog are
    accepted. To keep HEIF, pass the first three names. -ListPackages shows every accepted name and its state.

.PARAMETER ListPackages
    Read-only. Lists every codec package the script can handle - the name to use with -Package, the Store listing,
    whether it is a default target, and its state on this computer (or in -MountedImagePath) - writes the list to
    <OutputPath>\codec-packages-<computer>-<timestamp>.csv and prints the removal command for the packages that are
    present. Cannot be combined with -Mode, -Package, -StopBlockingProcesses, -RunAsSystem or -NoConfirm.

.PARAMETER MountedImagePath
    Offline servicing: the folder a Windows image is mounted at (Mount-WindowsImage -Path). Empty (default) means
    the running operating system. The running OS and its system drive are refused here.

.PARAMETER StopBlockingProcesses
    When Windows refuses a removal because a process holds a package file (0x80073D02), stop that process (Edge,
    WebView2 hosts, Photos, dllhost ...) and retry; Explorer is stopped and started again. Processes are stopped
    only after Windows has refused, never up front. Without the switch a refused package is FAIL and skipped. On a
    user's computer this closes their browser and WebView2-based apps - run it at logon or maintenance time.

.PARAMETER RunAsSystem
    -Mode Remove only, running OS only. After the pre-flight, the plan and the confirmation, run the removal as
    NT AUTHORITY\SYSTEM in a child run (session 0, Windows PowerShell 5.1, -NoConfirm) and wait for it. The
    launcher is PsExec (tools\PsExec64.exe, or -PsExecPath; the file must match the pinned SHA256) or a one-shot
    scheduled task, see -SystemLauncher. The child's rows appear in this run's table prefixed [SYSTEM]; this run
    then verifies from the system and exits 1 if anything failed. When the session already is SYSTEM (Intune,
    ConfigMgr, a startup script) nothing is relaunched. The script folder, -LogPath and -OutputPath must be on a
    local drive.

.PARAMETER SystemLauncher
    With -RunAsSystem: Auto (default) uses PsExec when it is present and its hash matches, otherwise the scheduled
    task, and falls back to the task when PsExec could not start the child; PsExec insists on PsExec and stops when
    it is absent, altered or fails; ScheduledTask never uses PsExec (no third-party file needed).

.PARAMETER PsExecPath
    Path of PsExec64.exe or PsExec.exe. Default <repo>\tools\PsExec64.exe. The SHA256 must be one of the values
    pinned in scripts\Codec-System.ps1 (tools\THIRD-PARTY-NOTICES.md lists them).

.PARAMETER RunTag
    Letters, digits and hyphens, appended to the names of this run's files (transcript, CSV, step log, inventory).
    A -RunAsSystem parent passes system-<its timestamp> to the child and finds the child's files by it.

.PARAMETER LogPath
    Folder for the transcript, the CSV, the step log and the AppX events. Default <repo>\Logs. Use a writable local
    path when deploying from a read-only share.

.PARAMETER OutputPath
    Folder for the inventory JSON (state before and after). Default <repo>\Outputs.

.PARAMETER DeprovisionedKeyRoot
    The Deprovisioned registry key. Leave the default; the tests point it at a key under HKCU.

.PARAMETER NoConfirm
    No Y/N prompt (Intune, Configuration Manager, scheduled task, image build). The plan is still printed and
    transcribed. A non-interactive session without -NoConfirm stops before changing anything.

.PARAMETER WhatIf
    Shows the plan and changes nothing. No prompt. With -RunAsSystem: shows the launcher and the child command.

.EXAMPLE
    .\Remove-CodecExtension.ps1
    Read-only: which of the four packages are installed (for whom), provisioned, keyed, and which processes hold
    their files. Exit code 1 while any is present.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -ListPackages
    Read-only: every codec package the script can handle, its state here, and the -Package name to use, followed by
    the removal command for the ones that are present.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove -WhatIf
    The exact plan for this computer, nothing changed, nothing asked.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove
    Removes the four packages for every user, deprovisions them and writes the keys, after Continue? [Y/N].
    A package Windows refuses as in use is reported and skipped.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove -Package Microsoft.HEVCVideoExtension -RunAsSystem
    HEVC only, removed by a child run as NT AUTHORITY\SYSTEM through tools\PsExec64.exe after Continue? [Y/N];
    this session shows the child's progress, merges its rows and verifies the result.

.EXAMPLE
    .\Remove-CodecExtension.ps1 -Mode Remove -RunAsSystem -SystemLauncher ScheduledTask -StopBlockingProcesses -NoConfirm
    Unattended: as SYSTEM through a one-shot scheduled task (no PsExec), closing Edge and WebView2 hosts only if
    Windows refuses a removal while they hold a file.

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
    PASS/WARN/FAIL table on the console, the same rows as CSV, a transcript, a step log, inventory JSON files.
    Exit code 1 when any row is FAIL (Check: a target is still present; Remove: a removal failed or was refused).

.NOTES
    Written for PowerShell 7; also runs in Windows PowerShell 5.1. ASCII-only source. Run elevated.
    tests\Test-CodecRemoval.ps1 sets $CodecRemovalHarness in its scope; the script then uses the harness's mocked
    functions instead of dot-sourcing scripts\Codec-Common.ps1, scripts\Codec-System.ps1 and
    scripts\Confirm-Change.ps1.

    Generative AI was used in the creation and validation of this code; the result was reviewed and tested by a
    person (tests in both editions, plus live runs on Windows 11 Enterprise computers).

.LINK
    https://learn.microsoft.com/windows/application-management/remove-provisioned-apps-during-update

.LINK
    https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps

.LINK
    https://learn.microsoft.com/windows/msix/group-policy-msix

.LINK
    https://learn.microsoft.com/troubleshoot/microsoft-edge/development/video-playback-issues

.LINK
    https://learn.microsoft.com/sysinternals/downloads/psexec

.LINK
    https://learn.microsoft.com/windows/win32/rstmgr/restart-manager-portal
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'Run')]
param(
    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('Check', 'Remove')]
    [string]$Mode = 'Check',

    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.HEVCVideoExtensions', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension', 'Microsoft.AV1VideoExtension', 'Microsoft.VP9VideoExtensions', 'Microsoft.MPEG2VideoExtension', 'Microsoft.WebMediaExtensions')]
    [string[]]$Package = @('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension'),

    [Parameter(Mandatory, ParameterSetName = 'List')]
    [switch]$ListPackages,

    [string]$MountedImagePath = '',

    [Parameter(ParameterSetName = 'Run')]
    [switch]$StopBlockingProcesses,

    [Parameter(ParameterSetName = 'Run')]
    [switch]$RunAsSystem,

    [Parameter(ParameterSetName = 'Run')]
    [ValidateSet('Auto', 'PsExec', 'ScheduledTask')]
    [string]$SystemLauncher = 'Auto',

    [Parameter(ParameterSetName = 'Run')]
    [string]$PsExecPath = '',

    [ValidatePattern('^$|^[A-Za-z0-9][A-Za-z0-9\-]{0,39}$')]
    [string]$RunTag = '',

    [string]$LogPath = '',
    [string]$OutputPath = '',

    [ValidatePattern('^HK(LM|CU):\\\S+$')]
    [string]$DeprovisionedKeyRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned',

    [Parameter(ParameterSetName = 'Run')]
    [switch]$NoConfirm
)
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$RunKind = $Mode
if ($ListPackages) { $RunKind = 'List' }
# The command to suggest in hints, as the user would type it from the current folder (.\scripts\... or .\...).
$CommandName = "$PSCommandPath"
try { $CommandName = "$(Resolve-Path -LiteralPath $PSCommandPath -Relative -ErrorAction Stop)" } catch { $CommandName = "$PSCommandPath" }
if ($CommandName -match '\s') { $CommandName = "& '$($CommandName -replace "'", "''")'" }
$UnderHarness = $null -ne (Get-Variable -Name CodecRemovalHarness -ErrorAction SilentlyContinue)   # any visible scope: the harness calls through a function
if (-not $UnderHarness) {
    . (Join-Path $PSScriptRoot 'Codec-Common.ps1')
    . (Join-Path $PSScriptRoot 'Codec-System.ps1')
    . (Join-Path $PSScriptRoot 'Confirm-Change.ps1')
}
else {
    # Test harness mode: every command that could change this computer must resolve to a plain function the harness
    # defined, never to a cmdlet or a module function. A real Appx/Dism module loaded in the session once reached the
    # live package store through the mocks; this guard makes that impossible.
    foreach ($Guarded in 'Get-AppxPackage', 'Remove-AppxPackage', 'Get-AppxProvisionedPackage', 'Remove-AppxProvisionedPackage', 'Stop-Process', 'Initialize-CodecModules', 'Write-CodecEvent', 'Use-CodecOfflineHive', 'Invoke-CodecSystemRun', 'Test-CodecPsExec', 'Get-CodecFileUser', 'Get-CodecPackageFile', 'Export-CodecAppxEvent') {
        $Resolved = Get-Command -Name $Guarded -ErrorAction SilentlyContinue
        if ($null -eq $Resolved -or $Resolved.CommandType -ne 'Function' -or $null -ne $Resolved.Module) {
            throw "STOP: test harness mode, but '$Guarded' would run for real ($(if ($null -eq $Resolved) { 'not defined' } else { "$($Resolved.CommandType) from $($Resolved.ModuleName)" })). Nothing was changed."
        }
    }
}
if (-not $LogPath) { $LogPath = Join-Path $Root 'Logs' }
if (-not $OutputPath) { $OutputPath = Join-Path $Root 'Outputs' }
foreach ($Dir in @($LogPath, $OutputPath)) { if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { New-Item -Path $Dir -ItemType Directory -Force -WhatIf:$false | Out-Null } }
# Absolute paths: a SYSTEM child run starts in another folder and must find the same files.
$LogPath = (Resolve-Path -LiteralPath $LogPath).ProviderPath
$OutputPath = (Resolve-Path -LiteralPath $OutputPath).ProviderPath
$RunStart = Get-Date
$Stamp = '{0:yyyyMMdd-HHmmss}' -f $RunStart
$TagSuffix = ''
if ($RunTag) { $TagSuffix = "-$RunTag" }
$LogBase = Join-Path $LogPath "Remove-CodecExtension-$RunKind-$Stamp$TagSuffix"
$StepLog = "$LogBase.steps.log"
# PowerShell 7 applies -WhatIf to Start-Transcript and Stop-Transcript (the transcript would never open or close);
# Windows PowerShell 5.1 has -WhatIf on Start-Transcript only. Pass -WhatIf:$false where the parameter exists.
$StartNoWhatIf = @{}; $StopNoWhatIf = @{}
if ((Get-Command Start-Transcript).Parameters.ContainsKey('WhatIf')) { $StartNoWhatIf = @{ WhatIf = $false } }
if ((Get-Command Stop-Transcript).Parameters.ContainsKey('WhatIf')) { $StopNoWhatIf = @{ WhatIf = $false } }
Start-Transcript -LiteralPath "$LogBase.log" @StartNoWhatIf | Out-Null

# The step log: one line per step with a millisecond timestamp, in the file and on the console (so the transcript
# has it too). Every result row goes through it as well.
function Write-CodecStep([string]$Level, [string]$Message) {
    $Line = '{0:yyyy-MM-dd HH:mm:ss.fff}  {1,-5} {2}' -f (Get-Date), $Level, $Message
    try { [IO.File]::AppendAllText($StepLog, "$Line`r`n", (New-Object Text.UTF8Encoding($false))) } catch { }
    Write-Host $Line -ForegroundColor DarkGray
}
$Results = New-Object System.Collections.Generic.List[object]
function Add-Result([string]$Status, [string]$Check, [string]$Detail) {
    $Results.Add([pscustomobject]@{ When = (Get-Date).ToString('HH:mm:ss'); Status = $Status; Check = $Check; Detail = $Detail })
    Write-CodecStep $Status "$Check - $Detail"
}
$Hints = New-Object System.Collections.Generic.List[string]
$ActivityIds = New-Object System.Collections.Generic.List[string]
$Failed = New-Object System.Collections.Generic.List[string]
$FailKind = @{}
$Mutex = $null; $MutexHeld = $false
$ExplorerStopped = $false
$Offline = [bool]"$MountedImagePath".Trim()
$DeprovisionedRelative = 'Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned'
$IsSystem = $false
$SystemRun = $false      # this run starts a SYSTEM child and waits for it
$Launcher = ''           # PsExec | ScheduledTask
$PsExec = $null
$ChildTag = "system-$Stamp"

function Format-Blocker([object[]]$Blocker) { return ((@($Blocker) | ForEach-Object { "$($_.ProcessName) (PID $($_.Id))" } | Select-Object -Unique) -join ', ') }
function Format-BlockerDetail([object[]]$Blocker) { return ((@($Blocker) | ForEach-Object { "$($_.ProcessName) (PID $($_.Id)) $($_.Module)" } | Select-Object -Unique) -join ', ') }
function Get-CodecFailureKind([string]$Detail) { if ($Detail -match '0x80073D02') { return 'inuse' }; if ($Detail -match '0x80070005') { return 'denied' }; return 'other' }

# The arguments that select the given packages (and the same mounted image) again, for the commands in the hints.
function Get-CodecRerunArgument([string[]]$Names) {
    $Text = ''
    if (@($Names | Where-Object { $_ }).Count -gt 0) { $Text += " -Package $(@($Names | Where-Object { $_ }) -join ', ')" }
    if ($Offline) { $Text += " -MountedImagePath '$("$MountedImagePath".Trim() -replace "'", "''")'" }
    return $Text
}

# A failed AppX call: the code from the message or the exception, plus Windows' own log entry for the failed step.
function Get-CodecFailure([object]$ErrorRecord, [string]$PackageName, [datetime]$Since) {
    $Why = ConvertTo-CodecHresultText -Message "$($ErrorRecord.Exception.Message)" -HResult ([int]$ErrorRecord.Exception.HResult)
    $Activity = Find-CodecDeploymentError -PackageName $PackageName -Since $Since
    $LogNote = ''
    if ($null -ne $Activity -and "$($Activity.ActivityId)") {
        $LogNote = " - Windows' log: $(if ($Activity.Step) { "$($Activity.Step) " })Get-AppPackageLog -ActivityID $($Activity.ActivityId)"
        $ActivityIds.Add("$($Activity.ActivityId)")
    }
    $Kind = 'other'
    if ($Why.Code -eq '0x80073D02') { $Kind = 'inuse' } elseif ($Why.Code -eq '0x80070005') { $Kind = 'denied' }
    return [pscustomobject]@{ Code = $Why.Code; Text = $Why.Text; LogNote = $LogNote; Kind = $Kind }
}

# Every process that holds a file of the given installed packages, found two ways: the loaded-module scan per
# package (which file, in which process) and one Restart Manager query over every file of every package (handles,
# services, processes whose modules cannot be read). A Restart Manager hit the module scan did not attribute to a
# package gets Package = '' (one of the targets). Rows: ProcessName, Id, Module, Package, How (module | handle).
function Find-CodecBlocker([object[]]$Installed) {
    $Packages = @($Installed | Where-Object { $null -ne $_ -and "$($_.InstallLocation)".Trim() })
    if ($Packages.Count -eq 0) { return @() }
    $Hits = New-Object System.Collections.Generic.List[object]
    foreach ($B in @(Get-CodecBlockingProcess -InstallLocation @($Packages | ForEach-Object { "$($_.InstallLocation)" }))) {
        $Hits.Add([pscustomobject]@{ ProcessName = "$($B.ProcessName)"; Id = [int]$B.Id; Module = "$($B.Module)"; Package = "$($B.Package)"; How = 'module' })
    }
    $Files = @(); $Unlisted = @()
    foreach ($P in $Packages) {
        $F = @(Get-CodecPackageFile -InstallLocation "$($P.InstallLocation)")
        if ($F.Count -eq 0) { $Unlisted += "$($P.PackageFullName)" }
        $Files += $F
    }
    if ($Unlisted.Count -gt 0) { Write-CodecStep WARN "Restart Manager scan: no files listed for $($Unlisted -join ', ') (folder missing or not readable)" }
    if ($Files.Count -gt 0) {
        $Users = @()
        try { $Users = @(Get-CodecFileUser -Path $Files) } catch { Write-CodecStep WARN "Restart Manager scan over $($Files.Count) file(s) failed: $($_.Exception.Message)" }
        foreach ($U in $Users) {
            if ([int]$U.Id -eq $PID) { continue }
            if (@($Hits | Where-Object { $_.Id -eq [int]$U.Id }).Count -gt 0) { continue }
            $What = "open handle ($($U.Type)$(if ("$($U.ServiceName)") { ', service ' + $U.ServiceName }))"
            $Hits.Add([pscustomobject]@{ ProcessName = "$($U.ProcessName)"; Id = [int]$U.Id; Module = $What; Package = ''; How = 'handle' })
        }
        Write-CodecStep INFO "holders of $($Packages.Count) package folder(s): module scan $(@($Hits | Where-Object { $_.How -eq 'module' }).Count) hit(s), Restart Manager $($Users.Count) process(es) over $($Files.Count) file(s)"
    }
    return @($Hits | Sort-Object -Property ProcessName, Id, Module -Unique)
}

# Stops the processes that hold a package file (never the ones Get-CodecBlockerAction refuses). Explorer is
# remembered so it can be started again at the end.
function Stop-CodecBlocker([object[]]$Blocker) {
    $Ids = @(@($Blocker) | Where-Object { (Get-CodecBlockerAction $_.ProcessName) -ne 'refuse' } | ForEach-Object { [int]$_.Id } | Select-Object -Unique)
    foreach ($ProcessId in $Ids) {
        if ($ProcessId -eq $PID) { continue }
        $Name = "$((@($Blocker) | Where-Object { [int]$_.Id -eq $ProcessId } | Select-Object -First 1).ProcessName)"
        if ($null -eq (Get-Process -Id $ProcessId -ErrorAction SilentlyContinue)) { Write-CodecStep INFO "$Name (PID $ProcessId) already gone"; continue }   # child of one we stopped
        if ($Name -ieq 'explorer') { $script:ExplorerStopped = $true }
        Write-CodecStep CMD "Stop-Process -Id $ProcessId -Force ($Name)"
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
        RunBy = [Security.Principal.WindowsIdentity]::GetCurrent().Name; RunAsSystem = [bool]$RunAsSystem; Launcher = $Launcher; RunTag = $RunTag
        Packages = @(foreach ($P in @($PlanRows)) {
            [ordered]@{
                Name = $P.Name; FamilyName = $P.FamilyName; KeyPresent = $P.KeyPresent
                Installed = @(foreach ($I in @($P.Installed)) { [ordered]@{ PackageFullName = "$($I.PackageFullName)"; Version = "$($I.Version)"; InstallLocation = "$($I.InstallLocation)"; Users = (Get-CodecUserList $I) } })
                Provisioned = @(foreach ($V in @($P.Provisioned)) { [ordered]@{ PackageName = "$($V.PackageName)"; Version = "$($V.Version)" } })
            }
        })
        Blockers = @(foreach ($B in @($BlockerRows)) { [ordered]@{ ProcessName = $B.ProcessName; Id = $B.Id; Module = $B.Module; Package = $B.Package; How = $B.How } })
        Transcript = "$LogBase.log"; StepLog = $StepLog
    }
    $File = Join-Path $OutputPath "codec-inventory-$($env:COMPUTERNAME)-$Stamp$TagSuffix-$Suffix.json"
    [IO.File]::WriteAllText($File, ([pscustomobject]$Record | ConvertTo-Json -Depth 6), (New-Object Text.UTF8Encoding($false)))
    return $File
}

# Reads the child's step log while the SYSTEM run is in progress and echoes the lines not shown yet.
$TailState = @{ File = ''; Lines = 0 }
$OnTick = {
    if (-not $TailState.File) {
        $F = @(Get-ChildItem -LiteralPath $LogPath -Filter "Remove-CodecExtension-*-$ChildTag.steps.log" -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($F.Count -gt 0) { $TailState.File = $F[0].FullName }
    }
    if ($TailState.File) {
        $All = @(Get-Content -LiteralPath $TailState.File -ErrorAction SilentlyContinue)
        for ($N = $TailState.Lines; $N -lt $All.Count; $N++) { Write-Host "  SYSTEM> $($All[$N])" -ForegroundColor DarkGray }
        if ($All.Count -gt $TailState.Lines) { $TailState.Lines = $All.Count }
    }
}

try {
    Write-CodecStep INFO "run started: $RunKind on $env:COMPUTERNAME, command $PSCommandPath, parameters $(($PSBoundParameters.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' ')"
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
    if ($ListPackages) { $Targets = @($CodecCatalog | ForEach-Object { $_.Name }) }
    else {
        $Targets = @($Package | ForEach-Object { (Get-CodecCatalogEntry $_).Name } | Select-Object -Unique)
        Add-Result OK 'Target packages' ($Targets -join ', ')
    }
    $Image = $null
    if ($Offline) {
        $Image = Test-CodecOfflineImage -Path $MountedImagePath
        Add-Result OK 'Mounted image' "$($Image.Path) - Windows build $($Image.Build) ($($Image.Version)) - provisioning and Deprovisioned keys only; user registrations in a captured image need the online run"
    }
    if ($RunAsSystem) {
        if ($Mode -ne 'Remove') { throw 'STOP: -RunAsSystem applies to -Mode Remove; -Mode Check is read-only and needs no SYSTEM session. Nothing was changed.' }
        if ($Offline) { throw 'STOP: -RunAsSystem is for the running operating system; offline servicing of a mounted image needs no SYSTEM session. Nothing was changed.' }
        if ($IsSystem) { Add-Result OK 'Run as' 'already NT AUTHORITY\SYSTEM - the removal runs in this session' }
        else {
            foreach ($P in @($PSScriptRoot, $LogPath, $OutputPath)) {
                if (-not (Test-CodecLocalPath -Path $P)) { throw "STOP: '$P' is not on a local drive. A SYSTEM session has no access to this session's network drives or credentials; copy the folder to a local path (for example C:\Temp\WIN11-CODEC-REMOVAL) and point -LogPath and -OutputPath at local folders. Nothing was changed." }
            }
            if (-not $PsExecPath) { $PsExecPath = Join-Path $Root 'tools\PsExec64.exe' }
            $PsExec = Test-CodecPsExec -Path $PsExecPath
            switch ($SystemLauncher) {
                'PsExec' {
                    if (-not $PsExec.Ok) { throw "STOP: -SystemLauncher PsExec, but $($PsExec.Reason). Put the verified PsExec64.exe in tools\ (tools\THIRD-PARTY-NOTICES.md has the hash; tools\Get-PsExec.ps1 downloads and checks it on a connected computer), or use -SystemLauncher ScheduledTask. Nothing was changed." }
                    $Launcher = 'PsExec'
                }
                'ScheduledTask' { $Launcher = 'ScheduledTask' }
                default {
                    if ($PsExec.Ok) { $Launcher = 'PsExec' }
                    else { $Launcher = 'ScheduledTask'; Add-Result WARN 'PsExec' "$($PsExec.Reason) - the child runs through a one-shot scheduled task instead" }
                }
            }
            if ($Launcher -eq 'PsExec') { Add-Result OK 'PsExec' "$($PsExec.Path) version $($PsExec.Version) - SHA256 $($PsExec.Hash) matches the pinned value - Authenticode $($PsExec.SignatureStatus)$(if ($PsExec.Signer) { " ($($PsExec.Signer))" })" }
            $SystemRun = $true
            Add-Result OK 'Run as' "NT AUTHORITY\SYSTEM through $(if ($Launcher -eq 'PsExec') { 'PsExec -s' } else { 'a one-shot scheduled task' }) - a child run (session 0, Windows PowerShell 5.1) whose files carry the tag $ChildTag"
        }
    }

    if ($ListPackages) {
        # ---- 2. List every catalog package (read-only) and the commands to remove the ones that are present
        $State = Read-CodecState
        $Listing = @(Get-CodecPackageListing -Installed $State.Installed -Provisioned $State.Provisioned -DeprovisionedKey $State.Keys -Offline:$Offline)
        $ListFile = Join-Path $OutputPath "codec-packages-$($env:COMPUTERNAME)-$Stamp$TagSuffix.csv"
        $Listing | Select-Object Package, DisplayName, StoreId, DefaultTarget, Present, State, Installed, Provisioned, KeyPresent, Decodes, Breaks | Export-Csv -LiteralPath $ListFile -NoTypeInformation -Encoding UTF8 -WhatIf:$false
        $Where = $env:COMPUTERNAME
        if ($Offline) { $Where = "mounted image $($Image.Path)" }
        Write-Host ''
        Write-Host "Codec packages this script can remove - $Where" -ForegroundColor Cyan
        $Listing | Select-Object @{ Name = 'Package (use with -Package)'; Expression = { $_.Package } }, @{ Name = 'Store listing'; Expression = { $_.DisplayName } }, @{ Name = 'Default'; Expression = { if ($_.DefaultTarget) { 'yes' } else { '' } } }, @{ Name = 'State'; Expression = { $_.State } } | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
        # Default targets first, so the single-package example is the one a scanner most likely flagged
        $PresentNames = @(@($Listing | Where-Object { $_.Present -and $_.DefaultTarget } | ForEach-Object { $_.Package }) + @($Listing | Where-Object { $_.Present -and -not $_.DefaultTarget } | ForEach-Object { $_.Package }))
        Add-Result OK 'Package list' "$($Listing.Count) package(s) in the catalog, $($PresentNames.Count) present - $ListFile"
        if ($PresentNames.Count -gt 0) {
            $Hints.Add('Remove one package (asks Y/N first; add -WhatIf to see the plan only):')
            $Hints.Add("  $CommandName -Mode Remove$(Get-CodecRerunArgument @($PresentNames[0]))")
            if ($PresentNames.Count -gt 1) {
                $Hints.Add("Remove all $($PresentNames.Count) present packages:")
                $Hints.Add("  $CommandName -Mode Remove$(Get-CodecRerunArgument $PresentNames)")
            }
            $NotDefault = @($Listing | Where-Object { $_.Present -and -not $_.DefaultTarget } | ForEach-Object { $_.Package })
            if ($NotDefault.Count -gt 0) { $Hints.Add("Not default targets: $($NotDefault -join ', '). The Breaks column of $ListFile says what stops working without each one.") }
        }
        else { $Hints.Add("None of the catalog packages is installed or provisioned $(if ($Offline) { 'in this image' } else { 'on this computer' }).") }
    }
    else {
        # ---- 2. Current state (read-only) and the plan
        $State = Read-CodecState
        $Plan = @(Get-CodecPlan -Target $Targets -Installed $State.Installed -Provisioned $State.Provisioned -DeprovisionedKey $State.Keys)
        $Blockers = @()
        if (-not $Offline) { $Blockers = @(Find-CodecBlocker -Installed $State.Installed) }
        foreach ($P in $Plan) {
            $Facts = New-Object System.Collections.Generic.List[string]
            foreach ($I in $P.Installed) {
                $Facts.Add("installed $($I.Version) for $(Get-CodecUserList $I)")
                if ((Get-CodecFamilyName "$($I.PackageFullName)") -ne $P.FamilyName) { Add-Result WARN "$($P.Name) publisher" "$($I.PackageFullName) is not signed by the Microsoft Store publisher ID; it was sideloaded" }
            }
            foreach ($V in $P.Provisioned) { $Facts.Add("provisioned $($V.Version) (every new user profile gets it)") }
            if ($P.KeyPresent) { $Facts.Add('Deprovisioned key present') } else { $Facts.Add('no Deprovisioned key') }
            $Mine = @($Blockers | Where-Object { "$($_.Package)" -like "$($P.Name)_*" -or -not "$($_.Package)" })
            if ($P.Installed.Count -gt 0 -and $Mine.Count -gt 0) { $Facts.Add('IN USE by ' + (Format-BlockerDetail $Mine)) }
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
                $Hints.Add("$($Present.Count) of $($Plan.Count) target package(s) still present. Remove them:  $CommandName -Mode Remove$(Get-CodecRerunArgument @($Present | ForEach-Object { $_.Name }))")
                if ($Blockers.Count -gt 0) { $Hints.Add("These processes hold a package file: $(Format-Blocker $Blockers). The removal is tried anyway; on a build that refuses while a file is loaded (0x80073D02), add -StopBlockingProcesses (closes them) or -RunAsSystem (runs the removal as NT AUTHORITY\SYSTEM).") }
            }
            else { $Hints.Add('Every target package is gone from this computer.') }
        }
        else {
            # ---- 3. Plan, confirm
            $Work = @($Plan | Where-Object { -not $_.AlreadyClean })
            if ($Work.Count -eq 0) {
                Add-Result OK 'Already current' 'every target package is removed, deprovisioned and keyed - nothing to change'
                if (-not $WhatIfPreference) { Write-CodecEvent -Id 1002 -EntryType Information -Message "Remove-CodecExtension: nothing to do for $($Targets -join ', ')" | Out-Null }
            }
            else {
                $Refused = @($Blockers | Where-Object { (Get-CodecBlockerAction $_.ProcessName) -eq 'refuse' })
                $Child = $null
                if ($SystemRun) { $Child = Get-CodecSystemCommand -ScriptPath $PSCommandPath -Package $Targets -LogPath $LogPath -OutputPath $OutputPath -RunTag $ChildTag -StopBlockingProcesses:$StopBlockingProcesses -DeprovisionedKeyRoot $DeprovisionedKeyRoot }
                $Detail = New-Object System.Collections.Generic.List[string]
                $Detail.Add("Computer: $env:COMPUTERNAME$(if ($Offline) { ' - mounted image ' + $Image.Path })")
                foreach ($W in $Work) { foreach ($A in $W.Actions) { $Detail.Add("$($W.Name): $A") } }
                if ($Blockers.Count -gt 0) {
                    if ($StopBlockingProcesses) { $Detail.Add("Processes with a package file loaded: $(Format-Blocker $Blockers). The removal is tried first; if Windows refuses (0x80073D02) they are stopped and the removal retried$(if (@($Blockers | Where-Object { $_.ProcessName -ieq 'explorer' }).Count -gt 0) { ' (Explorer is started again afterwards)' }).") }
                    else { $Detail.Add("Processes with a package file loaded: $(Format-Blocker $Blockers). The removal is tried anyway; if Windows refuses (0x80073D02) the package is reported as in use and skipped (-StopBlockingProcesses closes them).") }
                    if ($StopBlockingProcesses -and $Refused.Count -gt 0) { $Detail.Add("Never stopped (system, security or management process): $(Format-Blocker $Refused) - a package Windows refuses because of them stays until a run before anyone signs in.") }
                }
                if ($SystemRun) {
                    $Detail.Add("Run as: NT AUTHORITY\SYSTEM through $(if ($Launcher -eq 'PsExec') { "PsExec -s ($($PsExec.Path))" } else { "a one-shot scheduled task ($CodecSystemTaskPrefix$Stamp)" }) - a child run in session 0 with Windows PowerShell 5.1; its files carry the tag $ChildTag")
                    $Detail.Add("Child command: $($Child.Script)")
                }
                $Detail.Add('Effect: Photos, Paint, Explorer thumbnails, Media Player, Edge and WebView2 apps can no longer decode these formats on this computer. Browsers keep their own WebP decoder; Teams/Zoom calls, JPEG/PNG/H.264 are not affected.')
                $Detail.Add('Undo: reinstall from the Microsoft Store (' + ((@($Work | ForEach-Object { $E = Get-CodecCatalogEntry $_.Name; "$($E.DisplayName) $($E.StoreId)".Trim() })) -join '; ') + ') and delete the Deprovisioned key to let setup provision it again.')
                if (-not $WhatIfPreference) {
                    Confirm-Change -NoConfirm:$NoConfirm -Action "REMOVE $($Work.Count) codec package(s) on $env:COMPUTERNAME$(if ($Offline) { ' (mounted image)' })$(if ($SystemRun) { " as NT AUTHORITY\SYSTEM through $Launcher" })" -Detail $Detail.ToArray()
                    $ConfirmPreference = 'None'
                }
                else { Write-Host ''; Write-Host "WhatIf - the plan for $($env:COMPUTERNAME):" -ForegroundColor Yellow; foreach ($D in $Detail) { Write-Host "  $D" -ForegroundColor Yellow } }

                # ---- 4. Evidence before, then apply
                $Before = Write-CodecInventory -Suffix 'before' -PlanRows $Plan -BlockerRows $Blockers
                Add-Result OK 'Inventory before' $Before
                if ($SystemRun) {
                    # ---- 4s. The SYSTEM child does the removal; this session waits, shows its progress and takes its rows
                    if ($WhatIfPreference) { Add-Result OK 'SYSTEM run' "WhatIf: would start the child as SYSTEM through $Launcher, wait for it and take its result rows" }
                    else {
                        $Launchers = @($Launcher)
                        if ($Launcher -eq 'PsExec' -and $SystemLauncher -eq 'Auto') { $Launchers += 'ScheduledTask' }
                        $ChildResult = $null; $Run = $null
                        if ($MutexHeld) { try { $Mutex.ReleaseMutex() } catch { }; $MutexHeld = $false }   # the child takes the mutex while it works
                        foreach ($L in $Launchers) {
                            $TaskName = "$CodecSystemTaskPrefix$Stamp"
                            Write-CodecStep CMD "start the SYSTEM child through $L$(if ($L -eq 'PsExec') { ": $($PsExec.Path) -accepteula -nobanner -s -w '$PSScriptRoot'" } else { ": task $TaskName" }) $($Child.FilePath) -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <base64 of: $($Child.Script)>"
                            $Run = Invoke-CodecSystemRun -Launcher $L -PsExecPath "$(if ($null -ne $PsExec) { $PsExec.Path })" -FilePath $Child.FilePath -ArgumentList $Child.Argument -WorkingDirectory $PSScriptRoot -TaskName $TaskName -OnTick $OnTick
                            & $OnTick
                            Write-CodecStep INFO "$L returned after $($Run.Seconds) s with exit code $($Run.ExitCode)$(if ($Run.LauncherOutput) { ' - ' + $Run.LauncherOutput })$(if ($Run.Error) { ' - ' + $Run.Error })"
                            $ChildResult = Get-CodecChildResult -LogPath $LogPath -RunTag $ChildTag
                            if ($ChildResult.Found) { $Launcher = $L; break }
                            if ($L -ne $Launchers[-1]) { Add-Result WARN "SYSTEM run ($L)" "the child left no result file (exit code $($Run.ExitCode)$(if ($Run.Error) { ', ' + $Run.Error })$(if ($Run.LauncherOutput) { ': ' + $Run.LauncherOutput })) - trying the scheduled task launcher" }
                        }
                        try { $MutexHeld = $Mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $MutexHeld = $true }
                        if ($ChildResult.Found) {
                            Add-Result OK "SYSTEM run ($Launcher)" "finished in $($Run.Seconds) s with exit code $($Run.ExitCode) - transcript $($ChildResult.Transcript) - step log $($ChildResult.StepLog)"
                            foreach ($Row in $ChildResult.Rows) {
                                Add-Result "$($Row.Status)" "[SYSTEM] $($Row.Check)" "$($Row.Detail)"
                                if ("$($Row.Status)" -eq 'FAIL' -and "$($Row.Check)" -match '^(?<name>Microsoft\.[A-Za-z0-9]+) ') {
                                    $Failed.Add($Matches.name)
                                    if (-not $FailKind.ContainsKey($Matches.name)) { $FailKind[$Matches.name] = Get-CodecFailureKind "$($Row.Detail)" }
                                }
                            }
                            if (@($ChildResult.Rows | Where-Object { "$($_.Check)" -eq 'Explorer' -and "$($_.Status)" -eq 'WARN' }).Count -gt 0 -and -not $IsSystem) {
                                Start-Process -FilePath (Join-Path $env:SystemRoot 'explorer.exe') | Out-Null
                                Add-Result OK 'Explorer' 'started again by this session (the SYSTEM session had stopped it)'
                            }
                        }
                        else {
                            Add-Result FAIL 'SYSTEM run' "no result file from the SYSTEM session (expected Remove-CodecExtension-Remove-*-$ChildTag.csv in $LogPath) - launcher $Launcher, exit code $($Run.ExitCode)$(if ($Run.Error) { ', ' + $Run.Error })$(if ($Run.LauncherOutput) { ': ' + $Run.LauncherOutput })"
                            Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: the SYSTEM child run left no result on $env:COMPUTERNAME ($Launcher, exit code $($Run.ExitCode))" | Out-Null
                            foreach ($W in $Work) { $Failed.Add($W.Name); $FailKind[$W.Name] = 'other' }
                        }
                    }
                }
                else {
                    # ---- 4a-4c. This session does the removal
                    if (-not $WhatIfPreference) { Write-CodecEvent -Id 1000 -EntryType Information -Message "Remove-CodecExtension: removal started by $RunAs for $(($Work | ForEach-Object { $_.Name }) -join ', ')$(if ($Offline) { ' in mounted image ' + $Image.Path })" | Out-Null }
                    foreach ($W in $Work) {
                        $Check = $W.Name
                        # 4a. every user profile (online only). Tried first even when a process holds a file; stopped and
                        #     retried only after Windows has refused with 0x80073D02 and -StopBlockingProcesses is set.
                        foreach ($I in $W.Installed) {
                            $Full = "$($I.PackageFullName)"
                            $HeldBefore = @($Blockers | Where-Object { "$($_.Package)" -eq $Full })
                            if (-not $PSCmdlet.ShouldProcess($Full, 'Remove package for every user')) { Add-Result OK "$Check users" "WhatIf: would remove $Full for every user$(if ($HeldBefore.Count -gt 0) { " (a file of it is loaded by $(Format-Blocker $HeldBefore))" })"; continue }
                            $Done = $false; $Why = $null; $Holders = ''
                            for ($Try = 1; $Try -le 3 -and -not $Done; $Try++) {
                                $CallStart = (Get-Date).AddSeconds(-2)
                                Write-CodecStep CMD "try $Try of 3: Remove-AppxPackage -Package $Full -AllUsers"
                                try { Remove-AppxPackage -Package $Full -AllUsers -ErrorAction Stop; $Done = $true; Write-CodecStep INFO "try $Try of 3: removed $Full for every user" }
                                catch {
                                    $Why = Get-CodecFailure -ErrorRecord $_ -PackageName $Full -Since $CallStart
                                    Write-CodecStep INFO "try $Try of 3: failed - $($Why.Text)"
                                    if ($Why.Code -eq '0x80073CF1') { $Done = $true; break }
                                    if ($Why.Code -ne '0x80073D02') { break }
                                    $Again = @(Find-CodecBlocker -Installed @($I))
                                    $Holders = Format-BlockerDetail $Again
                                    if (-not $StopBlockingProcesses -or $Try -ge 3) { break }
                                    $RefusedNow = @($Again | Where-Object { (Get-CodecBlockerAction $_.ProcessName) -eq 'refuse' })
                                    if ($RefusedNow.Count -gt 0) { Add-Result WARN "$Check users" "try $Try - in use by $Holders; $(Format-Blocker $RefusedNow) must not be killed, no retry"; break }
                                    Add-Result WARN "$Check users" "try $Try - Windows refused, in use by $(if ($Holders) { $Holders } else { 'a process the scan did not find' }); $(if ($Again.Count -gt 0) { 'stopping it and retrying' } else { 'waiting 3 s and retrying' })"
                                    if ($Again.Count -gt 0) { Stop-CodecBlocker $Again } else { Start-Sleep -Seconds 3 }
                                }
                            }
                            if ($Done -and $null -ne $Why -and $Why.Code -eq '0x80073CF1') { Add-Result WARN "$Check users" "$Full was already gone ($($Why.Text))" }
                            elseif ($Done) { Add-Result OK "$Check users" "removed $Full for every user$(if ($HeldBefore.Count -gt 0) { " - $(Format-Blocker $HeldBefore) had a file of it loaded; Windows moved the folder to WindowsApps\Deleted and the file stays mapped until they exit" })" }
                            elseif ($Why.Kind -eq 'inuse') {
                                Add-Result FAIL "$Check users" "NOT removed: Windows refused, $Full is in use by $(if ($Holders) { $Holders } else { 'a process the scan did not find' }) - $($Why.Text)$($Why.LogNote)"
                                Write-CodecEvent -Id 2001 -EntryType Warning -Message "Remove-CodecExtension: $Full not removed, in use by $(if ($Holders) { $Holders } else { 'an unidentified process' }) ($($Why.Code))" | Out-Null
                                $Failed.Add($W.Name); $FailKind[$W.Name] = 'inuse'
                            }
                            else {
                                Add-Result FAIL "$Check users" "Remove-AppxPackage $Full failed: $($Why.Text)$($Why.LogNote)"
                                Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: Remove-AppxPackage $Full failed: $($Why.Text)$($Why.LogNote)" | Out-Null
                                $Failed.Add($W.Name); $FailKind[$W.Name] = $Why.Kind
                            }
                        }
                        # 4b. provisioning
                        foreach ($V in $W.Provisioned) {
                            $ProvName = "$($V.PackageName)"
                            if (-not $PSCmdlet.ShouldProcess($ProvName, 'Remove provisioned package')) { Add-Result OK "$Check provisioning" "WhatIf: would deprovision $ProvName"; continue }
                            $CallStart = (Get-Date).AddSeconds(-2)
                            Write-CodecStep CMD "Remove-AppxProvisionedPackage $(if ($Offline) { "-Path $($Image.Path)" } else { '-Online' }) -PackageName $ProvName"
                            try {
                                if ($Offline) { Remove-AppxProvisionedPackage -Path $Image.Path -PackageName $ProvName -ErrorAction Stop | Out-Null }
                                else { Remove-AppxProvisionedPackage -Online -PackageName $ProvName -ErrorAction Stop | Out-Null }
                                Add-Result OK "$Check provisioning" "deprovisioned $ProvName"
                            }
                            catch {
                                $Why = Get-CodecFailure -ErrorRecord $_ -PackageName $ProvName -Since $CallStart
                                # Windows deprovisions a package by itself while removing it for every user (seen live on
                                # 2026-10-26 and 2026-10-28); the explicit call then answers "file not found". Re-read the list:
                                # when the entry is gone, the step is done.
                                $StillProvisioned = $true
                                if (@('0x80070002', '0x80070003', '0x80073CF1') -contains $Why.Code) {
                                    try {
                                        if ($Offline) { $StillProvisioned = (@(Get-AppxProvisionedPackage -Path $Image.Path -ErrorAction Stop | Where-Object { "$($_.PackageName)" -eq $ProvName }).Count -gt 0) }
                                        else { $StillProvisioned = (@(Get-AppxProvisionedPackage -Online -ErrorAction Stop | Where-Object { "$($_.PackageName)" -eq $ProvName }).Count -gt 0) }
                                    }
                                    catch { $StillProvisioned = $true }
                                }
                                if (-not $StillProvisioned) {
                                    Write-CodecStep INFO "Remove-AppxProvisionedPackage $ProvName answered $($Why.Code); the provisioning list no longer has the package"
                                    Add-Result OK "$Check provisioning" "already deprovisioned by Windows during the removal for every user ($($Why.Text))"
                                }
                                else {
                                    Add-Result FAIL "$Check provisioning" "Remove-AppxProvisionedPackage $ProvName failed: $($Why.Text)$($Why.LogNote)"
                                    Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: Remove-AppxProvisionedPackage $ProvName failed: $($Why.Text)$($Why.LogNote)" | Out-Null
                                    $Failed.Add($W.Name)
                                    if (-not $FailKind.ContainsKey($W.Name)) { $FailKind[$W.Name] = $Why.Kind }
                                }
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
                }

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
                            Add-Result OK "$($P.Name) verified" "not registered to any user, not provisioned, Deprovisioned key present$(if ($SystemRun) { ' (checked by this session after the SYSTEM run)' })"
                            if (-not $SystemRun) { Write-CodecEvent -Id 1001 -EntryType Information -Message "Remove-CodecExtension: $($P.Name) removed for every user, deprovisioned and keyed on $env:COMPUTERNAME$(if ($Offline) { ' (mounted image ' + $Image.Path + ')' })" | Out-Null }
                        }
                        elseif ($Failed -contains $P.Name) { Add-Result WARN "$($P.Name) verified" ($Left.ToArray() -join '; ') }
                        else {
                            Add-Result FAIL "$($P.Name) verified" ($Left.ToArray() -join '; ')
                            Write-CodecEvent -Id 3001 -EntryType Error -Message "Remove-CodecExtension: $($P.Name) verification failed on $env:COMPUTERNAME - $($Left.ToArray() -join '; ')" | Out-Null
                        }
                    }
                    $AfterFile = Write-CodecInventory -Suffix 'after' -PlanRows $PlanAfter -BlockerRows @()
                    Add-Result OK 'Inventory after' $AfterFile
                    if ($Failed.Count -gt 0) {
                        $Unfinished = @($Failed | Select-Object -Unique)
                        $Hints.Add("Not finished for: $($Unfinished -join ', '). Deal with the cause below, then run the same command again; it only does what is still missing.")
                        $InUseNames = @($Unfinished | Where-Object { $FailKind[$_] -eq 'inuse' })
                        $DeniedNames = @($Unfinished | Where-Object { $FailKind[$_] -eq 'denied' })
                        $OtherNames = @($Unfinished | Where-Object { $FailKind[$_] -ne 'inuse' -and $FailKind[$_] -ne 'denied' })
                        if ($InUseNames.Count -gt 0) {
                            if ($SystemRun -or $IsSystem) { $Hints.Add("In use ($($InUseNames -join ', ')): Windows refused the removal while a process held a package file, even from the SYSTEM session. Close the apps named in the rows above or sign the users out, add -StopBlockingProcesses to have the script close them, or run before anyone signs in (a startup script).") }
                            else { $Hints.Add("In use ($($InUseNames -join ', ')): close the apps named in the rows above or sign the users out, add -StopBlockingProcesses to have the script close them, or add -RunAsSystem to run the removal as NT AUTHORITY\SYSTEM.") }
                        }
                        if ($DeniedNames.Count -gt 0) { $Hints.Add("Access denied ($($DeniedNames -join ', ')): 0x80070005 came from Windows' app deployment service, not from this session (it is elevated). Nothing needs closing; run the command again now. On build 28000 the rerun removed what the first run could not.") }
                        if ($OtherNames.Count -gt 0) { $Hints.Add("Other errors ($($OtherNames -join ', ')): see the FAIL rows above.") }
                        if ($ActivityIds.Count -gt 0) { $Hints.Add("Windows' own log of the failed step:  Get-AppPackageLog -ActivityID $(@($ActivityIds | Select-Object -Unique) -join ', ')  (Event Viewer: Microsoft-Windows-AppXDeploymentServer/Operational; this run's events are in $LogBase.appx-events.csv)") }
                        $Rerun = "$CommandName -Mode Remove$(Get-CodecRerunArgument $Unfinished)"
                        if ($SystemRun) { $Rerun += ' -RunAsSystem'; if ($SystemLauncher -ne 'Auto') { $Rerun += " -SystemLauncher $SystemLauncher" } }
                        if ($StopBlockingProcesses) { $Rerun += ' -StopBlockingProcesses' }
                        $Hints.Add("Run again:  $Rerun")
                    }
                    else { $Hints.Add("Done. No reboot is needed. Confirm any time with:  $CommandName -Mode Check$(Get-CodecRerunArgument @())") }
                }
                else { $Hints.Add('WhatIf: nothing was changed. Run without -WhatIf to perform the removal.') }
            }
        }
    }
}
catch {
    Add-Result FAIL 'Stopped' $_.Exception.Message
    if ($Mode -eq 'Remove' -and -not $WhatIfPreference) { Write-CodecEvent -Id 3000 -EntryType Error -Message "Remove-CodecExtension: stopped - $($_.Exception.Message)" | Out-Null }
}
finally {
    if ($Mode -eq 'Remove' -and -not $ListPackages -and -not $Offline -and -not $WhatIfPreference) {
        # Windows' own record of what the deployment service did during this run (and during the SYSTEM child run)
        try { $EventCount = Export-CodecAppxEvent -Since $RunStart -Path "$LogBase.appx-events.csv"; Add-Result OK 'AppX deployment log' "$EventCount event(s) since $($RunStart.ToString('HH:mm:ss')) - $LogBase.appx-events.csv" }
        catch { Add-Result WARN 'AppX deployment log' "not exported: $($_.Exception.Message)" }
    }
    Write-Host ''
    $Results | Format-Table -AutoSize -Wrap | Out-String -Width 220 | Write-Host
    $Results | Export-Csv -LiteralPath "$LogBase.csv" -NoTypeInformation -Encoding UTF8 -WhatIf:$false
    $FailCount = @($Results | Where-Object { $_.Status -eq 'FAIL' }).Count
    $WarnCount = @($Results | Where-Object { $_.Status -eq 'WARN' }).Count
    if ($FailCount -gt 0) { Write-Host "RESULT: FAILED ($FailCount failed, $WarnCount warning(s)) - $LogBase.log" -ForegroundColor Red }
    elseif ($WarnCount -gt 0) { Write-Host "RESULT: PASSED with $WarnCount warning(s) - $LogBase.log" -ForegroundColor Yellow }
    else { Write-Host "RESULT: PASSED - $LogBase.log" -ForegroundColor Green }
    Write-Host "Logs: $LogBase.csv (rows), $StepLog (every step with a timestamp)$(if ($SystemRun) { ", plus the SYSTEM child's files tagged $ChildTag in $LogPath" })" -ForegroundColor DarkGray
    foreach ($H in $Hints) { Write-Host $H -ForegroundColor Cyan }
    Write-CodecStep INFO "run finished: $FailCount failed, $WarnCount warning(s)"
    if ($null -ne $Mutex) { if ($MutexHeld) { try { $Mutex.ReleaseMutex() } catch { } }; $Mutex.Dispose() }
    try { Stop-Transcript @StopNoWhatIf | Out-Null } catch { }
}
if (@($Results | Where-Object { $_.Status -eq 'FAIL' }).Count -gt 0) { exit 1 }
