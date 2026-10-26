<#
.SYNOPSIS
    Shared functions for Remove-CodecExtension.ps1 and tests\Test-CodecRemoval.ps1: the catalog of the codec
    packages Microsoft delivers through the Store, the removal plan, the "package is in use" detection, the Appx
    HRESULT texts, the Deprovisioned registry key and the offline-hive helpers. Dot-source it; it changes nothing
    by itself.

.DESCRIPTION
    Everything that decides something lives here as a function without side effects, so the tests can prove every
    branch without removing a package. The functions that touch the system (modules, registry hive, event log,
    elevation, OS) are thin wrappers at the end; the tests replace them with mocks.

    Functions:
      Get-CodecCatalogEntry        what a package is, where it comes from, what stops working without it, Store ID
      Get-CodecFamilyName          package family name (Name_PublisherId) from a full or a provisioned package name
      ConvertTo-CodecHresultText   the Appx deployment HRESULT inside a removal error, in words
      Get-CodecUserList            the user accounts a package is registered to, as one string
      Get-CodecBlockingProcess     processes that have a file of the package loaded (the "in use" cause)
      Get-CodecBlockerAction       stop / restart / refuse for a blocking process name
      Get-CodecPlan                per package: installed, provisioned, key present, and the actions still needed
      Test-CodecOfflineImage       a mounted image folder: SOFTWARE hive present, kernel build, not the running OS
      Set-CodecDeprovisionedKey    creates the Deprovisioned key for a package family (idempotent, -WhatIf aware)
      Test-CodecDeprovisionedKey   is the key there
      Invoke-CodecNative           runs a native executable with an argument array and returns exit code + output
      Use-CodecOfflineHive         loads an offline SOFTWARE hive, runs a script block against it, unloads it
      Initialize-CodecModules      Appx and Dism, natively or through the Windows PowerShell compatibility layer
      Test-CodecElevated           is this an elevated session
      Test-CodecSystemAccount      is this running as NT AUTHORITY\SYSTEM
      Get-CodecOsInfo              caption, build, display version, edition, product type
      Get-CodecStoreAccess         can users reach the Store and does it auto-update (policy values)
      Write-CodecEvent             an Application event from source CodecExtensionRemoval

.EXAMPLE
    . "$PSScriptRoot\Codec-Common.ps1"
    Get-CodecCatalogEntry Microsoft.WebpImageExtension
    Returns the catalog entry (display name, Store ID, origin, what breaks without it).

.NOTES
    Windows PowerShell 5.1 and PowerShell 7. ASCII-only source.

    Generative AI was used in the creation and validation of this code; the result was reviewed and tested by a
    person (tests\Test-CodecRemoval.ps1 in both editions, plus a live run).
#>

# ---------------------------------------------------------------------------------------------------------------------
# The catalog. Every entry is a Microsoft Store package (publisher ID 8wekyb3d8bbwe) that Windows setup provisions
# into the image, that is registered to each user at first sign-in, and that the Microsoft Store updates - never
# Windows Update, WSUS or Configuration Manager. Store IDs were checked against apps.microsoft.com, Microsoft Learn
# or winget on 2026-10-26; an empty StoreId means the ID could not be verified that day.
# ---------------------------------------------------------------------------------------------------------------------
$CodecPublisherId = '8wekyb3d8bbwe'
$CodecMinimumBuild = 17134      # Windows 10 1803: a deprovisioned package stays removed across feature updates
$CodecDeprovisionedKeyRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned'
$CodecEventSource = 'CodecExtensionRemoval'
$CodecDefaultPackages = @('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension')
$CodecCatalog = @(
    [pscustomobject]@{
        Name = 'Microsoft.WebpImageExtension'; DisplayName = 'WebP Image Extension'; StoreId = '9PG2DK419DRG'
        Kind = 'image codec for the Windows Imaging Component (WIC), built on Google libwebp'
        Decodes = '.webp images'
        Origin = 'provisioned by Windows 10/11 setup; updated by the Microsoft Store'
        Breaks = 'opening .webp in Photos, Paint, Snipping Tool and Explorer thumbnails; browsers keep their own decoder'
    }
    [pscustomobject]@{
        Name = 'Microsoft.HEVCVideoExtension'; DisplayName = 'HEVC Video Extensions from Device Manufacturer'; StoreId = '9N4WGH0Z6VHQ'
        Kind = 'H.265/HEVC video decoder for Media Foundation (hevcdecoder_store.dll)'
        Decodes = 'H.265/HEVC video and, through the HEIF extension, .heic photos from iPhones'
        Origin = 'provisioned by Windows 11 setup or by the OEM, which pays the HEVC patent licence; updated by the Store'
        Breaks = 'HEVC playback in Photos, Media Player, Movies & TV, Edge and every WebView2 app; .heic photos'
    }
    [pscustomobject]@{
        Name = 'Microsoft.HEVCVideoExtensions'; DisplayName = 'HEVC Video Extensions (paid Store listing)'; StoreId = '9NMZLZ57R3T7'
        Kind = 'the same H.265/HEVC decoder, bought by a user from the Store'
        Decodes = 'H.265/HEVC video and .heic photos'
        Origin = 'installed by a user from the Store (not provisioned by setup)'
        Breaks = 'HEVC playback in Photos, Media Player, Edge and WebView2 apps; .heic photos'
    }
    [pscustomobject]@{
        Name = 'Microsoft.RawImageExtension'; DisplayName = 'Raw Image Extension'; StoreId = '9NCTDW2W1BH8'
        Kind = 'image codec for WIC, built on LibRaw'
        Decodes = 'camera RAW files (.cr2, .cr3, .nef, .arw, .dng, .orf, .rw2 ...)'
        Origin = 'provisioned by Windows 10/11 setup; updated by the Microsoft Store'
        Breaks = 'RAW thumbnails and viewing in Photos and Explorer; photo editors bring their own RAW decoder'
    }
    [pscustomobject]@{
        Name = 'Microsoft.HEIFImageExtension'; DisplayName = 'HEIF Image Extensions'; StoreId = '9PMMSR1CGPWG'
        Kind = 'HEIF container codec for WIC; needs the HEVC (or AV1) extension to decode the picture inside'
        Decodes = '.heic / .heif / .avif containers'
        Origin = 'provisioned by Windows 10/11 setup; updated by the Microsoft Store'
        Breaks = '.heic photos in Photos and Explorer (already broken once HEVC is gone)'
    }
    [pscustomobject]@{
        Name = 'Microsoft.AV1VideoExtension'; DisplayName = 'AV1 Video Extension'; StoreId = ''
        Kind = 'AV1 video decoder for Media Foundation'
        Decodes = 'AV1 video and .avif images (through HEIF)'
        Origin = 'provisioned by Windows 11 setup; updated by the Microsoft Store'
        Breaks = 'AV1 playback in Photos and Media Player; browsers keep their own decoder'
    }
    [pscustomobject]@{
        Name = 'Microsoft.VP9VideoExtensions'; DisplayName = 'VP9 Video Extensions'; StoreId = '9N4D0MSMP0PT'
        Kind = 'VP9 video decoder for Media Foundation'
        Decodes = 'VP9 video (.webm)'
        Origin = 'provisioned by Windows 10/11 setup; updated by the Microsoft Store'
        Breaks = 'VP9 playback in Photos and Media Player; browsers keep their own decoder'
    }
    [pscustomobject]@{
        Name = 'Microsoft.MPEG2VideoExtension'; DisplayName = 'MPEG-2 Video Extension'; StoreId = '9N95Q1ZZPMH4'
        Kind = 'MPEG-2 video decoder for Media Foundation'
        Decodes = 'MPEG-2 video (DVD, .mpg, .ts)'
        Origin = 'provisioned by Windows 10/11 setup; updated by the Microsoft Store'
        Breaks = 'MPEG-2 playback in Media Player and Movies & TV'
    }
    [pscustomobject]@{
        Name = 'Microsoft.WebMediaExtensions'; DisplayName = 'Web Media Extensions'; StoreId = '9N5TDP8VCMHS'
        Kind = 'Ogg container, Vorbis, Opus and Theora codecs for Media Foundation'
        Decodes = '.ogg / .oga / .ogv / .opus media'
        Origin = 'provisioned by Windows 10/11 setup; updated by the Microsoft Store'
        Breaks = 'Ogg/Opus/Theora playback in Media Player and Movies & TV'
    }
)

# Appx deployment HRESULTs that Remove-AppxPackage returns, in words. The message also carries the code.
$CodecHresultText = @{
    '0x80073D02' = 'ERROR_PACKAGES_IN_USE - a running process has a file of the package loaded (Edge, WebView2 hosts, Photos, Explorer thumbnails); close it or use -StopBlockingProcesses'
    '0x80073CF1' = 'ERROR_INSTALL_PACKAGE_NOT_FOUND - the package is already gone'
    '0x80073CF3' = 'ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED - another package depends on it'
    '0x80073CFA' = 'ERROR_REMOVE_FAILED - the deployment service could not remove the package; see Event Viewer, Applications and Services Logs, Microsoft-Windows-AppXDeployment-Server'
    '0x80073D01' = 'ERROR_DEPLOYMENT_BLOCKED_BY_POLICY - a policy blocks app deployment on this computer'
    '0x80073D1A' = 'ERROR_DEPLOYMENT_BLOCKED_BY_USER_LOG_OFF - a user is signing out; retry'
    '0x80070032' = 'ERROR_NOT_SUPPORTED - this app is part of Windows and cannot be removed per user'
    '0x80070005' = 'E_ACCESSDENIED - the session is not elevated or the package is protected'
}

# Processes that must never be killed to free a package file. Explorer is restarted instead (see Get-CodecBlockerAction).
$CodecNeverStop = @('system', 'registry', 'memory compression', 'secure system', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'svchost', 'dwm', 'fontdrvhost', 'sihost', 'ctfmon', 'conhost', 'powershell', 'powershell_ise', 'pwsh', 'wsmprovhost', 'ccmexec', 'msiexec', 'intunemanagementextension', 'microsoft.management.services.intunewindowsagent', 'mssense', 'msmpeng', 'sense', 'taskhostw', 'searchindexer')

function Get-CodecCatalogEntry {
    <#
    .SYNOPSIS
        The catalog entry for a package name (case-insensitive), or $null when the name is not a known codec package.
    .PARAMETER Name
        Package name as Get-AppxPackage shows it, e.g. Microsoft.WebpImageExtension.
    .EXAMPLE
        (Get-CodecCatalogEntry microsoft.rawimageextension).StoreId    # 9NCTDW2W1BH8
    .OUTPUTS
        PSCustomObject or $null
    #>
    param([string]$Name)
    foreach ($Entry in $CodecCatalog) { if ($Entry.Name -ieq "$Name".Trim()) { return $Entry } }
    return $null
}

function Get-CodecFamilyName {
    <#
    .SYNOPSIS
        Package family name (Name_PublisherId) from a full package name, a provisioned package name or a bare name.
    .DESCRIPTION
        Microsoft.WebpImageExtension_1.2.31.0_x64__8wekyb3d8bbwe      -> Microsoft.WebpImageExtension_8wekyb3d8bbwe
        Microsoft.WebpImageExtension_1.2.31.0_neutral_~_8wekyb3d8bbwe -> Microsoft.WebpImageExtension_8wekyb3d8bbwe
        Microsoft.WebpImageExtension                                  -> Microsoft.WebpImageExtension_8wekyb3d8bbwe
        The name is untrusted input (it comes from the package store); anything else throws a STOP.
    .PARAMETER PackageName
        Full, provisioned or bare package name.
    .OUTPUTS
        String
    #>
    param([Parameter(Mandatory)][string]$PackageName)
    $Value = "$PackageName".Trim()
    if ($Value -match '^(?<name>[A-Za-z0-9][A-Za-z0-9\.\-]*)$') { return "$($Matches.name)_$($CodecPublisherId)" }
    if ($Value -match '^(?<name>[A-Za-z0-9][A-Za-z0-9\.\-]*)_(?<version>\d+(\.\d+){3})_(?<arch>[A-Za-z0-9]+)_(?<resource>[^_]*)_(?<publisher>[a-z0-9]{13})$') { return "$($Matches.name)_$($Matches.publisher)" }
    throw "STOP: '$Value' is not a valid package name (expected Name_Version_Architecture_Resource_PublisherId). Nothing was changed."
}

function ConvertTo-CodecHresultText {
    <#
    .SYNOPSIS
        Finds the 0x8007xxxx / 0x8007 3Dxx HRESULT in an Appx error message and explains it.
    .PARAMETER Message
        The exception message from Remove-AppxPackage or Remove-AppxProvisionedPackage.
    .OUTPUTS
        PSCustomObject with Code (e.g. 0x80073D02 or ''), Text (the explanation, or the original message)
    #>
    param([string]$Message)
    $Text = "$Message" -replace '\s+', ' '
    $Code = ''
    if ($Text -match '0x[0-9A-Fa-f]{8}') { $Code = $Matches[0].ToUpperInvariant().Replace('0X', '0x') }
    if ($Code -and $CodecHresultText.ContainsKey($Code)) { return [pscustomobject]@{ Code = $Code; Text = "$Code $($CodecHresultText[$Code])" } }
    return [pscustomobject]@{ Code = $Code; Text = $Text.Trim() }
}

function Get-CodecUserList {
    <#
    .SYNOPSIS
        The user accounts a package is registered to, as 'DOMAIN\user (Installed), ...'. Works with the deserialized
        objects the Windows PowerShell compatibility layer returns.
    .PARAMETER Package
        One object from Get-AppxPackage -AllUsers.
    .OUTPUTS
        String
    #>
    param([object]$Package)
    $Items = @()
    try { $Items = @($Package.PackageUserInformation) } catch { $Items = @() }
    $Out = New-Object System.Collections.Generic.List[string]
    foreach ($U in $Items) {
        if ($null -eq $U) { continue }
        $Name = ''; $State = ''
        try { $Name = "$($U.UserSecurityId.Username)" } catch { }
        if (-not $Name) { try { $Name = "$($U.UserSecurityId)" } catch { } }
        if (-not $Name) { $Name = "$U" }
        try { $State = "$($U.InstallState)" } catch { }
        if ($State) { $Out.Add("$Name ($State)") } else { $Out.Add($Name) }
    }
    if ($Out.Count -eq 0) { return '(no user registration)' }
    return ($Out.ToArray() -join ', ')
}

function Get-CodecBlockingProcess {
    <#
    .SYNOPSIS
        Processes that have a file from one of the package folders loaded. This is what makes Remove-AppxPackage
        fail with 0x80073D02 "resources it modifies are currently in use".
    .DESCRIPTION
        Compares every loaded module path of every process with the package install folders
        (C:\Program Files\WindowsApps\<PackageFullName>\). Processes whose modules cannot be read (protected
        processes, other architectures) are skipped. Running elevated sees every session.
    .PARAMETER InstallLocation
        One or more package install folders (Get-AppxPackage ...).InstallLocation.
    .PARAMETER Process
        The process objects to inspect. Default: Get-Process. Tests pass fake objects.
    .OUTPUTS
        PSCustomObject per hit: ProcessName, Id, Module (relative file), Package (folder name). Wrap the call in @().
    #>
    param([string[]]$InstallLocation = @(), [object[]]$Process = $null)
    $Prefixes = @()
    foreach ($L in $InstallLocation) { if ("$L".Trim()) { $Prefixes += ("$L".Trim().TrimEnd('\') + '\') } }
    if ($Prefixes.Count -eq 0) { return @() }
    if ($null -eq $Process) { $Process = @(Get-Process -ErrorAction SilentlyContinue) }
    $Found = New-Object System.Collections.Generic.List[object]
    foreach ($P in $Process) {
        if ($null -eq $P) { continue }
        $Modules = @()
        try { $Modules = @($P.Modules) } catch { continue }
        foreach ($M in $Modules) {
            if ($null -eq $M) { continue }
            $File = ''
            try { $File = "$($M.FileName)" } catch { continue }
            if (-not $File) { continue }
            foreach ($Prefix in $Prefixes) {
                if ($File.StartsWith($Prefix, [StringComparison]::OrdinalIgnoreCase)) {
                    $Found.Add([pscustomobject]@{ ProcessName = "$($P.ProcessName)"; Id = [int]$P.Id; Module = $File.Substring($Prefix.Length); Package = (Split-Path -Leaf $Prefix.TrimEnd('\')) })
                }
            }
        }
    }
    return @($Found | Sort-Object -Property ProcessName, Id, Module -Unique)
}

function Get-CodecBlockerAction {
    <#
    .SYNOPSIS
        What -StopBlockingProcesses may do with a process that holds a package file: 'stop' (kill it), 'restart'
        (explorer: kill and start again) or 'refuse' (system, security and management processes are never killed).
    .PARAMETER ProcessName
        Process name without .exe, as Get-Process shows it.
    .OUTPUTS
        String: stop | restart | refuse
    #>
    param([string]$ProcessName)
    $N = "$ProcessName".Trim().ToLowerInvariant()
    if ($N -eq 'explorer') { return 'restart' }
    if ($CodecNeverStop -contains $N) { return 'refuse' }
    return 'stop'
}

function Get-CodecPlan {
    <#
    .SYNOPSIS
        For every target package: what is installed, what is provisioned, whether the Deprovisioned key exists, and
        the actions still needed. Pure: takes the inventories as parameters.
    .PARAMETER Target
        Package names (catalog names).
    .PARAMETER Installed
        Objects from Get-AppxPackage -AllUsers (any package; filtered here by Name).
    .PARAMETER Provisioned
        Objects from Get-AppxProvisionedPackage (any package; filtered here by DisplayName).
    .PARAMETER DeprovisionedKey
        Names of the subkeys under AppxAllUserStore\Deprovisioned (package family names).
    .OUTPUTS
        PSCustomObject per target: Name, DisplayName, FamilyName, Installed[], Provisioned[], KeyPresent, Actions[],
        Present (installed or provisioned), AlreadyClean (nothing installed, nothing provisioned, key present).
        Wrap the call in @().
    #>
    param([Parameter(Mandatory)][string[]]$Target, [object[]]$Installed = @(), [object[]]$Provisioned = @(), [string[]]$DeprovisionedKey = @())
    $Plan = New-Object System.Collections.Generic.List[object]
    foreach ($Name in $Target) {
        $Entry = Get-CodecCatalogEntry $Name
        if ($null -eq $Entry) { throw "STOP: '$Name' is not a known codec extension package. Nothing was changed." }
        $Inst = @($Installed | Where-Object { $null -ne $_ -and "$($_.Name)" -ieq $Entry.Name })
        $Prov = @($Provisioned | Where-Object { $null -ne $_ -and "$($_.DisplayName)" -ieq $Entry.Name })
        $Family = "$($Entry.Name)_$($CodecPublisherId)"
        $KeyPresent = [bool](@($DeprovisionedKey | Where-Object { "$_" -ieq $Family }).Count -gt 0)
        $Actions = New-Object System.Collections.Generic.List[string]
        foreach ($I in $Inst) { $Actions.Add("remove $($I.PackageFullName) for every user") }
        foreach ($P in $Prov) { $Actions.Add("deprovision $($P.PackageName) (new user profiles no longer get it)") }
        if (-not $KeyPresent) { $Actions.Add("write Deprovisioned key $Family (feature updates do not bring it back)") }
        $Plan.Add([pscustomobject]@{
            Name = $Entry.Name; DisplayName = $Entry.DisplayName; FamilyName = $Family
            Installed = $Inst; Provisioned = $Prov; KeyPresent = $KeyPresent; Actions = $Actions.ToArray()
            Present = ($Inst.Count -gt 0 -or $Prov.Count -gt 0)
            AlreadyClean = ($Inst.Count -eq 0 -and $Prov.Count -eq 0 -and $KeyPresent)
        })
    }
    return $Plan.ToArray()   # not @($Plan): wrapping a List[object] of custom objects throws 'Argument types do not match' on some builds
}

function Test-CodecOfflineImage {
    <#
    .SYNOPSIS
        Validates a mounted Windows image folder before offline servicing and returns its path, SOFTWARE hive path
        and kernel build. Refuses the running operating system.
    .PARAMETER Path
        The mount folder (Mount-WindowsImage -Path), e.g. C:\Mount\Win11.
    .OUTPUTS
        PSCustomObject: Path, HivePath, Build, Version
    #>
    param([Parameter(Mandatory)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) { throw "STOP: -MountedImagePath '$Path' is not a folder. Mount the image first (Mount-WindowsImage) and pass the mount folder. Nothing was changed." }
    $Full = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    $SystemDrive = [IO.Path]::GetFullPath("$env:SystemDrive\").TrimEnd('\')
    $SystemRoot = [IO.Path]::GetFullPath($env:SystemRoot).TrimEnd('\')
    if ($Full -ieq $SystemDrive -or $Full -ieq $SystemRoot) { throw "STOP: '$Full' is the running operating system, not a mounted image. Leave -MountedImagePath empty for the running OS. Nothing was changed." }
    $Hive = Join-Path $Full 'Windows\System32\config\SOFTWARE'
    $Kernel = Join-Path $Full 'Windows\System32\ntoskrnl.exe'
    if (-not (Test-Path -LiteralPath $Hive -PathType Leaf)) { throw "STOP: no SOFTWARE hive at '$Hive'. Is the image mounted read-write at '$Full'? Nothing was changed." }
    if (-not (Test-Path -LiteralPath $Kernel -PathType Leaf)) { throw "STOP: no ntoskrnl.exe at '$Kernel'; this is not a Windows image. Nothing was changed." }
    $Info = (Get-Item -LiteralPath $Kernel).VersionInfo
    $Build = 0
    [void][int]::TryParse("$($Info.ProductBuildPart)", [ref]$Build)
    if ($Build -lt $CodecMinimumBuild) { throw "STOP: the image is Windows build $Build; build $($CodecMinimumBuild) (Windows 10 1803) or later is required so a deprovisioned package stays removed. Nothing was changed." }
    return [pscustomobject]@{ Path = $Full; HivePath = $Hive; Build = $Build; Version = "$($Info.ProductVersion)" }
}

function Test-CodecDeprovisionedKey {
    <#
    .SYNOPSIS
        True when <Root>\<FamilyName> exists.
    .PARAMETER Root
        The Deprovisioned key (HKLM:\...\AppxAllUserStore\Deprovisioned, or the same path inside a loaded hive).
    .PARAMETER FamilyName
        Package family name, e.g. Microsoft.WebpImageExtension_8wekyb3d8bbwe.
    #>
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$FamilyName)
    return [bool](Test-Path -LiteralPath (Join-Path $Root $FamilyName))
}

function Set-CodecDeprovisionedKey {
    <#
    .SYNOPSIS
        Creates <Root>\<FamilyName>. Windows reads this key during a feature update and does not provision the
        package again (documented in "Keep removed apps from returning during an update").
    .PARAMETER Root
        The Deprovisioned key (live registry or inside a loaded offline hive).
    .PARAMETER FamilyName
        Package family name; validated against Name_PublisherId.
    .OUTPUTS
        String: present | created | whatif
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9\.\-]*_[a-z0-9]{13}$')][string]$FamilyName)
    $Key = Join-Path $Root $FamilyName
    if (Test-Path -LiteralPath $Key) { return 'present' }
    if ($PSCmdlet.ShouldProcess($Key, 'Create registry key')) {
        New-Item -Path $Key -Force | Out-Null
        if (-not (Test-Path -LiteralPath $Key)) { throw "STOP: the registry key $Key was not created. Check that the session is elevated." }
        return 'created'
    }
    return 'whatif'
}

function Invoke-CodecNative {
    <#
    .SYNOPSIS
        Runs a native executable with an argument array (no string-built command lines) and returns its exit code
        and combined output. Stderr is captured, never turned into a terminating error (Windows PowerShell 5.1 does
        that when $ErrorActionPreference is Stop).
    .PARAMETER FilePath
        Full path of the executable.
    .PARAMETER ArgumentList
        Arguments, one per element.
    .OUTPUTS
        PSCustomObject: ExitCode, Output
    #>
    param([Parameter(Mandatory)][string]$FilePath, [string[]]$ArgumentList = @())
    if (-not (Test-Path -LiteralPath $FilePath -PathType Leaf)) { throw "STOP: '$FilePath' not found." }
    $Previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $Output = @(& $FilePath @ArgumentList 2>&1 | ForEach-Object { "$_" }) } finally { $ErrorActionPreference = $Previous }
    return [pscustomobject]@{ ExitCode = [int]$LASTEXITCODE; Output = ($Output -join ' ').Trim() }
}

function Use-CodecOfflineHive {
    <#
    .SYNOPSIS
        Loads the SOFTWARE hive of a mounted image under HKLM\<KeyName>, runs the script block with the root path
        (HKLM:\<KeyName>) as its argument, then unloads the hive (up to five tries, with a garbage collection in
        between so no registry handle keeps it open).
    .PARAMETER HivePath
        <mount>\Windows\System32\config\SOFTWARE
    .PARAMETER Script
        Script block that receives the loaded root, e.g. { param($Root) Test-Path "$Root\Microsoft" }.
    .PARAMETER KeyName
        Temporary key name under HKLM. Default CodecOfflineSoftware.
    .OUTPUTS
        Whatever the script block returns.
    #>
    param([Parameter(Mandatory)][string]$HivePath, [Parameter(Mandatory)][scriptblock]$Script, [ValidatePattern('^[A-Za-z0-9]+$')][string]$KeyName = 'CodecOfflineSoftware')
    if (-not (Test-Path -LiteralPath $HivePath -PathType Leaf)) { throw "STOP: hive file '$HivePath' not found. Nothing was changed." }
    $Reg = Join-Path $env:SystemRoot 'System32\reg.exe'
    $Target = "HKLM\$KeyName"
    if (Test-Path -LiteralPath "HKLM:\$KeyName") { throw "STOP: $Target is already loaded (a previous run did not unload it). Run 'reg unload $Target' and retry. Nothing was changed." }
    $Load = Invoke-CodecNative -FilePath $Reg -ArgumentList @('load', $Target, $HivePath)
    if ($Load.ExitCode -ne 0) { throw "STOP: reg.exe load $Target '$HivePath' failed (exit $($Load.ExitCode)): $($Load.Output). Is the image mounted read-write and the hive not in use by DISM? Nothing was changed." }
    try { $Result = & $Script "HKLM:\$KeyName" }
    finally {
        $Unloaded = $false
        for ($Try = 1; $Try -le 5 -and -not $Unloaded; $Try++) {
            [gc]::Collect(); [gc]::WaitForPendingFinalizers()
            $Unload = Invoke-CodecNative -FilePath $Reg -ArgumentList @('unload', $Target)
            if ($Unload.ExitCode -eq 0) { $Unloaded = $true } else { Start-Sleep -Seconds 1 }
        }
        if (-not $Unloaded) { Write-Warning "The offline hive is still loaded as $Target - run 'reg unload $Target' before dismounting the image." }
    }
    return $Result
}

function Initialize-CodecModules {
    <#
    .SYNOPSIS
        Imports Appx and Dism. In PowerShell 7 the Dism module (and on some builds Appx) fails with "Class not
        registered" when loaded natively; the module is then imported through the Windows PowerShell compatibility
        layer (-UseWindowsPowerShell). Each module is probed with a read-only call before it is accepted.
    .OUTPUTS
        PSCustomObject: Appx, Dism - 'native' or 'Windows PowerShell compatibility'
    #>
    # Loading a module is not a change, but a script started with -WhatIf carries the preference into every scope,
    # including the module's own alias creation and the proxy files of the Windows PowerShell compatibility import,
    # which then silently do nothing and the probe fails. Clear the preference globally while importing, restore it after.
    $GlobalWhatIf = $Global:WhatIfPreference
    $Global:WhatIfPreference = $false
    $WhatIfPreference = $false
    $How = @{ Appx = ''; Dism = '' }
    try {
        foreach ($Name in @('Appx', 'Dism')) {
            $Probe = { param($M) try { if ($M -eq 'Appx') { Get-AppxPackage -AllUsers -Name 'Microsoft.Windows.ShellExperienceHost' -ErrorAction Stop | Out-Null } else { Get-AppxProvisionedPackage -Online -ErrorAction Stop | Select-Object -First 1 | Out-Null }; return $true } catch { return $false } }
            $Native = $false
            try { Import-Module -Name $Name -ErrorAction Stop -WarningAction SilentlyContinue; $Native = (& $Probe $Name) } catch { $Native = $false }
            if ($Native) { $How[$Name] = 'native'; continue }
            if ($PSVersionTable.PSEdition -ne 'Core') { throw "STOP: the $Name module does not work in this session (probe failed). Run from an elevated Windows PowerShell 5.1 console. Nothing was changed." }
            Remove-Module -Name $Name -Force -ErrorAction SilentlyContinue
            try { Import-Module -Name $Name -UseWindowsPowerShell -ErrorAction Stop -WarningAction SilentlyContinue } catch { throw "STOP: the $Name module could not be loaded natively or through Windows PowerShell compatibility: $($_.Exception.Message). Run from an elevated Windows PowerShell 5.1 console. Nothing was changed." }
            if (-not (& $Probe $Name)) { throw "STOP: the $Name module was loaded through Windows PowerShell compatibility but its probe failed. Run from an elevated Windows PowerShell 5.1 console. Nothing was changed." }
            $How[$Name] = 'Windows PowerShell compatibility'
        }
    }
    finally { $Global:WhatIfPreference = $GlobalWhatIf }
    return [pscustomobject]$How
}

function Test-CodecElevated {
    <#
    .SYNOPSIS
        True in an elevated session (member of the Administrators role, UAC-elevated). Uses the enum, never the
        string 'Administrator', which IsInRole always rejects.
    #>
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-CodecSystemAccount {
    <#
    .SYNOPSIS
        True when the current token is NT AUTHORITY\SYSTEM (S-1-5-18): scheduled task, MECM, Intune, psexec -s.
    #>
    return ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq 'S-1-5-18')
}

function Get-CodecOsInfo {
    <#
    .SYNOPSIS
        Caption, build number, display version (e.g. 24H2), edition ID and product type (1 = workstation) of the
        running OS.
    #>
    $Os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $Cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
    $Build = 0
    [void][int]::TryParse("$($Os.BuildNumber)", [ref]$Build)
    $Display = ''; $Edition = ''
    if ($null -ne $Cv) {
        if ($null -ne $Cv.PSObject.Properties['DisplayVersion']) { $Display = "$($Cv.DisplayVersion)" }
        if (-not $Display -and $null -ne $Cv.PSObject.Properties['ReleaseId']) { $Display = "$($Cv.ReleaseId)" }
        if ($null -ne $Cv.PSObject.Properties['EditionID']) { $Edition = "$($Cv.EditionID)" }
    }
    return [pscustomobject]@{ Caption = "$($Os.Caption)".Trim(); Build = $Build; DisplayVersion = $Display; Edition = $Edition; ProductType = [int]$Os.ProductType }
}

function Get-CodecStoreAccess {
    <#
    .SYNOPSIS
        Reads the Store policies that matter after a removal: RemoveWindowsStore (1 = users cannot open the Store,
        so they cannot reinstall) and AutoDownload (2 = Store auto-updates off, 4 = on).
    .OUTPUTS
        PSCustomObject: StoreAppBlocked, AutoUpdateOff, Detail
    #>
    $Machine = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue
    $User = Get-ItemProperty -LiteralPath 'HKCU:\Software\Policies\Microsoft\WindowsStore' -ErrorAction SilentlyContinue
    $Blocked = $false; $AutoOff = $false
    $Parts = New-Object System.Collections.Generic.List[string]
    foreach ($Pair in @(@('HKLM', $Machine), @('HKCU', $User))) {
        $Hive = $Pair[0]; $Values = $Pair[1]
        if ($null -eq $Values) { continue }
        if ($null -ne $Values.PSObject.Properties['RemoveWindowsStore']) {
            $Parts.Add("$Hive RemoveWindowsStore=$($Values.RemoveWindowsStore)")
            if ("$($Values.RemoveWindowsStore)" -eq '1') { $Blocked = $true }
        }
    }
    if ($null -ne $Machine -and $null -ne $Machine.PSObject.Properties['AutoDownload']) {
        $Parts.Add("HKLM AutoDownload=$($Machine.AutoDownload)")
        if ("$($Machine.AutoDownload)" -eq '2') { $AutoOff = $true }
    }
    if ($Parts.Count -eq 0) { $Parts.Add('no Store policy configured') }
    return [pscustomobject]@{ StoreAppBlocked = $Blocked; AutoUpdateOff = $AutoOff; Detail = ($Parts -join ', ') }
}

function Write-CodecEvent {
    <#
    .SYNOPSIS
        Writes an Application event from source CodecExtensionRemoval (created on first use). Never throws: returns
        $false when the event log is not writable, so a logging problem cannot stop a removal.
    .DESCRIPTION
        Event IDs: 1000 removal run started, 1001 package removed and verified, 1002 nothing to do,
                   2001 package in use (not removed for users), 2002 warning, 3000 run stopped, 3001 removal failed.
    .PARAMETER Id
        Event ID (see above).
    .PARAMETER EntryType
        Information, Warning or Error.
    .PARAMETER Message
        Event text.
    .OUTPUTS
        Boolean
    #>
    param([Parameter(Mandatory)][int]$Id, [ValidateSet('Information', 'Warning', 'Error')][string]$EntryType = 'Information', [Parameter(Mandatory)][string]$Message)
    try {
        if (-not [System.Diagnostics.EventLog]::SourceExists($CodecEventSource)) { [System.Diagnostics.EventLog]::CreateEventSource($CodecEventSource, 'Application') }
        $Log = New-Object System.Diagnostics.EventLog('Application')
        $Log.Source = $CodecEventSource
        $Log.WriteEntry($Message, [System.Diagnostics.EventLogEntryType]$EntryType, $Id)
        $Log.Dispose()
        return $true
    }
    catch { Write-Verbose "Event log not written: $($_.Exception.Message)"; return $false }
}
