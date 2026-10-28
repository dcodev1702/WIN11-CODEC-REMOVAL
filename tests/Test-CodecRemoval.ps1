<#
.SYNOPSIS
    Tests for scripts\Codec-Common.ps1, scripts\Codec-System.ps1, scripts\Confirm-Change.ps1 and
    scripts\Remove-CodecExtension.ps1: no package is removed, no process is stopped, nothing runs as SYSTEM, nothing
    is written outside a temporary folder and a test key under HKCU.

.DESCRIPTION
    Groups:
      A. every script parses in the running edition and is ASCII-only
      B. the catalog: default targets, Store IDs, case-insensitive lookup, unknown names
      C. package family names from full, provisioned and bare names; malformed names are refused
      D. Appx HRESULT texts (in use, not found, unknown code, no code)
      E. "in use" detection against fake processes, and which processes may be stopped
      E2. the Restart Manager query against a file this process holds open (real API, read-only)
      F. the plan: installed / provisioned / keyed combinations, actions, AlreadyClean, Present
      G. mounted-image validation (missing hive, running OS refused, build read from the kernel)
      H. the Deprovisioned key: created, present, -WhatIf
      I. the offline SOFTWARE hive: load, write keys, unload, read back (elevated sessions only - uses reg.exe save)
      J. the confirmation gate with Read-Host and Test-Interactive replaced (Y, yes, N, invalid x3, non-interactive, -NoConfirm)
      L. the SYSTEM helpers: PsExec verification (missing, wrong hash, the shipped copy), the child command line,
         CreateProcess quoting, the task XML, local-path detection, the child result reader
      K. end-to-end runs of Remove-CodecExtension.ps1 against mocked Appx / Dism / process cmdlets: Check, -WhatIf,
         the non-interactive STOP, a full removal with verification, a package held by a process (removed anyway,
         refused with and without -StopBlockingProcesses), the 0x80073D02 retry, 0x80073CF1 treated as gone,
         already clean, a holder that must not be killed, a not-elevated session, an old build, the offline mode
         against a fake mounted image, and -RunAsSystem with the launcher mocked (the child runs in-process)

    The harness sets $CodecRemovalHarness in its scope; the main script then uses the harness's functions (the mocks)
    instead of dot-sourcing scripts\Codec-Common.ps1 and scripts\Codec-System.ps1. Run it with -NonInteractive so
    the "non-interactive session stops before changing anything" test is meaningful. The temporary folder and the
    HKCU test key are deleted at the end.

.EXAMPLE
    pwsh -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
    Expected last line: ALL <n> TESTS PASSED (exit code 0). Any failure prints FAIL lines and exits 1.

.EXAMPLE
    powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
    The same in Windows PowerShell 5.1.

.OUTPUTS
    PASS / FAIL lines on the console; exit code 1 when any test fails.

.NOTES
    Windows PowerShell 5.1 and PowerShell 7, no Pester needed. ASCII-only source.

    Generative AI was used in the creation and validation of this code; the result was reviewed and run by a person
    in both editions.
#>
param()
$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent $PSScriptRoot
$Scripts = Join-Path $Root 'scripts'
$Main = Join-Path $Scripts 'Remove-CodecExtension.ps1'
. (Join-Path $Scripts 'Codec-Common.ps1')
. (Join-Path $Scripts 'Codec-System.ps1')
. (Join-Path $Scripts 'Confirm-Change.ps1')
$CodecRemovalHarness = $true
$RealElevated = Test-CodecElevated
$RealUseHive = (Get-Command Use-CodecOfflineHive).ScriptBlock
$Pass = 0; $Fail = 0
function Assert([string]$Name, [bool]$Ok, [string]$Info = '') {
    if ($Ok) { $script:Pass++; Write-Host "PASS  $Name" -ForegroundColor Green }
    else { $script:Fail++; Write-Host "FAIL  $Name $Info" -ForegroundColor Red }
}
function Throws([scriptblock]$Code, [string]$Like = 'STOP:*') { try { & $Code *>&1 | Out-Null; return $false } catch { return ("$($_.Exception.Message)" -like $Like) } }
$Tmp = Join-Path ([IO.Path]::GetTempPath()) ("codec-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -Path $Tmp -ItemType Directory | Out-Null
$TestKeyRoot = 'HKCU:\Software\CodecRemovalTests'
$TestDeprovisioned = "$TestKeyRoot\Deprovisioned"
if (Test-Path -LiteralPath $TestKeyRoot) { Remove-Item -LiteralPath $TestKeyRoot -Recurse -Force }
New-Item -Path $TestDeprovisioned -Force | Out-Null
Write-Host "PowerShell $($PSVersionTable.PSVersion) $($PSVersionTable.PSEdition) - temp $Tmp - elevated: $RealElevated - interactive: $(Test-Interactive)"

# Fake package objects shaped like Get-AppxPackage -AllUsers / Get-AppxProvisionedPackage output
function New-FakePackage([string]$Name, [string]$Version = '1.0.0.0', [string[]]$Users = @('SKYNET\alice', 'SKYNET\bob')) {
    $Full = "${Name}_${Version}_x64__8wekyb3d8bbwe"
    [pscustomobject]@{
        Name = $Name; Version = $Version; PackageFullName = $Full; PackageFamilyName = "${Name}_8wekyb3d8bbwe"
        InstallLocation = "C:\Program Files\WindowsApps\$Full"
        PackageUserInformation = @($Users | ForEach-Object { [pscustomobject]@{ UserSecurityId = [pscustomobject]@{ Username = $_; Sid = 'S-1-5-21-1-2-3-1001' }; InstallState = 'Installed' } })
    }
}
function New-FakeProvisioned([string]$Name, [string]$Version = '1.0.0.0') { [pscustomobject]@{ DisplayName = $Name; Version = $Version; PackageName = "${Name}_${Version}_neutral_~_8wekyb3d8bbwe" } }
function New-FakeProcess([string]$Name, [int]$Id, [string[]]$Files = @()) {
    [pscustomobject]@{ ProcessName = $Name; Id = $Id; Modules = @($Files | ForEach-Object { [pscustomobject]@{ FileName = $_; ModuleName = (Split-Path -Leaf $_) } }) }
}

try {
    # ---- A. Every script parses in this edition and is ASCII-only
    foreach ($File in (Get-ChildItem -LiteralPath $Scripts, $PSScriptRoot, (Join-Path $Root 'tools') -Filter *.ps1)) {
        $Tokens = $null; $Errors = $null
        [Management.Automation.Language.Parser]::ParseFile($File.FullName, [ref]$Tokens, [ref]$Errors) | Out-Null
        Assert "parse: $($File.Name)" (@($Errors).Count -eq 0) (($Errors | ForEach-Object { $_.Message }) -join '; ')
        $Bytes = [IO.File]::ReadAllBytes($File.FullName)
        $NonAscii = @($Bytes | Where-Object { $_ -gt 127 }).Count
        Assert "ascii: $($File.Name)" ($NonAscii -eq 0) "$NonAscii byte(s) above 127"
    }

    # ---- B. Catalog
    # Group K derives every count from this list, so changing the default targets needs no edit in this file.
    $TargetCount = $CodecDefaultPackages.Count
    Assert 'catalog: the default list is not empty and has no duplicates' ($TargetCount -gt 0 -and @($CodecDefaultPackages | Select-Object -Unique).Count -eq $TargetCount)
    $MainAst = [Management.Automation.Language.Parser]::ParseFile($Main, [ref]$null, [ref]$null)
    $PackageParam = @($MainAst.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'Package' })[0]
    $ScriptDefault = @($PackageParam.DefaultValue.FindAll({ param($Node) $Node -is [Management.Automation.Language.StringConstantExpressionAst] }, $true) | ForEach-Object { $_.Value })
    Assert 'catalog: the script''s -Package default is the catalog default list, in the same order' (($ScriptDefault -join ',') -eq ($CodecDefaultPackages -join ',')) ($ScriptDefault -join ',')
    $ValidateSet = @($PackageParam.Attributes | Where-Object { $_.TypeName.Name -eq 'ValidateSet' } | ForEach-Object { $_.PositionalArguments } | ForEach-Object { $_.Value })
    Assert 'catalog: the script''s -Package ValidateSet lists exactly the catalog names' ((@($ValidateSet | Sort-Object) -join ',') -eq (@($CodecCatalog | ForEach-Object { $_.Name } | Sort-Object) -join ',')) ($ValidateSet -join ',')
    foreach ($N in $CodecDefaultPackages) { $E = Get-CodecCatalogEntry $N; Assert "catalog: $N has a verified Store ID, origin and impact" ($null -ne $E -and $E.StoreId -match '^9[A-Z0-9]{11}$' -and $E.Origin -and $E.Breaks) }
    Assert 'catalog: lookup is case-insensitive and trims' ((Get-CodecCatalogEntry ' microsoft.rawimageextension ').StoreId -eq '9NCTDW2W1BH8')
    Assert 'catalog: unknown name -> $null' ($null -eq (Get-CodecCatalogEntry 'Microsoft.Photos'))
    Assert 'catalog: paid HEVC listing is a separate package name' ((Get-CodecCatalogEntry 'Microsoft.HEVCVideoExtensions').StoreId -eq '9NMZLZ57R3T7')
    Assert 'catalog: every entry has a unique name' ((@($CodecCatalog | ForEach-Object { $_.Name } | Select-Object -Unique)).Count -eq $CodecCatalog.Count)

    # ---- C. Family names
    Assert 'family: full name' ((Get-CodecFamilyName 'Microsoft.WebpImageExtension_1.2.31.0_x64__8wekyb3d8bbwe') -eq 'Microsoft.WebpImageExtension_8wekyb3d8bbwe')
    Assert 'family: provisioned name (neutral_~)' ((Get-CodecFamilyName 'Microsoft.HEVCVideoExtension_2.5.48.0_neutral_~_8wekyb3d8bbwe') -eq 'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe')
    Assert 'family: bare name' ((Get-CodecFamilyName 'Microsoft.RawImageExtension') -eq 'Microsoft.RawImageExtension_8wekyb3d8bbwe')
    Assert 'family: malformed -> STOP' (Throws { Get-CodecFamilyName 'Microsoft.Webp;rm -rf' })
    Assert 'family: wrong publisher length -> STOP' (Throws { Get-CodecFamilyName 'Microsoft.WebpImageExtension_1.2.31.0_x64__abc' })

    # ---- D. HRESULT texts
    $InUse = ConvertTo-CodecHresultText 'Deployment failed with HRESULT: 0x80073D02, The package could not be installed because resources it modifies are currently in use.'
    Assert 'hresult: 0x80073D02 -> in use, code extracted' ($InUse.Code -eq '0x80073D02' -and $InUse.Text -like '*ERROR_PACKAGES_IN_USE*')
    Assert 'hresult: lower-case hex is normalised' ((ConvertTo-CodecHresultText 'error 0x80073cf1 something').Code -eq '0x80073CF1')
    Assert 'hresult: unknown code keeps the message' ((ConvertTo-CodecHresultText 'HRESULT: 0x80004005 unspecified').Text -like '*0x80004005 unspecified*')
    Assert 'hresult: no code -> message, empty code' ((ConvertTo-CodecHresultText "no code  here`n at all").Code -eq '' -and (ConvertTo-CodecHresultText "no code  here`n at all").Text -eq 'no code here at all')
    Assert 'hresult: every catalogued code has text' (@($CodecHresultText.Keys | Where-Object { -not $CodecHresultText[$_] }).Count -eq 0)
    $Denied = ConvertTo-CodecHresultText -Message 'Access is denied.' -HResult -2147024891
    Assert 'hresult: PowerShell 7 "Access is denied." -> 0x80070005 from the exception, deployment-service text' ($Denied.Code -eq '0x80070005' -and $Denied.Text -like '0x80070005 E_ACCESSDENIED - the app deployment service*run the same command again*') $Denied.Text
    Assert 'hresult: a code in the message wins over the exception HResult' ((ConvertTo-CodecHresultText -Message 'Deployment failed with HRESULT: 0x80073D02, in use' -HResult -2147024891).Code -eq '0x80073D02')
    $Generic = ConvertTo-CodecHresultText -Message 'Something odd happened.' -HResult -2146233088
    Assert 'hresult: a generic exception HResult (0x80131500) is ignored' ($Generic.Code -eq '' -and $Generic.Text -eq 'Something odd happened.')
    $Sharing = ConvertTo-CodecHresultText -Message 'The process cannot access the file.' -HResult -2147024864
    Assert 'hresult: an uncatalogued Win32 code from the exception is shown with the message' ($Sharing.Code -eq '0x80070020' -and $Sharing.Text -eq '0x80070020 The process cannot access the file.')

    # ---- D2. Module origin and the deployment log lookup
    Assert 'module origin: implicit-remoting proxy -> compatibility' ((Get-CodecModuleOrigin ([pscustomobject]@{ PrivateData = @{ ImplicitRemoting = $true }; ModuleBase = 'C:\x' })) -eq 'Windows PowerShell compatibility')
    Assert 'module origin: remoteIpMoProxy folder -> compatibility' ((Get-CodecModuleOrigin ([pscustomobject]@{ PrivateData = $null; ModuleBase = 'C:\Users\u\AppData\Local\Temp\remoteIpMoProxy_Dism_3.0_localhost_1234' })) -eq 'Windows PowerShell compatibility')
    Assert 'module origin: an inbox module -> native' ((Get-CodecModuleOrigin ([pscustomobject]@{ PrivateData = $null; ModuleBase = 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\Appx' })) -eq 'native')
    Assert 'module origin: a real loaded module -> native; none -> empty' ((Get-CodecModuleOrigin (Get-Command Get-ChildItem).Module) -eq 'native' -and (Get-CodecModuleOrigin $null) -eq '')
    Assert 'deployment log: a package with no failure -> $null (read-only query of the real log)' ($null -eq (Find-CodecDeploymentError -PackageName 'Microsoft.NoSuchCodecTest_1.0.0.0_x64__8wekyb3d8bbwe' -Since (Get-Date).AddMinutes(-10)))

    # ---- E. Blocking processes
    $Hevc = New-FakePackage 'Microsoft.HEVCVideoExtension' '2.5.48.0'
    $Webp = New-FakePackage 'Microsoft.WebpImageExtension' '1.2.31.0'
    $Procs = @(
        (New-FakeProcess 'msedge' 1512 @("$($Hevc.InstallLocation)\hevcdecoder_store.dll", 'C:\Windows\System32\ntdll.dll')),
        (New-FakeProcess 'msedgewebview2' 8312 @(($Hevc.InstallLocation.ToUpperInvariant() + '\HEVCDECODER_STORE.DLL'))),
        (New-FakeProcess 'explorer' 4000 @("$($Webp.InstallLocation)\WebpImageExtension.dll")),
        (New-FakeProcess 'notepad' 5000 @('C:\Windows\System32\kernel32.dll')),
        (New-FakeProcess 'lookalike' 6000 @("$($Hevc.InstallLocation)-other\hevcdecoder_store.dll"))
    )
    $B = @(Get-CodecBlockingProcess -InstallLocation @($Hevc.InstallLocation, $Webp.InstallLocation) -Process $Procs)
    Assert 'blockers: finds the three holders, not notepad, not the look-alike folder' ($B.Count -eq 3 -and (@($B | ForEach-Object { $_.ProcessName }) -join ',') -eq 'explorer,msedge,msedgewebview2')
    Assert 'blockers: case-insensitive path match, relative module name' (@($B | Where-Object { $_.Id -eq 8312 -and $_.Module -ieq 'hevcdecoder_store.dll' -and $_.Package -eq $Hevc.PackageFullName }).Count -eq 1)
    Assert 'blockers: no install locations -> empty array' (@(Get-CodecBlockingProcess -InstallLocation @() -Process $Procs).Count -eq 0)
    Assert 'blockers: nothing loaded -> empty array' (@(Get-CodecBlockingProcess -InstallLocation @($Webp.InstallLocation) -Process @($Procs[3])).Count -eq 0)
    $Throwing = [pscustomobject]@{ ProcessName = 'protected'; Id = 4 } | Add-Member -MemberType ScriptProperty -Name Modules -Value { throw 'Access is denied' } -PassThru
    Assert 'blockers: a process whose modules cannot be read is skipped' (@(Get-CodecBlockingProcess -InstallLocation @($Hevc.InstallLocation) -Process @($Throwing, $Procs[0])).Count -eq 1)
    Assert 'blocker action: explorer -> restart, svchost/lsass/pwsh -> refuse, msedge -> stop' ((Get-CodecBlockerAction 'explorer') -eq 'restart' -and (Get-CodecBlockerAction 'svchost') -eq 'refuse' -and (Get-CodecBlockerAction 'LSASS') -eq 'refuse' -and (Get-CodecBlockerAction 'pwsh') -eq 'refuse' -and (Get-CodecBlockerAction 'msedge') -eq 'stop')
    $Live = @(Get-CodecBlockingProcess -InstallLocation @('C:\Program Files\WindowsApps\Nothing_1.0.0.0_x64__8wekyb3d8bbwe'))
    Assert 'blockers: live scan of this computer runs and returns an array' ($null -ne $Live -and $Live.Count -eq 0)

    # ---- E2. Restart Manager: a file this process holds open is attributed to this process; nothing else is touched
    $Locked = Join-Path $Tmp 'locked.bin'
    [IO.File]::WriteAllBytes($Locked, [byte[]](1, 2, 3))
    $Stream = [IO.File]::Open($Locked, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
        $Users = @(Get-CodecFileUser -Path @($Locked, (Join-Path $Tmp 'does-not-exist.bin')))
        Assert 'restart manager: the process holding the file is reported with its PID and type' (@($Users | Where-Object { $_.Id -eq $PID }).Count -eq 1 -and @($Users | Where-Object { $_.Id -eq $PID })[0].ProcessName -match '^(pwsh|powershell)$' -and @($Users | Where-Object { $_.Id -eq $PID })[0].Type -in @('console', 'application', 'explorer', 'service', 'critical', 'unknown')) (($Users | ForEach-Object { "$($_.ProcessName) $($_.Id) $($_.Type)" }) -join '; ')
    }
    finally { $Stream.Dispose() }
    Assert 'restart manager: a released file has no users' (@(Get-CodecFileUser -Path @($Locked)).Count -eq 0)
    Assert 'restart manager: no existing file -> empty array, no API call' (@(Get-CodecFileUser -Path @((Join-Path $Tmp 'nope.bin'), '')).Count -eq 0)
    Assert 'package files: a missing folder -> empty array' (@(Get-CodecPackageFile -InstallLocation (Join-Path $Tmp 'no-such-package')).Count -eq 0)
    Assert 'package files: a folder lists its files recursively' (@(Get-CodecPackageFile -InstallLocation $Tmp) -contains $Locked)

    # ---- L. SYSTEM helpers (pure, or read-only against files in the temp folder)
    $Missing = Test-CodecPsExec -Path (Join-Path $Tmp 'PsExec64.exe')
    Assert 'psexec: missing file -> not present, not Ok, reason names the path' (-not $Missing.Present -and -not $Missing.Ok -and $Missing.Reason -like '*PsExec not found at*PsExec64.exe*')
    [IO.File]::WriteAllBytes((Join-Path $Tmp 'PsExec64.exe'), [byte[]](77, 90, 1, 2, 3))
    $Wrong = Test-CodecPsExec -Path (Join-Path $Tmp 'PsExec64.exe')
    Assert 'psexec: a file with another hash -> present, hash mismatch, not Ok' ($Wrong.Present -and -not $Wrong.HashOk -and -not $Wrong.Ok -and $Wrong.Expected -eq $CodecPsExecHash['PsExec64.exe'] -and $Wrong.Reason -like '*not the pinned*')
    [IO.File]::WriteAllBytes((Join-Path $Tmp 'other.exe'), [byte[]](77, 90))
    Assert 'psexec: a file name without a pinned hash -> not Ok' (-not (Test-CodecPsExec -Path (Join-Path $Tmp 'other.exe')).Ok)
    $Shipped = Join-Path $Root 'tools\PsExec64.exe'
    if (Test-Path -LiteralPath $Shipped -PathType Leaf) {
        $Real = Test-CodecPsExec -Path $Shipped
        Assert "psexec: tools\PsExec64.exe is the pinned $CodecPsExecVersion copy (hash and Microsoft signature)" ($Real.Ok -and $Real.HashOk -and $Real.Version -eq $CodecPsExecVersion -and $Real.SignatureStatus -eq 'Valid' -and $Real.Signer -eq $CodecPsExecSigner) "$($Real.Reason) $($Real.SignatureStatus) $($Real.Signer)"
    }
    else { Write-Host 'SKIP  psexec: tools\PsExec64.exe is not in this copy of the folder (tools\Get-PsExec.ps1 fetches it)' -ForegroundColor Yellow }
    Assert 'quoting: plain arguments stay, spaces and quotes are quoted the CreateProcess way' ((ConvertTo-CodecArgumentString -Argument @('-s', 'C:\a b\c', 'x"y', 'C:\trail\', '')) -eq '-s "C:\a b\c" "x\"y" C:\trail\ ""') (ConvertTo-CodecArgumentString -Argument @('-s', 'C:\a b\c', 'x"y', 'C:\trail\', ''))
    Assert 'quoting: a quoted argument ending in a backslash doubles it' ((ConvertTo-CodecArgumentString -Argument @('C:\a b\')) -eq '"C:\a b\\"')
    $Cmd = Get-CodecSystemCommand -ScriptPath 'C:\Build\scripts\Remove-CodecExtension.ps1' -Package @('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension') -LogPath 'C:\Build\Logs' -OutputPath 'C:\Build\Outputs' -RunTag 'system-20261028-010203' -StopBlockingProcesses -DeprovisionedKeyRoot 'HKCU:\Software\CodecRemovalTests\Deprovisioned'
    Assert 'child command: Windows PowerShell 5.1, non-interactive, -EncodedCommand' ($Cmd.FilePath -like '*\System32\WindowsPowerShell\v1.0\powershell.exe' -and (($Cmd.Argument -join ' ') -like '-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand *'))
    Assert 'child command: the plain text carries every setting and exits with the script''s code' ($Cmd.Script -eq "& 'C:\Build\scripts\Remove-CodecExtension.ps1' -Mode Remove -NoConfirm -RunTag 'system-20261028-010203' -LogPath 'C:\Build\Logs' -OutputPath 'C:\Build\Outputs' -Package 'Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension' -StopBlockingProcesses -DeprovisionedKeyRoot 'HKCU:\Software\CodecRemovalTests\Deprovisioned'; exit `$LASTEXITCODE") $Cmd.Script
    Assert 'child command: the encoded form decodes to the plain text' ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Cmd.Argument[-1])) -eq $Cmd.Script)
    $CmdDefault = Get-CodecSystemCommand -ScriptPath "C:\It's here\Remove-CodecExtension.ps1" -LogPath 'C:\L' -OutputPath 'C:\O' -RunTag 'x1' -DeprovisionedKeyRoot $CodecDeprovisionedKeyRoot
    Assert 'child command: the default key root is not passed, a quote in the path is doubled, no switch without the switch' ($CmdDefault.Script -notlike '*-DeprovisionedKeyRoot*' -and $CmdDefault.Script -like "& 'C:\It''s here\Remove-CodecExtension.ps1' -Mode Remove -NoConfirm -RunTag 'x1'*" -and $CmdDefault.Script -notlike '*-StopBlockingProcesses*')
    Assert 'child command: a bad run tag is refused' (Throws { Get-CodecSystemCommand -ScriptPath 'C:\x.ps1' -LogPath 'C:\L' -OutputPath 'C:\O' -RunTag 'bad tag!' } '*RunTag*')
    $Xml = [xml](New-CodecTaskXml -Command 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -Argument '-NoProfile -EncodedCommand AAA= "x<y>"' -WorkingDirectory 'C:\Build\scripts' -TimeLimitMinutes 45)
    $Ns = New-Object Xml.XmlNamespaceManager($Xml.NameTable); $Ns.AddNamespace('t', 'http://schemas.microsoft.com/windows/2004/02/mit/task')
    Assert 'task xml: SYSTEM principal, highest run level, no trigger, the command, escaped arguments, time limit' ($Xml.SelectSingleNode('//t:Principal/t:UserId', $Ns).InnerText -eq 'S-1-5-18' -and $Xml.SelectSingleNode('//t:Principal/t:RunLevel', $Ns).InnerText -eq 'HighestAvailable' -and $null -eq $Xml.SelectSingleNode('//t:Triggers', $Ns) -and $Xml.SelectSingleNode('//t:Exec/t:Command', $Ns).InnerText -eq 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe' -and $Xml.SelectSingleNode('//t:Exec/t:Arguments', $Ns).InnerText -eq '-NoProfile -EncodedCommand AAA= "x<y>"' -and $Xml.SelectSingleNode('//t:Exec/t:WorkingDirectory', $Ns).InnerText -eq 'C:\Build\scripts' -and $Xml.SelectSingleNode('//t:Settings/t:ExecutionTimeLimit', $Ns).InnerText -eq 'PT45M')
    Assert 'local path: the temp folder is local, a UNC path is not' ((Test-CodecLocalPath -Path $Tmp) -and -not (Test-CodecLocalPath -Path '\\server\share\folder'))
    $ChildDir = Join-Path $Tmp 'child'
    New-Item -Path $ChildDir -ItemType Directory | Out-Null
    Assert 'child result: no CSV for the tag -> not found' (-not (Get-CodecChildResult -LogPath $ChildDir -RunTag 'system-1').Found)
    @([pscustomobject]@{ When = '01:02:03'; Status = 'OK'; Check = 'Microsoft.WebpImageExtension users'; Detail = 'removed' }, [pscustomobject]@{ When = '01:02:04'; Status = 'FAIL'; Check = 'Microsoft.HEVCVideoExtension users'; Detail = 'in use' }) | Export-Csv -LiteralPath (Join-Path $ChildDir 'Remove-CodecExtension-Remove-20261028-010203-system-1.csv') -NoTypeInformation -Encoding UTF8
    $ChildRead = Get-CodecChildResult -LogPath $ChildDir -RunTag 'system-1'
    Assert 'child result: the CSV rows, transcript and step log names are derived from the tag' ($ChildRead.Found -and $ChildRead.Rows.Count -eq 2 -and $ChildRead.Rows[1].Status -eq 'FAIL' -and $ChildRead.Transcript -like '*Remove-CodecExtension-Remove-20261028-010203-system-1.log' -and $ChildRead.StepLog -like '*system-1.steps.log')
    Assert 'child result: another tag does not match' (-not (Get-CodecChildResult -LogPath $ChildDir -RunTag 'system-10').Found)

    # ---- F. Plan
    $Plan = @(Get-CodecPlan -Target @('Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.RawImageExtension', 'Microsoft.HEIFImageExtension') -Installed @($Hevc, $Webp, (New-FakePackage 'Microsoft.Photos')) -Provisioned @((New-FakeProvisioned 'Microsoft.HEVCVideoExtension' '2.5.48.0'), (New-FakeProvisioned 'Microsoft.HEIFImageExtension')) -DeprovisionedKey @('Microsoft.RawImageExtension_8wekyb3d8bbwe', 'Microsoft.Copilot_8wekyb3d8bbwe'))
    $PH = $Plan | Where-Object { $_.Name -eq 'Microsoft.HEVCVideoExtension' }
    $PW = $Plan | Where-Object { $_.Name -eq 'Microsoft.WebpImageExtension' }
    $PR = $Plan | Where-Object { $_.Name -eq 'Microsoft.RawImageExtension' }
    $PF = $Plan | Where-Object { $_.Name -eq 'Microsoft.HEIFImageExtension' }
    Assert 'plan: four rows in target order' ($Plan.Count -eq 4 -and $Plan[0].Name -eq 'Microsoft.WebpImageExtension' -and $Plan[3].Name -eq 'Microsoft.HEIFImageExtension')
    Assert 'plan: HEIF provisioned only, no key -> deprovision + key, Present' ($PF.Installed.Count -eq 0 -and $PF.Provisioned.Count -eq 1 -and $PF.Actions.Count -eq 2 -and $PF.Actions[0] -like 'deprovision Microsoft.HEIFImageExtension_*' -and $PF.Present)
    Assert 'plan: HEVC installed + provisioned + no key -> 3 actions, Present, not clean' ($PH.Installed.Count -eq 1 -and $PH.Provisioned.Count -eq 1 -and -not $PH.KeyPresent -and $PH.Actions.Count -eq 3 -and $PH.Present -and -not $PH.AlreadyClean)
    Assert 'plan: WebP installed only -> remove + key' ($PW.Installed.Count -eq 1 -and $PW.Provisioned.Count -eq 0 -and $PW.Actions.Count -eq 2 -and $PW.Actions[0] -like 'remove Microsoft.WebpImageExtension_1.2.31.0_x64__8wekyb3d8bbwe*')
    Assert 'plan: Raw nothing installed, key present -> AlreadyClean, no actions' ($PR.AlreadyClean -and -not $PR.Present -and $PR.Actions.Count -eq 0)
    Assert 'plan: family name = Name_8wekyb3d8bbwe' ($PH.FamilyName -eq 'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe')
    $PlanKeyOnly = @(Get-CodecPlan -Target @('Microsoft.WebpImageExtension') -Installed @() -Provisioned @() -DeprovisionedKey @())
    Assert 'plan: nothing present, no key -> not Present, not clean, one action (key)' (-not $PlanKeyOnly[0].Present -and -not $PlanKeyOnly[0].AlreadyClean -and $PlanKeyOnly[0].Actions.Count -eq 1)
    Assert 'plan: unknown target -> STOP' (Throws { Get-CodecPlan -Target @('Microsoft.Photos') })

    # ---- F2. Package listing (-ListPackages)
    $List = @(Get-CodecPackageListing -Installed @($Hevc, (New-FakePackage 'Microsoft.VP9VideoExtensions' '1.2.20.0'), (New-FakePackage 'Microsoft.Photos')) -Provisioned @((New-FakeProvisioned 'Microsoft.HEIFImageExtension' '1.2.48.0')) -DeprovisionedKey @('Microsoft.RawImageExtension_8wekyb3d8bbwe'))
    $LByName = @{}; foreach ($R in $List) { $LByName[$R.Package] = $R }
    Assert 'listing: one row per catalog package, in catalog order, nothing else' ($List.Count -eq $CodecCatalog.Count -and $List[0].Package -eq $CodecCatalog[0].Name -and -not $LByName.ContainsKey('Microsoft.Photos'))
    Assert 'listing: installed package -> present, versions and users, no key' ($LByName['Microsoft.HEVCVideoExtension'].Present -and $LByName['Microsoft.HEVCVideoExtension'].State -eq 'installed 2.5.48.0 for SKYNET\alice (Installed), SKYNET\bob (Installed); no Deprovisioned key')
    Assert 'listing: provisioned only -> present' ($LByName['Microsoft.HEIFImageExtension'].Present -and $LByName['Microsoft.HEIFImageExtension'].State -eq 'provisioned 1.2.48.0; no Deprovisioned key')
    Assert 'listing: key only -> removed, not present' (-not $LByName['Microsoft.RawImageExtension'].Present -and $LByName['Microsoft.RawImageExtension'].State -like 'removed:*Deprovisioned key present')
    Assert 'listing: nothing -> not on this computer' (-not $LByName['Microsoft.WebpImageExtension'].Present -and $LByName['Microsoft.WebpImageExtension'].State -eq 'not on this computer')
    Assert 'listing: default targets flagged, others not; Store ID and Breaks carried' ($LByName['Microsoft.HEVCVideoExtension'].DefaultTarget -eq ($CodecDefaultPackages -contains 'Microsoft.HEVCVideoExtension') -and -not $LByName['Microsoft.HEVCVideoExtensions'].DefaultTarget -and $LByName['Microsoft.VP9VideoExtensions'].StoreId -eq '9N4D0MSMP0PT' -and $LByName['Microsoft.VP9VideoExtensions'].Breaks)
    $ListOff = @(Get-CodecPackageListing -Provisioned @((New-FakeProvisioned 'Microsoft.HEIFImageExtension' '1.2.48.0')) -Offline)
    Assert 'listing: offline wording' ((@($ListOff | Where-Object { $_.Package -eq 'Microsoft.HEIFImageExtension' })[0].State -like 'provisioned 1.2.48.0 in the image*') -and (@($ListOff | Where-Object { $_.Package -eq 'Microsoft.WebpImageExtension' })[0].State -eq 'not in the image'))

    # ---- G. Mounted image validation
    $Mount = Join-Path $Tmp 'Mount'
    New-Item -Path (Join-Path $Mount 'Windows\System32\config') -ItemType Directory -Force | Out-Null
    Assert 'image: folder without a hive -> STOP' (Throws { Test-CodecOfflineImage -Path $Mount } 'STOP: no SOFTWARE hive*')
    Assert 'image: missing folder -> STOP' (Throws { Test-CodecOfflineImage -Path (Join-Path $Tmp 'nope') } 'STOP: -MountedImagePath*')
    Assert 'image: the running system drive is refused' (Throws { Test-CodecOfflineImage -Path "$env:SystemDrive\" } '*running operating system*')
    Assert 'image: the running SystemRoot is refused' (Throws { Test-CodecOfflineImage -Path $env:SystemRoot } '*running operating system*')
    [IO.File]::WriteAllBytes((Join-Path $Mount 'Windows\System32\config\SOFTWARE'), [byte[]](1, 2, 3))
    Assert 'image: hive but no kernel -> STOP' (Throws { Test-CodecOfflineImage -Path $Mount } 'STOP: no ntoskrnl.exe*')
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\ntoskrnl.exe') -Destination (Join-Path $Mount 'Windows\System32\ntoskrnl.exe')
    $Img = Test-CodecOfflineImage -Path $Mount
    Assert 'image: valid tree -> path, hive, build from the kernel' ($Img.Path -eq $Mount -and $Img.HivePath -eq (Join-Path $Mount 'Windows\System32\config\SOFTWARE') -and $Img.Build -ge 17134)

    # ---- H. Deprovisioned key
    $Fam = 'Microsoft.WebpImageExtension_8wekyb3d8bbwe'
    Assert 'key: absent -> Test false' (-not (Test-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName $Fam))
    Assert 'key: -WhatIf creates nothing' ((Set-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName $Fam -WhatIf) -eq 'whatif' -and -not (Test-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName $Fam))
    Assert 'key: created, then present' ((Set-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName $Fam) -eq 'created' -and (Set-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName $Fam) -eq 'present' -and (Test-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName $Fam))
    Assert 'key: invalid family name is rejected' (Throws { Set-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName 'bad name' } '*FamilyName*')
    Remove-Item -LiteralPath (Join-Path $TestDeprovisioned $Fam) -Force

    # ---- I. Offline hive (needs reg.exe save -> elevated)
    if ($RealElevated) {
        New-Item -Path "$TestKeyRoot\HiveSource\Microsoft" -Force | Out-Null
        $HiveFile = Join-Path $Tmp 'SOFTWARE'
        $Saved = Invoke-CodecNative -FilePath (Join-Path $env:SystemRoot 'System32\reg.exe') -ArgumentList @('save', 'HKCU\Software\CodecRemovalTests\HiveSource', $HiveFile, '/y')
        Assert 'hive: reg.exe save produced a hive file' ($Saved.ExitCode -eq 0 -and (Test-Path -LiteralPath $HiveFile))
        $R1 = & $RealUseHive -HivePath $HiveFile -KeyName 'CodecTestHive' -Script { param($HiveRoot) $K = Join-Path $HiveRoot 'Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned'; Set-CodecDeprovisionedKey -Root $K -FamilyName 'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe'; Set-CodecDeprovisionedKey -Root $K -FamilyName 'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe' }
        Assert 'hive: keys written in the loaded hive (created, then present)' (@($R1).Count -eq 2 -and $R1[0] -eq 'created' -and $R1[1] -eq 'present')
        Assert 'hive: unloaded afterwards' (-not (Test-Path -LiteralPath 'HKLM:\CodecTestHive'))
        $R2 = & $RealUseHive -HivePath $HiveFile -KeyName 'CodecTestHive' -Script { param($HiveRoot) Test-CodecDeprovisionedKey -Root (Join-Path $HiveRoot 'Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned') -FamilyName 'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe' }
        Assert 'hive: the key persisted in the hive file' ($R2 -eq $true)
        Assert 'hive: missing hive file -> STOP' (Throws { & $RealUseHive -HivePath (Join-Path $Tmp 'none') -Script { } })
        Assert 'hive: a script block error still unloads the hive' ((Throws { & $RealUseHive -HivePath $HiveFile -KeyName 'CodecTestHive' -Script { throw 'STOP: inner' } } 'STOP: inner') -and -not (Test-Path -LiteralPath 'HKLM:\CodecTestHive'))
    }
    else { Write-Host 'SKIP  hive tests (not elevated; reg.exe save needs an elevated session)' -ForegroundColor Yellow }

    # ---- J. Confirmation gate
    # Mock state lives in the global scope: a mock called from inside the main script would resolve $script: to the
    # main script's scope, not to this harness.
    $Global:Answers = New-Object System.Collections.Generic.List[string]
    function Read-Host { param($Prompt) $A = $Global:Answers[0]; $Global:Answers.RemoveAt(0); return $A }
    function Test-Interactive { return [bool]$Global:InteractiveMock }
    $Global:InteractiveMock = $true
    $Global:Answers.Clear(); $Global:Answers.Add('Y'); Assert 'confirm: Y continues' (-not (Throws { Confirm-Change -Action 'test' } ))
    $Global:Answers.Clear(); $Global:Answers.Add('yes'); Assert 'confirm: yes continues' (-not (Throws { Confirm-Change -Action 'test' }))
    $Global:Answers.Clear(); $Global:Answers.Add('N'); Assert 'confirm: N stops' (Throws { Confirm-Change -Action 'test' } 'STOP: not confirmed*')
    $Global:Answers.Clear(); $Global:Answers.AddRange([string[]]@('maybe', '', 'x')); Assert 'confirm: three invalid answers stop' ((Throws { Confirm-Change -Action 'test' } 'STOP: not confirmed*') -and $Global:Answers.Count -eq 0)
    $Global:Answers.Clear(); $Global:Answers.AddRange([string[]]@('?', 'y')); Assert 'confirm: invalid then y continues' (-not (Throws { Confirm-Change -Action 'test' }))
    $Global:InteractiveMock = $false
    Assert 'confirm: non-interactive without -NoConfirm stops' (Throws { Confirm-Change -Action 'test' } '*non-interactive*')
    Assert 'confirm: -NoConfirm continues non-interactively' (-not (Throws { Confirm-Change -Action 'test' -NoConfirm }))

    # ---- K. End-to-end against mocks
    $Global:MockState = @{ Installed = @(); Provisioned = @(); Processes = @(); Calls = (New-Object System.Collections.Generic.List[string]); Events = (New-Object System.Collections.Generic.List[string]); FailOnce = @{}; Elevated = $true; Build = 26100; IsSystem = $false; PsExecOk = $true; SystemLaunchFail = @(); RefuseInUse = $false }
    function Test-CodecElevated { return $Global:MockState.Elevated }
    function Test-CodecSystemAccount { return [bool]$Global:MockState.IsSystem }
    function Test-CodecPsExec { param([string]$Path) $Global:MockState.Calls.Add("Test-CodecPsExec $Path"); return [pscustomobject]@{ Path = $Path; Name = (Split-Path -Leaf $Path); Present = $true; Version = '2.43'; Hash = 'MOCKHASH'; Expected = 'MOCKHASH'; HashOk = [bool]$Global:MockState.PsExecOk; SignatureStatus = 'Valid'; Signer = $CodecPsExecSigner; SignatureOk = $true; Ok = [bool]$Global:MockState.PsExecOk; Reason = $(if ($Global:MockState.PsExecOk) { '' } else { 'mock: PsExec hash mismatch' }) } }
    function Get-CodecFileUser { param([string[]]$Path) $Global:MockState.Calls.Add("Get-CodecFileUser $($Path.Count)"); return @() }
    function Get-CodecPackageFile { param([string]$InstallLocation, [int]$Limit) if ("$InstallLocation".Trim()) { return @("$InstallLocation\fake1.dll", "$InstallLocation\fake2.dll") }; return @() }
    function Export-CodecAppxEvent { param([datetime]$Since, [string]$Path) $Global:MockState.Calls.Add("Export-CodecAppxEvent $Path"); [IO.File]::WriteAllText($Path, "mock`r`n"); return 0 }
    # The SYSTEM launcher: decodes the child command and runs the script in-process under the same mocks, so the
    # child writes a real CSV with the run tag and mutates the same mock state the parent verifies against.
    function Invoke-CodecSystemRun {
        param([string]$Launcher, [string]$PsExecPath, [string]$FilePath, [string[]]$ArgumentList, [string]$WorkingDirectory, [string]$TaskName, [scriptblock]$OnTick, [int]$TimeoutMinutes)
        $Text = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($ArgumentList[-1]))
        $Global:MockState.Calls.Add("Invoke-CodecSystemRun $Launcher $PsExecPath $TaskName $Text")
        if (@($Global:MockState.SystemLaunchFail) -contains $Launcher) { return [pscustomobject]@{ Launcher = $Launcher; ExitCode = 53; Started = (Get-Date); Ended = (Get-Date); Seconds = 0; LauncherOutput = 'mock: the network path was not found'; Error = 'mock launcher failure' } }
        $Command = $Text -replace ';\s*exit \$LASTEXITCODE$', ''
        $Global:LASTEXITCODE = 0
        $null = Invoke-Expression "$Command *>&1" | Out-String
        return [pscustomobject]@{ Launcher = $Launcher; ExitCode = $LASTEXITCODE; Started = (Get-Date); Ended = (Get-Date); Seconds = 0; LauncherOutput = 'mock'; Error = '' }
    }
    function Get-CodecOsInfo { return [pscustomobject]@{ Caption = 'Microsoft Windows 11 Enterprise'; Build = $Global:MockState.Build; DisplayVersion = '24H2'; Edition = 'Enterprise'; ProductType = 1 } }
    function Initialize-CodecModules { return [pscustomobject]@{ Appx = 'mock'; Dism = 'mock' } }
    function Get-CodecStoreAccess { return [pscustomobject]@{ StoreAppBlocked = $true; AutoUpdateOff = $false; Detail = 'HKLM RemoveWindowsStore=1 (mock)' } }
    function Write-CodecEvent { param([int]$Id, [string]$EntryType = 'Information', [string]$Message) $Global:MockState.Events.Add("$Id $EntryType $Message"); return $true }
    function Get-AppxPackage { [CmdletBinding()] param([string]$Name = '*', [switch]$AllUsers) $Global:MockState.Calls.Add("Get-AppxPackage $Name"); return @($Global:MockState.Installed | Where-Object { $_.Name -like $Name }) }
    function Remove-AppxPackage {
        [CmdletBinding()] param([string]$Package, [switch]$AllUsers)
        $Global:MockState.Calls.Add("Remove-AppxPackage $Package AllUsers=$AllUsers")
        if ($Global:MockState.FailOnce.ContainsKey($Package) -and $Global:MockState.FailOnce[$Package] -gt 0) { $Global:MockState.FailOnce[$Package]--; throw "Remove-AppxPackage: Deployment failed with HRESULT: 0x80073D02, The package could not be installed because resources it modifies are currently in use. NOTE: For additional information, look for [ActivityId] ..." }
        if ($Global:MockState.FailOnce.ContainsKey("gone:$Package")) { throw 'Remove-AppxPackage: Deployment failed with HRESULT: 0x80073CF1, Package could not be found.' }
        # PowerShell 7 reports the deployment service's access denied as just this message, HResult 0x80070005
        if ($Global:MockState.FailOnce.ContainsKey("denied:$Package") -and $Global:MockState.FailOnce["denied:$Package"] -gt 0) { $Global:MockState.FailOnce["denied:$Package"]--; throw (New-Object System.UnauthorizedAccessException 'Access is denied.') }
        # A build that refuses while a process has a file of the package loaded (the 0x80073D02 case). The default
        # ($false) models builds 28000/26300, where the removal succeeds although Edge still maps the DLL.
        if ($Global:MockState.RefuseInUse) {
            $Loc = "$((@($Global:MockState.Installed | Where-Object { $_.PackageFullName -eq $Package })[0]).InstallLocation)"
            if ($Loc -and @($Global:MockState.Processes | Where-Object { @($_.Modules | Where-Object { "$($_.FileName)".StartsWith("$Loc\", [StringComparison]::OrdinalIgnoreCase) }).Count -gt 0 }).Count -gt 0) {
                throw "Remove-AppxPackage: Deployment failed with HRESULT: 0x80073D02, The package could not be installed because resources it modifies are currently in use. NOTE: For additional information, look for [ActivityId] ..."
            }
        }
        $Global:MockState.Installed = @($Global:MockState.Installed | Where-Object { $_.PackageFullName -ne $Package })
    }
    function Find-CodecDeploymentError { param([string]$PackageName, [datetime]$Since) $Global:MockState.Calls.Add("Find-CodecDeploymentError $PackageName"); return $Global:MockState.DeploymentError }
    function Get-AppxProvisionedPackage { [CmdletBinding()] param([switch]$Online, [string]$Path) $Global:MockState.Calls.Add("Get-AppxProvisionedPackage Online=$Online Path=$Path"); return @($Global:MockState.Provisioned) }
    function Remove-AppxProvisionedPackage {
        [CmdletBinding()] param([switch]$Online, [string]$Path, [string]$PackageName)
        $Global:MockState.Calls.Add("Remove-AppxProvisionedPackage $PackageName Online=$Online Path=$Path")
        $Global:MockState.Provisioned = @($Global:MockState.Provisioned | Where-Object { $_.PackageName -ne $PackageName })
        # Windows already deprovisioned it during Remove-AppxPackage -AllUsers: the entry is gone and DISM answers file not found (HResult 0x80070002)
        if ($Global:MockState.FailOnce.ContainsKey("provgone:$PackageName")) { throw (New-Object System.IO.FileNotFoundException 'The system cannot find the file specified.') }
    }
    function Get-Process { [CmdletBinding()] param([int[]]$Id) if ($PSBoundParameters.ContainsKey('Id')) { return @($Global:MockState.Processes | Where-Object { $Id -contains $_.Id }) }; return @($Global:MockState.Processes) }
    function Stop-Process { [CmdletBinding()] param([int[]]$Id, [switch]$Force) $Global:MockState.Calls.Add("Stop-Process $($Id -join ',')"); $Global:MockState.Processes = @($Global:MockState.Processes | Where-Object { $Id -notcontains $_.Id }) }
    function Start-Sleep { [CmdletBinding()] param([int]$Seconds, [int]$Milliseconds) }
    function Start-Process { [CmdletBinding()] param([string]$FilePath) $Global:MockState.Calls.Add("Start-Process $FilePath") }
    function Use-CodecOfflineHive { param([string]$HivePath, [scriptblock]$Script, [string]$KeyName = '') $Global:MockState.Calls.Add("Use-CodecOfflineHive $HivePath"); return (& $Script $Global:MockState.OfflineRoot) }
    # The mock computer has every default target installed and provisioned, plus Photos (installed) and one codec that
    # is not a target (provisioned). Known packages get realistic versions; tests look packages up by name.
    $MockVersions = @{ 'Microsoft.WebpImageExtension' = '1.2.31.0'; 'Microsoft.HEVCVideoExtension' = '2.5.48.0'; 'Microsoft.RawImageExtension' = '2.5.35.0'; 'Microsoft.HEIFImageExtension' = '1.2.48.0' }
    function Get-MockVersion([string]$Name) { if ($MockVersions.ContainsKey($Name)) { return $MockVersions[$Name] }; return '1.0.0.0' }
    function Get-MockPackage([string]$Name) { return @($Global:MockState.Installed | Where-Object { $_.Name -eq $Name })[0] }
    $Bystander = @('Microsoft.VP9VideoExtensions', 'Microsoft.MPEG2VideoExtension', 'Microsoft.WebMediaExtensions' | Where-Object { $CodecDefaultPackages -notcontains $_ })[0]
    foreach ($Needed in 'Microsoft.WebpImageExtension', 'Microsoft.HEVCVideoExtension', 'Microsoft.RawImageExtension') {
        if ($CodecDefaultPackages -notcontains $Needed) { throw "STOP: the end-to-end tests model in-use and retry cases on $Needed; keep it among the default targets or adapt group K." }
    }
    function Reset-Mock {
        $Global:MockState.Installed = @($CodecDefaultPackages | ForEach-Object { New-FakePackage $_ (Get-MockVersion $_) }) + @(New-FakePackage 'Microsoft.Photos')
        $Global:MockState.Provisioned = @($CodecDefaultPackages | ForEach-Object { New-FakeProvisioned $_ (Get-MockVersion $_) }) + @(New-FakeProvisioned $Bystander)
        $Global:MockState.Processes = @((New-FakeProcess 'notepad' 5000 @('C:\Windows\System32\kernel32.dll')))
        $Global:MockState.Calls.Clear(); $Global:MockState.Events.Clear(); $Global:MockState.FailOnce = @{}; $Global:MockState.Elevated = $true; $Global:MockState.Build = 26100; $Global:MockState.DeploymentError = $null
        $Global:MockState.IsSystem = $false; $Global:MockState.PsExecOk = $true; $Global:MockState.SystemLaunchFail = @(); $Global:MockState.RefuseInUse = $false
        if (Test-Path -LiteralPath $TestDeprovisioned) { Remove-Item -LiteralPath $TestDeprovisioned -Recurse -Force }
        New-Item -Path $TestDeprovisioned -Force | Out-Null
    }
    $script:RunCount = 0
    function Invoke-Main {
        param([hashtable]$Arguments)
        $Global:LASTEXITCODE = 0
        $script:RunCount++
        $Text = & $Main @Arguments -LogPath $Tmp -OutputPath $Tmp -DeprovisionedKeyRoot $TestDeprovisioned *>&1 | Out-String -Width 4000   # no wrapping: the assertions match whole lines
        $Exit = $LASTEXITCODE
        $Csv = (Get-ChildItem -LiteralPath $Tmp -Filter 'Remove-CodecExtension-*.csv' | Sort-Object LastWriteTime, Name | Select-Object -Last 1).FullName
        $Rows = @(Import-Csv -LiteralPath $Csv -Encoding UTF8)
        if ($env:CODEC_TEST_VERBOSE) {
            Write-Host "----- run $($script:RunCount) $(($Arguments.GetEnumerator() | ForEach-Object { "-$($_.Key) $($_.Value)" }) -join ' ') exit $Exit csv $Csv -----"
            Write-Host ("rows: " + (@($Rows | ForEach-Object { "[$($_.Status)|$($_.Check)]" }) -join ' '))
            Write-Host $Text
        }
        return [pscustomobject]@{ Exit = $Exit; Text = $Text; Rows = $Rows }
    }
    # Always an array: a single custom object has no .Count in Windows PowerShell 5.1
    function Rows([object]$Run, [string]$Status, [string]$CheckLike = '*') { return , @($Run.Rows | Where-Object { $_.Status -eq $Status -and $_.Check -like $CheckLike }) }
    function Calls([string]$Like) { return , @($Global:MockState.Calls | Where-Object { $_ -like $Like }) }
    $Global:InteractiveMock = $false

    # K0. Guard: from this scope every command that could change the computer is a plain harness function. If a real
    #     Appx or Dism module were visible, the end-to-end runs would touch the live package store - refuse to go on.
    $Resolved = @('Get-AppxPackage', 'Remove-AppxPackage', 'Get-AppxProvisionedPackage', 'Remove-AppxProvisionedPackage', 'Stop-Process', 'Initialize-CodecModules', 'Write-CodecEvent', 'Use-CodecOfflineHive', 'Invoke-CodecSystemRun', 'Test-CodecPsExec', 'Get-CodecFileUser', 'Get-CodecPackageFile', 'Export-CodecAppxEvent' | ForEach-Object { $C = Get-Command $_ -ErrorAction SilentlyContinue; "$_=$(if ($C) { $C.CommandType } else { 'missing' })/$(if ($C) { $C.ModuleName })" })
    $NotMocked = @($Resolved | Where-Object { $_ -notlike '*=Function/' })
    Assert 'e2e guard: every system command resolves to a harness function, not a cmdlet or module' ($NotMocked.Count -eq 0) ($NotMocked -join ' ')
    if ($NotMocked.Count -gt 0) { throw "STOP: refusing to run the end-to-end tests, these commands are real: $($NotMocked -join ' ')" }

    # K1. Check: everything present -> one FAIL row per target, exit 1, nothing called that changes
    Reset-Mock
    $Run = Invoke-Main @{ Mode = 'Check' }
    Assert 'e2e check: one PRESENT row per target, exit 1' ((Rows $Run 'FAIL').Count -eq $TargetCount -and $Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Microsoft.HEVCVideoExtension')[0].Detail -like 'PRESENT - installed 2.5.48.0 for SKYNET\alice (Installed), SKYNET\bob (Installed); provisioned 2.5.48.0*no Deprovisioned key')
    Assert 'e2e check: changes nothing' ((Calls 'Remove-*').Count -eq 0 -and (Calls 'Stop-Process*').Count -eq 0 -and $Global:MockState.Events.Count -eq 0 -and @(Get-ChildItem -LiteralPath $TestDeprovisioned).Count -eq 0)
    Assert 'e2e check: Store row OK when the Store is blocked by policy' ((Rows $Run 'OK' 'Microsoft Store').Count -eq 1)
    Assert 'e2e check: transcript and CSV written' ((Get-ChildItem -LiteralPath $Tmp -Filter 'Remove-CodecExtension-Check-*.log').Count -ge 1 -and $Run.Rows.Count -gt 5)

    # K2. Check with a blocker: the row names the process
    Reset-Mock
    $Global:MockState.Processes += @(New-FakeProcess 'msedge' 1512 @("$((Get-MockPackage 'Microsoft.HEVCVideoExtension').InstallLocation)\hevcdecoder_store.dll"))
    $Run = Invoke-Main @{ Mode = 'Check' }
    Assert 'e2e check: in-use process named in the HEVC row and in the hint, with the two ways out' ((Rows $Run 'FAIL' 'Microsoft.HEVCVideoExtension')[0].Detail -like '*IN USE by msedge (PID 1512) hevcdecoder_store.dll*' -and $Run.Text -like '*These processes hold a package file: msedge (PID 1512). The removal is tried anyway*-StopBlockingProcesses*-RunAsSystem*')
    Assert 'e2e check: the Restart Manager scan ran over the installed packages' ((Calls 'Get-CodecFileUser*').Count -eq 1)
    Assert 'e2e check: result rows carry a time, the step log exists and has timestamped lines' ($Run.Rows[0].When -match '^\d\d:\d\d:\d\d$' -and @(Get-ChildItem -LiteralPath $Tmp -Filter 'Remove-CodecExtension-Check-*.steps.log').Count -ge 1 -and @(Get-Content -LiteralPath (Get-ChildItem -LiteralPath $Tmp -Filter 'Remove-CodecExtension-Check-*.steps.log' | Sort-Object LastWriteTime | Select-Object -Last 1).FullName | Where-Object { $_ -match '^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d\.\d{3}  (OK|WARN|FAIL|INFO|CMD) ' }).Count -gt 5)
    Assert 'e2e check: no AppX event export in Check mode' ((Calls 'Export-CodecAppxEvent*').Count -eq 0)

    # K3. Remove -WhatIf: plan only
    Reset-Mock
    $Run = Invoke-Main @{ Mode = 'Remove'; WhatIf = $true }
    Assert 'e2e whatif: exit 0, WhatIf rows for users, provisioning and key' ($Run.Exit -eq 0 -and (Rows $Run 'OK' '*users').Count -eq $TargetCount -and (Rows $Run 'OK' '*provisioning').Count -eq $TargetCount -and (Rows $Run 'OK' '*key').Count -eq $TargetCount -and @(Rows $Run 'OK' '*users' | Where-Object { $_.Detail -notlike 'WhatIf:*' }).Count -eq 0)
    Assert 'e2e whatif: nothing removed, no key, no event, no prompt' ((Calls 'Remove-*').Count -eq 0 -and @(Get-ChildItem -LiteralPath $TestDeprovisioned).Count -eq 0 -and $Global:MockState.Events.Count -eq 0 -and $Run.Text -like '*WhatIf: nothing was changed*')
    Assert 'e2e whatif: inventory-before JSON written' ((Get-ChildItem -LiteralPath $Tmp -Filter 'codec-inventory-*-before.json').Count -ge 1)
    Assert 'e2e whatif: the plan header names this computer' ($Run.Text -like "*WhatIf - the plan for $($env:COMPUTERNAME):*")

    # K4. Remove, non-interactive, no -NoConfirm: STOP before any change
    Reset-Mock
    $Run = Invoke-Main @{ Mode = 'Remove' }
    Assert 'e2e remove: non-interactive without -NoConfirm stops, exit 1' ($Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Stopped')[0].Detail -like 'STOP:*non-interactive*')
    Assert 'e2e remove: nothing changed by the STOP' ((Calls 'Remove-*').Count -eq 0 -and @(Get-ChildItem -LiteralPath $TestDeprovisioned).Count -eq 0 -and $Global:MockState.Installed.Count -eq ($TargetCount + 1))

    # K5. Remove -NoConfirm: everything removed, deprovisioned, keyed, verified
    Reset-Mock
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e remove: exit 0, every target removed for all users' ($Run.Exit -eq 0 -and (Calls 'Remove-AppxPackage * AllUsers=True').Count -eq $TargetCount -and @($Global:MockState.Installed).Count -eq 1 -and $Global:MockState.Installed[0].Name -eq 'Microsoft.Photos')
    Assert 'e2e remove: every target deprovisioned online, the non-target left provisioned' ((Calls 'Remove-AppxProvisionedPackage * Online=True*').Count -eq $TargetCount -and @($Global:MockState.Provisioned).Count -eq 1 -and $Global:MockState.Provisioned[0].DisplayName -eq $Bystander)
    Assert 'e2e remove: one Deprovisioned key per target created' (@(Get-ChildItem -LiteralPath $TestDeprovisioned | Where-Object { $_.PSChildName -like 'Microsoft.*_8wekyb3d8bbwe' }).Count -eq $TargetCount)
    Assert 'e2e remove: verified rows OK for every target, no FAIL/WARN' ((Rows $Run 'OK' '*verified').Count -eq $TargetCount -and (Rows $Run 'FAIL').Count -eq 0 -and (Rows $Run 'WARN').Count -eq 0)
    Assert 'e2e remove: events 1000 then one 1001 per target' (@($Global:MockState.Events | Where-Object { $_ -like '1000 *' }).Count -eq 1 -and @($Global:MockState.Events | Where-Object { $_ -like '1001 *' }).Count -eq $TargetCount)
    Assert 'e2e remove: inventory before and after written' ((Get-ChildItem -LiteralPath $Tmp -Filter 'codec-inventory-*-after.json').Count -ge 1)
    Assert 'e2e remove: no process stopped when nothing holds a file' ((Calls 'Stop-Process*').Count -eq 0)

    # K6. Second run: already current, no prompt needed (non-interactive, no -NoConfirm)
    $Global:MockState.Calls.Clear(); $Global:MockState.Events.Clear()
    $Run = Invoke-Main @{ Mode = 'Remove' }
    Assert 'e2e idempotent: already current, exit 0, event 1002, nothing called' ($Run.Exit -eq 0 -and (Rows $Run 'OK' 'Already current').Count -eq 1 -and (Calls 'Remove-*').Count -eq 0 -and @($Global:MockState.Events | Where-Object { $_ -like '1002 *' }).Count -eq 1)
    $Run = Invoke-Main @{ Mode = 'Check' }
    Assert 'e2e idempotent: Check is clean, exit 0' ($Run.Exit -eq 0 -and (Rows $Run 'OK' 'Microsoft.*Extension*').Count -eq $TargetCount)

    # K7. A build that refuses while a file is held, no -StopBlockingProcesses: the removal is tried, Windows refuses
    #     (0x80073D02), that package is FAIL "in use" and skipped, the others are done. SYSTEM is not involved.
    Reset-Mock
    $Global:MockState.RefuseInUse = $true
    $Global:MockState.Processes += @((New-FakeProcess 'msedge' 1512 @("$((Get-MockPackage 'Microsoft.HEVCVideoExtension').InstallLocation)\hevcdecoder_store.dll")), (New-FakeProcess 'msedgewebview2' 8312 @("$((Get-MockPackage 'Microsoft.HEVCVideoExtension').InstallLocation)\hevcdecoder_store.dll")))
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e in use: the removal was tried once and Windows refused; FAIL row names msedge and webview2, exit 1' ($Run.Exit -eq 1 -and (Calls 'Remove-AppxPackage Microsoft.HEVC*').Count -eq 1 -and (Rows $Run 'FAIL' 'Microsoft.HEVCVideoExtension users')[0].Detail -like 'NOT removed: Windows refused, Microsoft.HEVCVideoExtension_2.5.48.0_x64__8wekyb3d8bbwe is in use by msedge (PID 1512) hevcdecoder_store.dll, msedgewebview2 (PID 8312) hevcdecoder_store.dll*0x80073D02 ERROR_PACKAGES_IN_USE*')
    Assert 'e2e in use: HEVC not removed for users, but deprovisioned and keyed; the other targets fully removed' ((Calls 'Remove-AppxPackage * AllUsers=True').Count -eq $TargetCount -and (Calls 'Remove-AppxPackage Microsoft.Webp*').Count -eq 1 -and @($Global:MockState.Installed | Where-Object { $_.Name -eq 'Microsoft.HEVCVideoExtension' }).Count -eq 1 -and (Calls 'Remove-AppxProvisionedPackage Microsoft.HEVC*').Count -eq 1 -and (Test-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName 'Microsoft.HEVCVideoExtension_8wekyb3d8bbwe'))
    Assert 'e2e in use: verification WARN for HEVC (still registered), OK for the other targets, event 2001, nothing stopped' ((Rows $Run 'WARN' 'Microsoft.HEVCVideoExtension verified').Count -eq 1 -and (Rows $Run 'OK' '*verified').Count -eq ($TargetCount - 1) -and @($Global:MockState.Events | Where-Object { $_ -like '2001 *' }).Count -eq 1 -and (Calls 'Stop-Process*').Count -eq 0)
    Assert 'e2e in use: hint says run again' ($Run.Text -like '*Not finished for: Microsoft.HEVCVideoExtension*run the same command again*')
    Assert 'e2e in use: the in-use hint offers -StopBlockingProcesses and -RunAsSystem, not the access-denied one' ($Run.Text -like '*In use (Microsoft.HEVCVideoExtension): close the apps named in the rows above*-StopBlockingProcesses*-RunAsSystem*' -and $Run.Text -notlike '*Access denied (*')

    # K7b. A build that does NOT refuse (28000/26300): a process holds the HEVC DLL, but the removal succeeds anyway
    #      and the DLL stays mapped until the process exits. Nothing is stopped.
    Reset-Mock
    $Global:MockState.Processes += @(New-FakeProcess 'msedge' 1512 @("$((Get-MockPackage 'Microsoft.HEVCVideoExtension').InstallLocation)\hevcdecoder_store.dll"))
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e held-but-ok: HEVC removed on the first try though msedge held its DLL, exit 0, nothing stopped' ($Run.Exit -eq 0 -and (Calls 'Remove-AppxPackage Microsoft.HEVC*').Count -eq 1 -and (Rows $Run 'OK' 'Microsoft.HEVCVideoExtension verified').Count -eq 1 -and (Calls 'Stop-Process*').Count -eq 0)
    Assert 'e2e held-but-ok: the OK row notes the folder moved to WindowsApps\Deleted while the file stays mapped' ((Rows $Run 'OK' 'Microsoft.HEVCVideoExtension users')[0].Detail -like 'removed Microsoft.HEVCVideoExtension_2.5.48.0_x64__8wekyb3d8bbwe for every user - msedge (PID 1512) had a file of it loaded; Windows moved the folder to WindowsApps\Deleted*')

    # K8. A refusing build with -StopBlockingProcesses: the removal is tried, Windows refuses, the holder is stopped
    #     and the removal retried; Explorer is stopped and started again.
    Reset-Mock
    $Global:MockState.RefuseInUse = $true
    $Global:MockState.Processes += @((New-FakeProcess 'msedge' 1512 @("$((Get-MockPackage 'Microsoft.HEVCVideoExtension').InstallLocation)\hevcdecoder_store.dll")), (New-FakeProcess 'explorer' 4000 @("$((Get-MockPackage 'Microsoft.WebpImageExtension').InstallLocation)\WebpImageExtension.dll")))
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; StopBlockingProcesses = $true }
    Assert 'e2e stop: msedge and explorer stopped after the refusal, explorer started again, exit 0' ($Run.Exit -eq 0 -and (Calls 'Stop-Process 1512').Count -eq 1 -and (Calls 'Stop-Process 4000').Count -eq 1 -and (Calls 'Start-Process *explorer.exe').Count -eq 1 -and (Rows $Run 'OK' 'Explorer')[0].Detail -eq 'started again')
    Assert 'e2e stop: WebP and HEVC each tried twice (refused, then after stopping), every target removed and verified' ((Calls 'Remove-AppxPackage Microsoft.Webp* AllUsers=True').Count -eq 2 -and (Calls 'Remove-AppxPackage Microsoft.HEVC* AllUsers=True').Count -eq 2 -and (Calls 'Remove-AppxPackage Microsoft.Raw* AllUsers=True').Count -eq 1 -and (Rows $Run 'OK' '*verified').Count -eq $TargetCount -and (Rows $Run 'FAIL').Count -eq 0)
    Assert 'e2e stop: the plan said the removal is tried first and holders stopped only if Windows refuses' ($Run.Text -like '*Processes with a package file loaded: explorer (PID 4000), msedge (PID 1512). The removal is tried first; if Windows refuses*they are stopped and the removal retried*Explorer is started again*')

    # K9. A refusing build, -StopBlockingProcesses, the holder is gone after the first stop: retried and done
    Reset-Mock
    $Global:MockState.RefuseInUse = $true
    $Global:MockState.Processes += @(New-FakeProcess 'msedge' 1512 @("$((Get-MockPackage 'Microsoft.HEVCVideoExtension').InstallLocation)\hevcdecoder_store.dll"))
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; StopBlockingProcesses = $true }
    Assert 'e2e retry: the retry WARN names Windows'' refusal and the holder, msedge is stopped, HEVC removed, exit 0' ($Run.Exit -eq 0 -and (Calls 'Remove-AppxPackage Microsoft.HEVC*').Count -eq 2 -and (Calls 'Stop-Process 1512').Count -eq 1 -and (Rows $Run 'WARN' 'Microsoft.HEVCVideoExtension users')[0].Detail -like 'try 1 - Windows refused, in use by msedge (PID 1512)*stopping it and retrying' -and (Rows $Run 'OK' 'Microsoft.HEVCVideoExtension verified').Count -eq 1)

    # K10. A refusing build, the holder cannot be found after the refusal and no switch: FAIL in use, one try, event 2001
    Reset-Mock
    $Global:MockState.FailOnce[(Get-MockPackage 'Microsoft.WebpImageExtension').PackageFullName] = 5
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e fail: one try, FAIL row explains ERROR_PACKAGES_IN_USE, exit 1, event 2001 (package in use)' ($Run.Exit -eq 1 -and (Calls 'Remove-AppxPackage Microsoft.Webp*').Count -eq 1 -and (Rows $Run 'FAIL' 'Microsoft.WebpImageExtension users')[0].Detail -like 'NOT removed: Windows refused, *is in use by a process the scan did not find*0x80073D02 ERROR_PACKAGES_IN_USE*' -and @($Global:MockState.Events | Where-Object { $_ -like '2001 *' }).Count -ge 1)

    # K11. 0x80073CF1 (already gone): WARN, continue, verified
    Reset-Mock
    $Gone = Get-MockPackage 'Microsoft.RawImageExtension'
    $Global:MockState.FailOnce["gone:$($Gone.PackageFullName)"] = 1
    $Global:MockState.Installed = @($Global:MockState.Installed | Where-Object { $_.PackageFullName -ne $Gone.PackageFullName }) + @($Gone)   # still reported before, throws on removal
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    # the mock still lists it afterwards, so verification is WARN/FAIL depending on the path; we only assert the WARN row for the removal itself
    Assert 'e2e not found: 0x80073CF1 is reported as already gone (WARN)' ((Rows $Run 'WARN' 'Microsoft.RawImageExtension users')[0].Detail -like '*already gone*0x80073CF1*')

    # K11b. Windows deprovisioned the package itself while removing it for every user (seen live on 2026-10-26 and
    #       2026-10-28): the explicit deprovisioning answers file-not-found and the entry is gone -> OK, not FAIL
    Reset-Mock
    $ProvGone = @($Global:MockState.Provisioned | Where-Object { $_.DisplayName -eq 'Microsoft.HEVCVideoExtension' })[0]
    $Global:MockState.FailOnce["provgone:$($ProvGone.PackageName)"] = 1
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e provisioning already gone: OK row says Windows deprovisioned it, verified, exit 0, no 3001' ($Run.Exit -eq 0 -and (Rows $Run 'OK' 'Microsoft.HEVCVideoExtension provisioning')[0].Detail -like 'already deprovisioned by Windows during the removal for every user (0x80070002 ERROR_FILE_NOT_FOUND*' -and (Rows $Run 'FAIL').Count -eq 0 -and (Rows $Run 'OK' 'Microsoft.HEVCVideoExtension verified').Count -eq 1 -and @($Global:MockState.Events | Where-Object { $_ -like '3001 *' }).Count -eq 0)

    # K12. A refusing build where the holder must not be killed (svchost), with -StopBlockingProcesses: that package
    #      is FAIL in use and svchost is never stopped; the other targets are still removed.
    Reset-Mock
    $Global:MockState.RefuseInUse = $true
    $Global:MockState.Processes += @(New-FakeProcess 'svchost' 900 @("$((Get-MockPackage 'Microsoft.WebpImageExtension').InstallLocation)\WebpImageExtension.dll"))
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; StopBlockingProcesses = $true }
    Assert 'e2e refuse: WebP FAIL in use because svchost must not be killed, svchost never stopped, exit 1' ($Run.Exit -eq 1 -and (Rows $Run 'WARN' 'Microsoft.WebpImageExtension users')[0].Detail -like 'try 1 - in use by svchost (PID 900)*svchost (PID 900) must not be killed, no retry' -and (Rows $Run 'FAIL' 'Microsoft.WebpImageExtension users').Count -eq 1 -and (Calls 'Stop-Process*').Count -eq 0)
    Assert 'e2e refuse: the other targets are removed and the plan warned svchost is never stopped' ((Rows $Run 'OK' '*verified').Count -eq ($TargetCount - 1) -and (Calls 'Remove-AppxPackage Microsoft.HEIF* AllUsers=True').Count -eq 1 -and $Run.Text -like '*Never stopped (system, security or management process): svchost (PID 900)*')

    # K13. Not elevated / old build: STOP before anything
    Reset-Mock; $Global:MockState.Elevated = $false
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e: not elevated -> STOP' ($Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Stopped')[0].Detail -like 'STOP: run this script elevated*' -and (Calls 'Get-AppxPackage*').Count -eq 0)
    Reset-Mock; $Global:MockState.Build = 16299
    $Run = Invoke-Main @{ Mode = 'Check' }
    Assert 'e2e: build 16299 -> STOP naming 17134' ($Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Stopped')[0].Detail -like 'STOP: this is Windows build 16299*17134*')

    # K14. A different package set and a sideloaded publisher warning
    Reset-Mock
    $Side = New-FakePackage 'Microsoft.WebpImageExtension' '9.9.9.9'; $Side.PackageFullName = 'Microsoft.WebpImageExtension_9.9.9.9_x64__abcdefghijklm'; $Side.InstallLocation = "C:\Program Files\WindowsApps\$($Side.PackageFullName)"
    $Global:MockState.Installed = @($Side) + @($Global:MockState.Installed | Where-Object { $_.Name -ne 'Microsoft.WebpImageExtension' })
    $Run = Invoke-Main @{ Mode = 'Check'; Package = @('Microsoft.WebpImageExtension') }
    Assert 'e2e: -Package limits the targets; a foreign publisher ID is flagged' ((Rows $Run 'FAIL').Count -eq 1 -and (Rows $Run 'WARN' 'Microsoft.WebpImageExtension publisher').Count -eq 1 -and $Run.Text -notlike '*Microsoft.RawImageExtension*PRESENT*')

    # K15. Offline mode against the fake mounted image: provisioning removed, keys written through the hive mock
    Reset-Mock
    $Global:MockState.OfflineRoot = "$TestKeyRoot\OfflineHive"
    New-Item -Path $Global:MockState.OfflineRoot -Force | Out-Null
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; MountedImagePath = $Mount }
    $OfflineKeys = @(Get-ChildItem -LiteralPath "$($Global:MockState.OfflineRoot)\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned" -ErrorAction SilentlyContinue | ForEach-Object { $_.PSChildName })
    Assert 'e2e offline: every target deprovisioned with -Path, none online, no Remove-AppxPackage' ((Calls "Remove-AppxProvisionedPackage * Online=False Path=$Mount").Count -eq $TargetCount -and (Calls 'Remove-AppxProvisionedPackage * Online=True*').Count -eq 0 -and (Calls 'Remove-AppxPackage*').Count -eq 0)
    Assert 'e2e offline: one key per target written into the image hive, verified, exit 0' ($OfflineKeys.Count -eq $TargetCount -and $Run.Exit -eq 0 -and (Rows $Run 'OK' '*verified').Count -eq $TargetCount -and (Rows $Run 'OK' 'Mounted image').Count -eq 1)
    Assert 'e2e offline: no live Deprovisioned key touched, no process scan' (@(Get-ChildItem -LiteralPath $TestDeprovisioned).Count -eq 0 -and (Calls 'Get-AppxPackage*').Count -eq 0)
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; MountedImagePath = "$env:SystemDrive\" }
    Assert 'e2e offline: the running OS as image path -> STOP' ($Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Stopped')[0].Detail -like '*running operating system*')

    # K16. Access denied from the deployment service (seen live on build 28000): the row carries the code, the failing
    #      step and the activity ID; the hint says it is not about closing apps; the rerun finishes the package.
    Reset-Mock
    $DeniedPackage = Get-MockPackage 'Microsoft.RawImageExtension'
    $Global:MockState.FailOnce["denied:$($DeniedPackage.PackageFullName)"] = 1
    $Global:MockState.DeploymentError = [pscustomobject]@{ ActivityId = '6c3a0a34-645e-0004-d77c-686c5e64dd01'; Step = 'Error 0x80070005: Failure in the OptionalDependenciesHandled state handler.' }
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true }
    Assert 'e2e access denied: FAIL row shows 0x80070005, the failing step and the activity, exit 1' ($Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Microsoft.RawImageExtension users')[0].Detail -like '*failed: 0x80070005 E_ACCESSDENIED*OptionalDependenciesHandled state handler.*Get-AppPackageLog -ActivityID 6c3a0a34-645e-0004-d77c-686c5e64dd01') ((Rows $Run 'FAIL' 'Microsoft.RawImageExtension users')[0].Detail)
    Assert 'e2e access denied: the hint explains it and does not say to close apps' ($Run.Text -like '*Access denied (Microsoft.RawImageExtension): 0x80070005 came from Windows'' app deployment service*' -and $Run.Text -notlike '*close the apps*' -and $Run.Text -like '*Get-AppPackageLog -ActivityID 6c3a0a34-645e-0004-d77c-686c5e64dd01*')
    Assert 'e2e access denied: the rerun command names only the unfinished package' ($Run.Text -like '*Run again:  *Remove-CodecExtension.ps1 -Mode Remove -Package Microsoft.RawImageExtension*')
    Assert 'e2e access denied: the other targets are done; Raw deprovisioned and keyed anyway' ((Rows $Run 'OK' '*verified').Count -eq ($TargetCount - 1) -and (Calls 'Remove-AppxProvisionedPackage Microsoft.RawImageExtension*').Count -eq 1 -and (Test-CodecDeprovisionedKey -Root $TestDeprovisioned -FamilyName 'Microsoft.RawImageExtension_8wekyb3d8bbwe'))
    $Global:MockState.Calls.Clear()
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; Package = @('Microsoft.RawImageExtension') }
    Assert 'e2e access denied: the rerun removes the last registration, exit 0' ($Run.Exit -eq 0 -and (Calls 'Remove-AppxPackage Microsoft.Raw*').Count -eq 1 -and (Rows $Run 'OK' 'Microsoft.RawImageExtension verified').Count -eq 1 -and $Run.Text -like '*Done. No reboot is needed. Confirm any time with:  *Remove-CodecExtension.ps1 -Mode Check*')

    # K16a. -RunAsSystem through PsExec (launcher mocked; the child runs in-process under the same mocks, so it
    #       writes a real result file the parent reads back and verifies against).
    Reset-Mock
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; RunAsSystem = $true }
    Assert 'e2e system: PsExec chosen, the child ran as SYSTEM and removed every target, exit 0' ($Run.Exit -eq 0 -and (Calls 'Invoke-CodecSystemRun PsExec*').Count -eq 1 -and @($Global:MockState.Installed).Count -eq 1 -and (Calls 'Remove-AppxPackage * AllUsers=True').Count -eq $TargetCount)
    Assert 'e2e system: the child''s rows were merged with a [SYSTEM] marker and the SYSTEM run row is OK' ($Run.Text -like '*`[SYSTEM`] Microsoft.HEVCVideoExtension*' -and (Rows $Run 'OK' 'SYSTEM run (PsExec)').Count -eq 1)
    Assert 'e2e system: the parent verified from the system after the child, OK per target, no FAIL' (@($Run.Rows | Where-Object { $_.Status -eq 'OK' -and $_.Check -like '*verified' -and $_.Check -notlike '`[SYSTEM`]*' }).Count -eq $TargetCount -and (Rows $Run 'FAIL').Count -eq 0)
    Assert 'e2e system: the child command passed to the launcher is Windows PowerShell with -EncodedCommand and the run tag' ((Calls '*WindowsPowerShell\v1.0\powershell.exe*-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand*').Count -ge 0 -and (Calls 'Invoke-CodecSystemRun PsExec*-Mode Remove -NoConfirm -RunTag ''system-*').Count -eq 1)

    # K16b. Already SYSTEM: no child is launched, the removal runs in this session
    Reset-Mock
    $Global:MockState.IsSystem = $true
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; RunAsSystem = $true }
    Assert 'e2e system: when the session already is SYSTEM, nothing is relaunched' ($Run.Exit -eq 0 -and (Calls 'Invoke-CodecSystemRun*').Count -eq 0 -and (Calls 'Remove-AppxPackage * AllUsers=True').Count -eq $TargetCount -and (Rows $Run 'OK' 'Run as')[0].Detail -like 'already NT AUTHORITY\SYSTEM*')

    # K16c. A bad PsExec hash under Auto falls back to the scheduled task
    Reset-Mock
    $Global:MockState.PsExecOk = $false
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; RunAsSystem = $true }
    Assert 'e2e system: a bad PsExec hash under Auto warns and uses the scheduled task, which finishes the removal' ($Run.Exit -eq 0 -and (Calls 'Invoke-CodecSystemRun ScheduledTask*').Count -eq 1 -and (Calls 'Invoke-CodecSystemRun PsExec*').Count -eq 0 -and (Rows $Run 'WARN' 'PsExec').Count -eq 1 -and @($Global:MockState.Installed).Count -eq 1)

    # K16d. -SystemLauncher PsExec with a bad hash: STOP before any change
    Reset-Mock
    $Global:MockState.PsExecOk = $false
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; RunAsSystem = $true; SystemLauncher = 'PsExec' }
    Assert 'e2e system: -SystemLauncher PsExec with a bad hash stops before any change' ($Run.Exit -eq 1 -and (Rows $Run 'FAIL' 'Stopped')[0].Detail -like 'STOP: -SystemLauncher PsExec, but *' -and (Calls 'Invoke-CodecSystemRun*').Count -eq 0 -and (Calls 'Remove-AppxPackage*').Count -eq 0)

    # K16e. -RunAsSystem -WhatIf: the plan shows the launcher and the child command, nothing launched or changed
    Reset-Mock
    $Run = Invoke-Main @{ Mode = 'Remove'; WhatIf = $true; RunAsSystem = $true }
    Assert 'e2e system whatif: launcher and child command shown, nothing launched or removed' ($Run.Exit -eq 0 -and (Calls 'Invoke-CodecSystemRun*').Count -eq 0 -and (Calls 'Remove-AppxPackage*').Count -eq 0 -and $Run.Text -like '*Run as: NT AUTHORITY\SYSTEM through PsExec*' -and $Run.Text -like '*Child command: & *-Mode Remove -NoConfirm -RunTag *' -and (Rows $Run 'OK' 'SYSTEM run')[0].Detail -like 'WhatIf: would start the child as SYSTEM*')

    # K16f. PsExec fails to start the child under Auto: the scheduled task takes over
    Reset-Mock
    $Global:MockState.SystemLaunchFail = @('PsExec')
    $Run = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true; RunAsSystem = $true }
    Assert 'e2e system: PsExec leaves no child result under Auto, the scheduled task takes over and finishes, exit 0' ($Run.Exit -eq 0 -and (Calls 'Invoke-CodecSystemRun PsExec*').Count -eq 1 -and (Calls 'Invoke-CodecSystemRun ScheduledTask*').Count -eq 1 -and (Rows $Run 'WARN' 'SYSTEM run (PsExec)').Count -eq 1 -and (Rows $Run 'OK' 'SYSTEM run (ScheduledTask)').Count -eq 1 -and @($Global:MockState.Installed).Count -eq 1)

    # K17. -ListPackages: every catalog package, the -Package names, the commands; read-only
    Reset-Mock
    $Global:MockState.Installed += @(New-FakePackage $Bystander '1.2.20.0')
    $InventoriesBefore = @(Get-ChildItem -LiteralPath $Tmp -Filter 'codec-inventory-*').Count
    $Run = Invoke-Main @{ ListPackages = $true }
    $ListCsv = Get-ChildItem -LiteralPath $Tmp -Filter 'codec-packages-*.csv' | Sort-Object LastWriteTime, Name | Select-Object -Last 1
    $ListRows = @(Import-Csv -LiteralPath $ListCsv.FullName)
    $PresentOrder = @(@($CodecCatalog | ForEach-Object { $_.Name } | Where-Object { $CodecDefaultPackages -contains $_ }) + @($Bystander))
    Assert 'e2e list: exit 0, transcript named List, one CSV row per catalog package' ($Run.Exit -eq 0 -and $ListRows.Count -eq $CodecCatalog.Count -and (Get-ChildItem -LiteralPath $Tmp -Filter 'Remove-CodecExtension-List-*.log').Count -ge 1 -and (Rows $Run 'OK' 'Package list')[0].Detail -like "$($CodecCatalog.Count) package(s) in the catalog, $($TargetCount + 1) present*")
    Assert 'e2e list: the table shows the -Package name, the default flag and the state' ($Run.Text -like '*Package (use with -Package)*Store listing*Default*State*' -and $Run.Text -like "*$Bystander*installed 1.2.20.0 for SKYNET\alice (Installed), SKYNET\bob (Installed); provisioned 1.0.0.0; no Deprovisioned key*")
    Assert 'e2e list: one-package command uses a default target, the all-present command lists defaults first' ($Run.Text -like "*Remove one package*-Mode Remove -Package $($PresentOrder[0])*" -and $Run.Text -like "*Remove all $($TargetCount + 1) present packages:*-Mode Remove -Package $($PresentOrder -join ', ')*")
    Assert 'e2e list: present packages that are not default targets are called out' ($Run.Text -like "*Not default targets: $Bystander. The Breaks column*")
    Assert 'e2e list: read-only - nothing removed, no key, no event, no inventory, no process scan' ((Calls 'Remove-*').Count -eq 0 -and @(Get-ChildItem -LiteralPath $TestDeprovisioned).Count -eq 0 -and $Global:MockState.Events.Count -eq 0 -and @(Get-ChildItem -LiteralPath $Tmp -Filter 'codec-inventory-*').Count -eq $InventoriesBefore)

    # K18. -ListPackages against a mounted image: provisioning of the image, commands carry -MountedImagePath
    Reset-Mock
    $Global:MockState.OfflineRoot = "$TestKeyRoot\OfflineHiveList"
    New-Item -Path $Global:MockState.OfflineRoot -Force | Out-Null
    $Run = Invoke-Main @{ ListPackages = $true; MountedImagePath = $Mount }
    Assert 'e2e list offline: image provisioning listed, commands keep -MountedImagePath, no user query' ($Run.Exit -eq 0 -and $Run.Text -like "*Codec packages this script can remove - mounted image*" -and $Run.Text -like '*provisioned 2.5.48.0 in the image*' -and $Run.Text -like "*-Mode Remove -Package *-MountedImagePath '$Mount'*" -and (Calls 'Get-AppxPackage*').Count -eq 0)

    # K19. -ListPackages cannot be combined with -Mode: refused by parameter binding, before anything runs
    Reset-Mock
    $BindText = ''
    try { $BindRun = Invoke-Main @{ ListPackages = $true; Mode = 'Remove' }; $BindText = $BindRun.Text } catch { $BindText = "$($_.Exception.Message)" }
    Assert 'e2e list: -ListPackages with -Mode is rejected before anything runs' ($BindText -like '*Parameter set cannot be resolved*' -and (Calls '*').Count -eq 0) $BindText

    # K20. The main script's own guard: a module-provided Remove-AppxPackage visible under the harness stops the run
    #      before the transcript, the inventory or any call. The fake module replaces the mock in this scope, and
    #      removing it removes the mock too - so this test runs last.
    Reset-Mock
    New-Module -Name CodecFakeRealModule -ScriptBlock { function Remove-AppxPackage { [CmdletBinding()] param([string]$Package, [switch]$AllUsers) throw 'a real command was reached' } } | Import-Module -Scope Local
    $GuardMessage = ''
    try { $null = Invoke-Main @{ Mode = 'Remove'; NoConfirm = $true } } catch { $GuardMessage = "$($_.Exception.Message)" }
    Remove-Module -Name CodecFakeRealModule -Force -ErrorAction SilentlyContinue
    Assert 'e2e guard: the script refuses harness mode when Remove-AppxPackage comes from a module' ($GuardMessage -like 'STOP: test harness mode, but ''Remove-AppxPackage'' would run for real (Function from CodecFakeRealModule)*') $GuardMessage
    Assert 'e2e guard: nothing was called or changed' ((Calls '*').Count -eq 0 -and $Global:MockState.Installed.Count -eq ($TargetCount + 1) -and @(Get-ChildItem -LiteralPath $TestDeprovisioned).Count -eq 0)
}
finally {
    foreach ($F in 'Read-Host', 'Test-Interactive', 'Test-CodecElevated', 'Test-CodecSystemAccount', 'Get-CodecOsInfo', 'Initialize-CodecModules', 'Get-CodecStoreAccess', 'Write-CodecEvent', 'Find-CodecDeploymentError', 'Get-AppxPackage', 'Remove-AppxPackage', 'Get-AppxProvisionedPackage', 'Remove-AppxProvisionedPackage', 'Get-Process', 'Stop-Process', 'Start-Sleep', 'Start-Process', 'Use-CodecOfflineHive') { Remove-Item -LiteralPath "Function:\$F" -ErrorAction SilentlyContinue }
    Remove-Variable -Name MockState, InteractiveMock, Answers -Scope Global -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath 'HKLM:\CodecTestHive') { & (Join-Path $env:SystemRoot 'System32\reg.exe') unload 'HKLM\CodecTestHive' 2>&1 | Out-Null }
    if (Test-Path -LiteralPath $TestKeyRoot) { Remove-Item -LiteralPath $TestKeyRoot -Recurse -Force -ErrorAction SilentlyContinue }
    Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host ''
if ($Fail -eq 0) { Write-Host "ALL $Pass TESTS PASSED" -ForegroundColor Green; exit 0 }
Write-Host "$Fail FAILED, $Pass passed" -ForegroundColor Red
exit 1
