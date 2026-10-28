<#
.SYNOPSIS
    Shared functions for the -RunAsSystem path of Remove-CodecExtension.ps1 and for the "who holds the package
    files" scan: PsExec verification against pinned SHA256 hashes, the child run's command line, the one-shot
    scheduled task, the Restart Manager query, the AppX deployment log export and the child-run result reader.
    Dot-source it after Codec-Common.ps1; it changes nothing by itself.

.DESCRIPTION
    Functions:
      Test-CodecLocalPath            is a folder on a local drive (a SYSTEM session has no access to this session's
                                     mapped drives or network credentials)
      Get-CodecPackageFile           every file of a package folder, for the Restart Manager scan
      Get-CodecFileUser              processes that hold any of the given files open or mapped (Restart Manager API,
                                     the same answer Windows Installer gets when it asks "which apps are using this")
      Test-CodecPsExec               is PsExec present, byte-for-byte the pinned copy (SHA256), Microsoft-signed
      ConvertTo-CodecArgumentString  one command line from an argument array (CreateProcess quoting rules)
      Get-CodecSystemCommand         the child run's powershell.exe command: plain text and the -EncodedCommand form
      New-CodecTaskXml               the XML of the one-shot scheduled task that runs the child as SYSTEM
      Invoke-CodecSystemRun          starts the child through PsExec or the task, waits, returns exit code + output
      Get-CodecChildResult           the child run's CSV rows, transcript and step log, found by its run tag
      Export-CodecAppxEvent          Windows' own AppX deployment events since a point in time, as CSV

    Why -EncodedCommand for the child: powershell.exe -File passes every argument as one literal string, so a
    package list ("A,B") never reaches a [string[]] parameter with a ValidateSet; a base64 command has no quoting
    problem through PsExec or a task definition either. The plain text is logged next to it.

    Why PsExec writes nothing useful to the parent console: PsExec relays only part of a child's console output
    when its own output is redirected. The parent therefore reads the child's own transcript, CSV and step log.

.NOTES
    Windows PowerShell 5.1 and PowerShell 7. ASCII-only source.
    PsExec is Sysinternals PsTools 2.54 / PsExec 2.43, https://download.sysinternals.com/files/PSTools.zip,
    downloaded 2026-10-28; license in tools\Sysinternals-EULA.txt, hashes in tools\THIRD-PARTY-NOTICES.md.

    Generative AI was used in the creation and validation of this code; the result was reviewed and tested by a
    person (tests\Test-CodecRemoval.ps1 in both editions, plus live runs).
#>

$CodecPsExecVersion = '2.43'
$CodecPsExecHash = @{
    'PsExec64.exe' = 'EDFAE1A69522F87B12C6DAC3225D930E4848832E3C551EE1E7D31736BF4525EF'
    'PsExec.exe'   = '078163D5C16F64CAA5A14784323FD51451B8C831C73396B967B4E35E6879937B'
}
$CodecPsExecSigner = 'CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US'
$CodecSystemTaskPrefix = 'Remove-CodecExtension-System-'
$CodecRestartManagerSource = @'
using System;
using System.Runtime.InteropServices;
public static class CodecRestartManager {
    [StructLayout(LayoutKind.Sequential)]
    public struct RM_UNIQUE_PROCESS { public int dwProcessId; public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct RM_PROCESS_INFO {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType; public uint AppStatus; public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] public static extern int RmStartSession(out uint pSessionHandle, int dwSessionFlags, string strSessionKey);
    [DllImport("rstrtmgr.dll")] public static extern int RmEndSession(uint pSessionHandle);
    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)] public static extern int RmRegisterResources(uint pSessionHandle, uint nFiles, string[] rgsFilenames, uint nApplications, [In] RM_UNIQUE_PROCESS[] rgApplications, uint nServices, string[] rgsServiceNames);
    [DllImport("rstrtmgr.dll")] public static extern int RmGetList(uint dwSessionHandle, out uint pnProcInfoNeeded, ref uint pnProcInfo, [In, Out] RM_PROCESS_INFO[] rgAffectedApps, ref uint lpdwRebootReasons);
}
'@

function Test-CodecLocalPath {
    <#
    .SYNOPSIS
        True when the path is on a local drive: not a UNC path and not a network drive. A process started as SYSTEM
        sees none of this session's mapped drives and has no credentials for a share, so the script folder and the
        log folders of a -RunAsSystem run must be local.
    .PARAMETER Path
        Folder or file path.
    #>
    param([Parameter(Mandatory)][string]$Path)
    $Full = "$Path"
    try { $Full = [IO.Path]::GetFullPath("$Path") } catch { return $false }
    if ($Full.StartsWith('\\')) { return $false }
    $RootName = ''
    try { $RootName = [IO.Path]::GetPathRoot($Full) } catch { return $false }
    if (-not $RootName) { return $false }
    try { return ((New-Object IO.DriveInfo($RootName)).DriveType -ne [IO.DriveType]::Network) } catch { return $true }
}

function Get-CodecPackageFile {
    <#
    .SYNOPSIS
        The files of a package folder (recursive, at most -Limit), for Get-CodecFileUser. An unreadable or missing
        folder gives an empty array; the caller reports that.
    .PARAMETER InstallLocation
        (Get-AppxPackage ...).InstallLocation
    #>
    param([Parameter(Mandatory)][string]$InstallLocation, [int]$Limit = 2000)
    if (-not "$InstallLocation".Trim()) { return @() }
    if (-not (Test-Path -LiteralPath $InstallLocation -PathType Container)) { return @() }
    try { return @(Get-ChildItem -LiteralPath $InstallLocation -Recurse -File -ErrorAction Stop | Select-Object -First $Limit | ForEach-Object { $_.FullName }) }
    catch { return @() }
}

function Get-CodecFileUser {
    <#
    .SYNOPSIS
        The processes that hold any of the given files - open handles and mapped images alike - as Windows' Restart
        Manager reports them. This finds holders the module scan cannot see (a process whose modules cannot be read,
        a file handle without a loaded module, a service).
    .DESCRIPTION
        RmStartSession, RmRegisterResources with the file list, RmGetList (ERROR_MORE_DATA is answered with a
        buffer of the size it asked for), RmEndSession. Takes a few seconds. Throws when the API fails; the caller
        turns that into a warning. Paths that do not exist are skipped.
    .PARAMETER Path
        Full file paths (Get-CodecPackageFile).
    .OUTPUTS
        PSCustomObject per process: ProcessName, Id, AppName, ServiceName, Type (application, service, explorer,
        console, critical, unknown), SessionId. Wrap the call in @().
    #>
    param([string[]]$Path = @())
    $Files = @($Path | Where-Object { "$_".Trim() -and (Test-Path -LiteralPath "$_" -PathType Leaf) } | ForEach-Object { "$_" } | Select-Object -Unique)
    if ($Files.Count -eq 0) { return @() }
    if ($null -eq ('CodecRestartManager' -as [type])) { Add-Type -TypeDefinition $CodecRestartManagerSource -ErrorAction Stop }
    $Handle = 0
    $Result = [CodecRestartManager]::RmStartSession([ref]$Handle, 0, [guid]::NewGuid().ToString())
    if ($Result -ne 0) { throw "RmStartSession failed with Win32 error $Result." }
    $Found = New-Object System.Collections.Generic.List[object]
    try {
        $Result = [CodecRestartManager]::RmRegisterResources($Handle, [uint32]$Files.Count, [string[]]$Files, [uint32]0, $null, [uint32]0, $null)
        if ($Result -ne 0) { throw "RmRegisterResources failed with Win32 error $Result." }
        $Needed = 0; $Count = 0; $Reasons = 0
        $Info = $null
        $Result = [CodecRestartManager]::RmGetList($Handle, [ref]$Needed, [ref]$Count, $null, [ref]$Reasons)
        for ($Try = 0; $Try -lt 5 -and $Result -eq 234; $Try++) {
            $Info = New-Object 'CodecRestartManager+RM_PROCESS_INFO[]' $Needed
            $Count = $Needed
            $Result = [CodecRestartManager]::RmGetList($Handle, [ref]$Needed, [ref]$Count, $Info, [ref]$Reasons)
        }
        if ($Result -ne 0) { throw "RmGetList failed with Win32 error $Result." }
        for ($I = 0; $I -lt $Count; $I++) {
            $P = $Info[$I]
            $ProcessId = [int]$P.Process.dwProcessId
            $Name = ''
            try { $Name = "$((Get-Process -Id $ProcessId -ErrorAction Stop).ProcessName)" } catch { $Name = '' }
            if (-not $Name) { $Name = "$($P.strAppName)" }
            $Type = 'unknown'
            switch ([int]$P.ApplicationType) { 1 { $Type = 'application' } 2 { $Type = 'application' } 3 { $Type = 'service' } 4 { $Type = 'explorer' } 5 { $Type = 'console' } 1000 { $Type = 'critical' } }
            $Found.Add([pscustomobject]@{ ProcessName = $Name; Id = $ProcessId; AppName = "$($P.strAppName)"; ServiceName = "$($P.strServiceShortName)"; Type = $Type; SessionId = [int]$P.TSSessionId })
        }
    }
    finally { [void][CodecRestartManager]::RmEndSession($Handle) }
    return @($Found | Sort-Object -Property Id -Unique)
}

function Test-CodecPsExec {
    <#
    .SYNOPSIS
        Checks a PsExec file before it is run: present, SHA256 equal to the pinned hash of the verified copy
        ($CodecPsExecHash, by file name), and the Authenticode signature (reported; the hash is the decision).
    .PARAMETER Path
        Full path of PsExec64.exe or PsExec.exe.
    .OUTPUTS
        PSCustomObject: Path, Name, Present, Version, Hash, Expected, HashOk, SignatureStatus, Signer, SignatureOk,
        Ok (present and hash matches), Reason (why not Ok, or a note about the signature)
    #>
    param([Parameter(Mandatory)][string]$Path)
    $Full = "$Path"
    try { $Full = [IO.Path]::GetFullPath("$Path") } catch { }
    $Name = Split-Path -Leaf $Full
    $Out = [pscustomobject]@{ Path = $Full; Name = $Name; Present = $false; Version = ''; Hash = ''; Expected = ''; HashOk = $false; SignatureStatus = ''; Signer = ''; SignatureOk = $false; Ok = $false; Reason = '' }
    if ($CodecPsExecHash.ContainsKey($Name)) { $Out.Expected = $CodecPsExecHash[$Name] }
    if (-not (Test-Path -LiteralPath $Full -PathType Leaf)) { $Out.Reason = "PsExec not found at '$Full'"; return $Out }
    $Out.Present = $true
    try { $Out.Version = "$((Get-Item -LiteralPath $Full).VersionInfo.FileVersion)".Trim() } catch { }
    if (-not $Out.Expected) { $Out.Reason = "no pinned SHA256 for a file named '$Name' (expected $(@($CodecPsExecHash.Keys | Sort-Object) -join ' or '))"; return $Out }
    $Out.Hash = (Get-FileHash -LiteralPath $Full -Algorithm SHA256).Hash.ToUpperInvariant()
    $Out.HashOk = ($Out.Hash -eq $Out.Expected)
    try {
        $Sig = Get-AuthenticodeSignature -LiteralPath $Full
        $Out.SignatureStatus = "$($Sig.Status)"
        if ($null -ne $Sig.SignerCertificate) { $Out.Signer = "$($Sig.SignerCertificate.Subject)" }
        $Out.SignatureOk = ($Out.SignatureStatus -eq 'Valid' -and $Out.Signer -eq $CodecPsExecSigner)
    }
    catch { $Out.SignatureStatus = "not checked ($($_.Exception.Message))" }
    if (-not $Out.HashOk) { $Out.Reason = "the SHA256 of '$Full' is $($Out.Hash), not the pinned $($Out.Expected) of the verified $Name $CodecPsExecVersion - this is not the copy that was checked"; return $Out }
    $Out.Ok = $true
    if (-not $Out.SignatureOk) { $Out.Reason = "SHA256 matches the pinned value; Authenticode reported '$($Out.SignatureStatus)' ($($Out.Signer))" }
    return $Out
}

function ConvertTo-CodecArgumentString {
    <#
    .SYNOPSIS
        Joins an argument array into one command line the way CreateProcess expects it: arguments with spaces or
        quotes are quoted, inner quotes and the backslashes before them are escaped. Start-Process -ArgumentList
        and a task's <Arguments> element need this form.
    .PARAMETER Argument
        Arguments, one per element.
    #>
    param([string[]]$Argument = @())
    $Parts = New-Object System.Collections.Generic.List[string]
    foreach ($A in $Argument) {
        $Text = "$A"
        if ($Text.Length -gt 0 -and $Text -notmatch '[\s"]') { $Parts.Add($Text); continue }
        $Sb = New-Object System.Text.StringBuilder
        [void]$Sb.Append('"')
        $Backslashes = 0
        foreach ($C in $Text.ToCharArray()) {
            if ($C -eq '\') { $Backslashes++; continue }
            if ($C -eq '"') { [void]$Sb.Append([char]'\', [int]($Backslashes * 2 + 1)); [void]$Sb.Append('"'); $Backslashes = 0; continue }
            if ($Backslashes -gt 0) { [void]$Sb.Append([char]'\', [int]$Backslashes); $Backslashes = 0 }
            [void]$Sb.Append($C)
        }
        if ($Backslashes -gt 0) { [void]$Sb.Append([char]'\', [int]($Backslashes * 2)) }
        [void]$Sb.Append('"')
        $Parts.Add($Sb.ToString())
    }
    return ($Parts.ToArray() -join ' ')
}

function Get-CodecSystemCommand {
    <#
    .SYNOPSIS
        The command that runs Remove-CodecExtension.ps1 again as the child of a -RunAsSystem run: Windows
        PowerShell 5.1 (always present, native Appx and Dism modules), -NonInteractive, -NoConfirm, the same
        packages, folders and switches, plus -RunTag so the parent can find the child's files.
    .OUTPUTS
        PSCustomObject: FilePath (powershell.exe), Script (the plain command, for the plan and the log),
        Argument (string[]: -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand <base64>)
    #>
    param(
        [Parameter(Mandatory)][string]$ScriptPath,
        [string[]]$Package = @(),
        [Parameter(Mandatory)][string]$LogPath,
        [Parameter(Mandatory)][string]$OutputPath,
        [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9\-]{0,39}$')][string]$RunTag,
        [switch]$StopBlockingProcesses,
        [string]$DeprovisionedKeyRoot = ''
    )
    $Quote = { param($S) "'" + ("$S" -replace "'", "''") + "'" }
    $Text = "& $(& $Quote $ScriptPath) -Mode Remove -NoConfirm -RunTag $(& $Quote $RunTag) -LogPath $(& $Quote $LogPath) -OutputPath $(& $Quote $OutputPath)"
    $Names = @($Package | Where-Object { "$_".Trim() })
    if ($Names.Count -gt 0) { $Text += ' -Package ' + (@($Names | ForEach-Object { & $Quote $_ }) -join ', ') }
    if ($StopBlockingProcesses) { $Text += ' -StopBlockingProcesses' }
    if ($DeprovisionedKeyRoot -and $DeprovisionedKeyRoot -ne $CodecDeprovisionedKeyRoot) { $Text += " -DeprovisionedKeyRoot $(& $Quote $DeprovisionedKeyRoot)" }
    $Text += '; exit $LASTEXITCODE'
    $Encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Text))
    return [pscustomobject]@{
        FilePath = (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe')
        Script = $Text
        Argument = @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $Encoded)
    }
}

function New-CodecTaskXml {
    <#
    .SYNOPSIS
        Task Scheduler XML for a one-shot task: runs as NT AUTHORITY\SYSTEM (S-1-5-18) with the highest privileges,
        no trigger (started on demand by the parent), one instance, stopped after -TimeLimitMinutes.
    .PARAMETER Command
        Executable (full path).
    .PARAMETER Argument
        The argument string (ConvertTo-CodecArgumentString).
    .PARAMETER WorkingDirectory
        Start-in folder.
    #>
    param([Parameter(Mandatory)][string]$Command, [string]$Argument = '', [Parameter(Mandatory)][string]$WorkingDirectory, [int]$TimeLimitMinutes = 60)
    $E = { param($S) [Security.SecurityElement]::Escape("$S") }
    return @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>One-shot task created by Remove-CodecExtension.ps1 -RunAsSystem; the parent run deletes it when the child finishes.</Description>
  </RegistrationInfo>
  <Principals>
    <Principal id="LocalSystem">
      <UserId>S-1-5-18</UserId>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>false</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT$([int]$TimeLimitMinutes)M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="LocalSystem">
    <Exec>
      <Command>$(& $E $Command)</Command>
      <Arguments>$(& $E $Argument)</Arguments>
      <WorkingDirectory>$(& $E $WorkingDirectory)</WorkingDirectory>
    </Exec>
  </Actions>
</Task>
"@
}

function Invoke-CodecSystemRun {
    <#
    .SYNOPSIS
        Runs a command as NT AUTHORITY\SYSTEM and waits for it: through PsExec (-s, session 0, output to temporary
        files) or through a one-shot scheduled task (registered, started, polled, deleted). -OnTick is called about
        every two seconds while waiting, so the caller can show the child's progress from the child's own log.
    .OUTPUTS
        PSCustomObject: Launcher, ExitCode (-1 when the child could not be started), Started, Ended, Seconds,
        LauncherOutput (PsExec's own messages or the task's last result), Error (launcher failure text)
    #>
    param(
        [Parameter(Mandatory)][ValidateSet('PsExec', 'ScheduledTask')][string]$Launcher,
        [string]$PsExecPath = '',
        [Parameter(Mandatory)][string]$FilePath,
        [string[]]$ArgumentList = @(),
        [Parameter(Mandatory)][string]$WorkingDirectory,
        [string]$TaskName = '',
        [scriptblock]$OnTick = $null,
        [int]$TimeoutMinutes = 60
    )
    $Started = Get-Date
    $Deadline = $Started.AddMinutes($TimeoutMinutes)
    $ExitCode = -1; $Output = ''; $ErrorText = ''
    try {
        if ($Launcher -eq 'PsExec') {
            if (-not (Test-Path -LiteralPath $PsExecPath -PathType Leaf)) { throw "PsExec not found at '$PsExecPath'." }
            $Tmp = Join-Path ([IO.Path]::GetTempPath()) ('codec-psexec-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
            New-Item -Path $Tmp -ItemType Directory -Force | Out-Null
            $OutFile = Join-Path $Tmp 'stdout.txt'; $ErrFile = Join-Path $Tmp 'stderr.txt'
            $Line = ConvertTo-CodecArgumentString -Argument (@('-accepteula', '-nobanner', '-s', '-w', $WorkingDirectory, $FilePath) + @($ArgumentList))
            $Process = Start-Process -FilePath $PsExecPath -ArgumentList $Line -WorkingDirectory $WorkingDirectory -NoNewWindow -PassThru -RedirectStandardOutput $OutFile -RedirectStandardError $ErrFile
            while (-not $Process.WaitForExit(2000)) {
                if ($null -ne $OnTick) { & $OnTick }
                if ((Get-Date) -gt $Deadline) { $ErrorText = "PsExec did not return within $TimeoutMinutes minutes; it was stopped"; try { $Process.Kill() } catch { }; break }
            }
            $Process.WaitForExit()
            $ExitCode = [int]$Process.ExitCode
            $Lines = @(@(Get-Content -LiteralPath $ErrFile -ErrorAction SilentlyContinue) + @(Get-Content -LiteralPath $OutFile -ErrorAction SilentlyContinue) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            $Output = ($Lines -join ' | ')
            Remove-Item -LiteralPath $Tmp -Recurse -Force -ErrorAction SilentlyContinue
        }
        else {
            if (-not $TaskName) { throw 'A task name is required for the ScheduledTask launcher.' }
            Import-Module -Name ScheduledTasks -ErrorAction Stop -WarningAction SilentlyContinue
            $Xml = New-CodecTaskXml -Command $FilePath -Argument (ConvertTo-CodecArgumentString -Argument $ArgumentList) -WorkingDirectory $WorkingDirectory -TimeLimitMinutes $TimeoutMinutes
            Register-ScheduledTask -TaskName $TaskName -Xml $Xml -Force -ErrorAction Stop | Out-Null
            try {
                Start-ScheduledTask -TaskName $TaskName -ErrorAction Stop
                $SeenRunning = $false
                while ($true) {
                    Start-Sleep -Seconds 2
                    $State = "$((Get-ScheduledTask -TaskName $TaskName -ErrorAction Stop).State)"
                    if ($State -eq 'Running') { $SeenRunning = $true }
                    elseif ($SeenRunning -or (Get-Date) -gt $Started.AddSeconds(30)) { break }
                    if ($null -ne $OnTick) { & $OnTick }
                    if ((Get-Date) -gt $Deadline) { $ErrorText = "the task did not finish within $TimeoutMinutes minutes; it was stopped"; Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue; break }
                }
                $Info = Get-ScheduledTaskInfo -TaskName $TaskName -ErrorAction Stop
                $Raw = [int64]$Info.LastTaskResult
                $ExitCode = [int]$Raw
                $Output = "task $TaskName last run $($Info.LastRunTime), last result $Raw (0x$($Raw.ToString('X')))$(if (-not $SeenRunning) { ' - the task was never seen running' })"
            }
            finally { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue }
        }
    }
    catch { $ErrorText = "$($_.Exception.Message)" }
    $Ended = Get-Date
    return [pscustomobject]@{ Launcher = $Launcher; ExitCode = $ExitCode; Started = $Started; Ended = $Ended; Seconds = [int]($Ended - $Started).TotalSeconds; LauncherOutput = $Output; Error = $ErrorText }
}

function Get-CodecChildResult {
    <#
    .SYNOPSIS
        The files a child run left in -LogPath, found by its run tag: the CSV rows (When, Status, Check, Detail),
        the transcript and the step log. Found = $false when the child never wrote its CSV.
    #>
    param([Parameter(Mandatory)][string]$LogPath, [Parameter(Mandatory)][ValidatePattern('^[A-Za-z0-9][A-Za-z0-9\-]{0,39}$')][string]$RunTag)
    $Csv = @(Get-ChildItem -LiteralPath $LogPath -Filter "Remove-CodecExtension-*-$RunTag.csv" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime, Name | Select-Object -Last 1)
    if ($Csv.Count -eq 0) { return [pscustomobject]@{ Found = $false; Csv = ''; Transcript = ''; StepLog = ''; Rows = @() } }
    $Base = $Csv[0].FullName.Substring(0, $Csv[0].FullName.Length - 4)
    $Rows = @(Import-Csv -LiteralPath $Csv[0].FullName -Encoding UTF8)
    return [pscustomobject]@{ Found = $true; Csv = $Csv[0].FullName; Transcript = "$Base.log"; StepLog = "$Base.steps.log"; Rows = $Rows }
}

function Export-CodecAppxEvent {
    <#
    .SYNOPSIS
        Writes Windows' own AppX deployment events (Microsoft-Windows-AppXDeploymentServer/Operational and
        Microsoft-Windows-AppXDeployment/Operational) from -Since on to a CSV: time, log, ID, level, activity ID,
        message. Returns the number of events. Read-only; a log that cannot be read is skipped.
    #>
    param([Parameter(Mandatory)][datetime]$Since, [Parameter(Mandatory)][string]$Path)
    $Rows = New-Object System.Collections.Generic.List[object]
    foreach ($Log in 'Microsoft-Windows-AppXDeploymentServer/Operational', 'Microsoft-Windows-AppXDeployment/Operational') {
        $Events = @()
        try { $Events = @(Get-WinEvent -FilterHashtable @{ LogName = $Log; StartTime = $Since } -ErrorAction Stop) } catch { continue }
        foreach ($E in $Events) {
            if ($null -eq $E) { continue }
            $Rows.Add([pscustomobject]@{ TimeCreated = $E.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'); Log = $Log; Id = [int]$E.Id; Level = "$($E.LevelDisplayName)"; ActivityId = "$($E.ActivityId)"; Message = ("$($E.Message)" -replace '\s+', ' ').Trim() })
        }
    }
    $Sorted = @($Rows | Sort-Object -Property TimeCreated)
    if ($Sorted.Count -eq 0) { [IO.File]::WriteAllText($Path, "No AppX deployment events since $($Since.ToString('yyyy-MM-dd HH:mm:ss')).`r`n", (New-Object Text.UTF8Encoding($false))) }
    else { $Sorted | Export-Csv -LiteralPath $Path -NoTypeInformation -Encoding UTF8 -WhatIf:$false }
    return $Sorted.Count
}
