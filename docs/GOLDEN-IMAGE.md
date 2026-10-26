# Golden image runbook: shipping Windows 11 without the codec packages

Three ways to get an image, or a deployed fleet, without WebP Image Extension, HEVC Video Extensions, Raw Image
Extension and HEIF Image Extensions. All of them use `scripts\Remove-CodecExtension.ps1`; the README explains what it
does and why.

## A. Reference computer in audit mode (recommended)

Nothing holds the package files in audit mode (no browser, no Store session), so the removal is clean.

1. Boot the reference VM into audit mode (Ctrl+Shift+F3 at the OOBE region screen) or sign in with the local
   administrator you build images with.
2. Copy this folder to the VM, for example `C:\Build\WIN11-CODEC-REMOVAL`.
3. In an elevated Windows PowerShell 5.1 or PowerShell 7 console:

   ```powershell
   Set-Location C:\Build\WIN11-CODEC-REMOVAL\scripts
   .\Remove-CodecExtension.ps1                        # Check: exit code 1 while any package is present
   .\Remove-CodecExtension.ps1 -Mode Remove -NoConfirm
   .\Remove-CodecExtension.ps1                        # Check again: exit code 0 = clean
   ```

4. Keep `Logs\` and `Outputs\` as build evidence (copy them off the VM), then delete the folder from the VM if you do
   not want it in the image.
5. Run `sysprep /generalize /oobe /shutdown` and capture. The script removes the packages for every user AND removes
   the provisioning; both are required, otherwise sysprep fails with "Package ... was installed for a user, but not
   provisioned for all users" (Microsoft KB: Sysprep fails after you remove or update Microsoft Store apps).

## B. Offline servicing of install.wim or a VHDX

```powershell
Get-WindowsImage -ImagePath D:\Images\install.wim                  # find the index (Enterprise is often 3)
New-Item -Path C:\Mount -ItemType Directory -Force | Out-Null
Mount-WindowsImage -ImagePath D:\Images\install.wim -Index 3 -Path C:\Mount
.\Remove-CodecExtension.ps1 -ListPackages -MountedImagePath C:\Mount   # every codec package the image provisions
.\Remove-CodecExtension.ps1 -Mode Check  -MountedImagePath C:\Mount
.\Remove-CodecExtension.ps1 -Mode Remove -MountedImagePath C:\Mount -NoConfirm
Dismount-WindowsImage -Path C:\Mount -Save
```

- The script removes the provisioning with DISM (`Remove-AppxProvisionedPackage -Path`) and writes the Deprovisioned
  keys into the image's `SOFTWARE` hive (loaded with `reg.exe load`, unloaded afterwards, five tries with a garbage
  collection in between so no handle keeps it open).
- The running operating system and its system drive are refused as `-MountedImagePath`.
- An image captured from a machine that already had user profiles keeps those users' registrations; offline servicing
  cannot touch them. Use A for that image.
- Needs an elevated session. PowerShell 7 loads DISM through the Windows PowerShell compatibility layer by itself.

## C. Computers that are already deployed

The script is built for unattended runs: `-NoConfirm`, exit code 1 on any failure, transcript + CSV + inventory JSON,
Application events from source `CodecExtensionRemoval`, one instance at a time (mutex).

Install command (System context, 64-bit host):

```text
%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File scripts\Remove-CodecExtension.ps1 -Mode Remove -NoConfirm -LogPath %ProgramData%\CodecRemoval\Logs -OutputPath %ProgramData%\CodecRemoval\Outputs
```

Detection (exit code 0 = compliant, 1 = a package is still present):

```text
... -File scripts\Remove-CodecExtension.ps1 -Mode Check -LogPath %ProgramData%\CodecRemoval\Logs -OutputPath %ProgramData%\CodecRemoval\Outputs
```

- **Intune**: Win32 app (package the folder with the Content Prep Tool), install command above, detection by a custom
  script that runs the Check command and exits with its exit code, or a Platform script. Run as System.
- **Configuration Manager**: a Package/Program or a Configuration Item with the same two commands; "Run with
  administrative rights", "Whether or not a user is logged on".
- **Group Policy startup script**: the install command with `-NoConfirm`. Startup scripts run before anyone signs in,
  so nothing holds the files and `-StopBlockingProcesses` is not needed.
- **Logon-time or maintenance-window runs on a user's computer**: add `-StopBlockingProcesses` if the HEVC package
  must go while Edge or WebView2 apps are open; it closes them (Explorer is restarted). Announce it.
- **Monitoring**: Application log, source `CodecExtensionRemoval`: 1001 per package removed and verified, 1002
  nothing to do, 2001 package in use, 3000 run stopped, 3001 a removal failed. A 3001 with `0x80070005` names the
  AppX activity ID; running the command again finished the package when this was seen (see E).
- **What else is on a computer**: `-ListPackages` lists every codec package the script can handle, its state, and
  the exact names to pass to `-Package`, and writes the list as CSV next to the inventory files.

`psexec -s` or any other way to run as SYSTEM is not required for the removal; an elevated administrator has every
right it needs, and SYSTEM does not release a DLL another process holds.

## D. Keeping them gone

- The Deprovisioned registry key written by the script (and by Windows itself when it deprovisions) is what stops a
  feature update from provisioning the package again (Windows 10 1803 and later).
- Users can reinstall a removed package from the Microsoft Store unless `Turn off the Store application` is Enabled
  (Computer Configuration > Administrative Templates > Windows Components > Store). That policy blocks the Store app
  only; the other Store packages still auto-update. A packaged-app rule in AppLocker or App Control for Business that
  denies the package family names is the hard block:
  `Microsoft.WebpImageExtension_8wekyb3d8bbwe`, `Microsoft.HEVCVideoExtension_8wekyb3d8bbwe`,
  `Microsoft.HEVCVideoExtensions_8wekyb3d8bbwe` (the paid listing), `Microsoft.RawImageExtension_8wekyb3d8bbwe`,
  `Microsoft.HEIFImageExtension_8wekyb3d8bbwe`.
- `-Mode Check` is read-only, cheap and exits 1 on drift; schedule it or use it as the compliance detection.
- HEIF Image Extensions is a default target: it decodes nothing useful once HEVC is gone, and it is one more
  Store-updated parser of untrusted files. To keep it, pass
  `-Package Microsoft.WebpImageExtension, Microsoft.HEVCVideoExtension, Microsoft.RawImageExtension`.

## E. What a real removal looked like (2026-10-26, Windows 11 Enterprise build 28000, PowerShell 7)

- AppX deployment log (`Microsoft-Windows-AppXDeploymentServer/Operational`): event 603 "Started deployment Remove
  operation ... Options RemoveForAllUsers" for each of the three packages, event 400 "Deployment
  DeprovisionPackageOperation ... finished successfully", event 472 "Moving package folder ... to
  WindowsApps\Deleted". The whole thing took three seconds.
- The HEVC removal succeeded although Microsoft Edge and three WebView2 hosts had `hevcdecoder_store.dll` loaded: on
  this build the deployment engine renames the package folder into `WindowsApps\Deleted` and finishes; the DLL stays
  mapped in those processes until they exit. So "in use" did not block the removal here. On builds where it does
  (HRESULT 0x80073D02), the script lists the holders in `-Mode Check` and `-StopBlockingProcesses` closes them.
- Windows created the three Deprovisioned keys itself during the deprovisioning; the script's own key step then found
  them "already present".
- Afterwards `-Mode Check` reported every package "not installed, not provisioned, Deprovisioned key present" and a
  second `-Mode Remove` reported "Already current" without prompting. No reboot was needed.
- HEIF on 2026-10-27, run interactively by the signed-in domain administrator: Windows removed the package for the
  local account, then returned access denied (0x80070005, "Failure in the OptionalDependenciesHandled state
  handler") for the signed-in account in the same request; the script's own deprovisioning and key step succeeded.
  The same command limited to HEIF finished it a few minutes later. An unattended run that hits this exits 1, and
  the next run is expected to complete the package the same way; that was seen interactively, not yet in a
  System-context deployment.
