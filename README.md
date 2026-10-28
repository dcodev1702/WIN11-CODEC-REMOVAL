# WIN11-CODEC-REMOVAL - remove the Microsoft Store codec packages from Windows 11

> [!NOTE]
> **`scripts\Remove-CodecExtension.ps1`** removes the Store-delivered codec packages that keep appearing in vulnerability scans - **WebP Image Extension**, **HEVC Video Extensions**, **Raw Image Extension** and **HEIF Image Extensions** by default - from a Windows 10/11 computer or from a **mounted golden image**: for **every user profile**, from the **provisioning list**, and with the **registry key that stops feature updates from bringing them back**. It names **every process that holds a package file** (loaded-module scan plus Windows' Restart Manager), tries the removal anyway, and when Windows refuses because the package is in use it can **close the holders and retry** (`-StopBlockingProcesses`) or **run the whole removal as `NT AUTHORITY\SYSTEM`** (`-RunAsSystem`, through PsExec pinned by hash or a one-shot scheduled task). It needs only the inbox Appx and Dism modules and an elevated session. Written for **PowerShell 7**; also runs in **Windows PowerShell 5.1**. **Read-only by default** (`-Mode Check`), asks **Y/N** before any change, supports **`-WhatIf`** and **`-NoConfirm`**, verifies the result from the system, and leaves a transcript, a **timestamped step log**, a CSV of PASS/WARN/FAIL rows, an inventory JSON (before and after), **Windows' own AppX deployment events** for the run, and Application events. **`-ListPackages`** lists every codec package it can handle, its state on the computer, and the exact name to pass to `-Package`. **`scripts\Restore-CodecExtension.ps1`** puts a package back on a computer that can reach the Store.

> [!IMPORTANT]
> **Verified live on 2026-10-28** on Windows 11 Enterprise 26H2 (build 26300): with two WebView2 hosts holding `hevcdecoder_store.dll`, `-Mode Remove -Package Microsoft.HEVCVideoExtension -RunAsSystem` started a child run as SYSTEM through `tools\PsExec64.exe` two seconds after the plan, the child named the same two holders, removed the package for every user on the first try, Windows deprovisioned it by itself, and the elevated session verified "not registered, not provisioned, Deprovisioned key present" 33 seconds after the start. The same with `-SystemLauncher ScheduledTask -StopBlockingProcesses` (no PsExec) finished in 18 seconds and deleted its task. Earlier live runs (2026-10-26/27, build 28000) are in [Appendix A](#appendix-a---live-runs). The removal path is also proven by **180 tests against mocked Appx/DISM/process/launcher commands** ([`tests/`](tests/Test-CodecRemoval.ps1)) in both editions, including a build that refuses while a file is held and the SYSTEM relaunch with the child run in-process. **The PsExec binaries are not in this repository** (it is public and the Sysinternals license forbids publishing them); `tools\Get-PsExec.ps1` fetches and verifies them on a connected computer before you carry the folder to the isolated network, and the scheduled-task launcher works without them.

---

## Contents

1. [What these packages are and where they come from](#1-what-these-packages-are-and-where-they-come-from)
2. [Why they are always "vulnerable"](#2-why-they-are-always-vulnerable)
3. [What stops working, and what does not](#3-what-stops-working-and-what-does-not)
4. [What is in this folder](#4-what-is-in-this-folder)
5. [Quick start](#5-quick-start)
6. [How the script works](#6-how-the-script-works)
7. ["The app is in use" - what the script does, and running as SYSTEM](#7-the-app-is-in-use---what-the-script-does-and-running-as-system)
8. [Golden image](#8-golden-image)
9. [Parameters](#9-parameters)
10. [Evidence - the logs of a run](#10-evidence---the-logs-of-a-run)
11. [Automation](#11-automation)
12. [Tests](#12-tests)
13. [Troubleshooting](#13-troubleshooting)
14. [References](#14-references)
- [Appendix A - Live runs](#appendix-a---live-runs)

The image-build runbook with exact commands is [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md).

---

## 1. What these packages are and where they come from

They are **Microsoft Store apps** (publisher ID `8wekyb3d8bbwe`) that **Windows setup provisions into the image**, so every new user profile gets them registered at first sign-in. Their files live in `C:\Program Files\WindowsApps\<PackageFullName>\` and plug into the **Windows Imaging Component** (image codecs) or **Media Foundation** (video codecs); that is how Photos, Paint, Explorer thumbnails, Media Player, Edge and every WebView2 app pick them up without knowing about them.

Microsoft moved these decoders out of the OS into Store packages so they could be **updated and licensed separately**. HEVC is patent-encumbered: the device maker pays for the *from Device Manufacturer* copy that ships preinstalled, retail users buy the other listing. The consequence for an enterprise: the packages are updated **only by the Microsoft Store** - never by Windows Update, WSUS or Configuration Manager - and they are **parsers for hostile file formats written in C/C++** (Google's libwebp, LibRaw, Microsoft's HEVC decoder).

| Package name | Store listing | Store ID | Decodes | Where it comes from |
|---|---|---|---|---|
| `Microsoft.WebpImageExtension` | WebP Image Extension | 9PG2DK419DRG | `.webp` images (WIC) | provisioned by Windows setup |
| `Microsoft.HEVCVideoExtension` | HEVC Video Extensions from Device Manufacturer | 9N4WGH0Z6VHQ | H.265/HEVC video; `.heic` photos through HEIF | provisioned by setup or the OEM |
| `Microsoft.RawImageExtension` | Raw Image Extension | 9NCTDW2W1BH8 | camera RAW (`.cr2`, `.nef`, `.arw`, `.dng` ...) (WIC) | provisioned by Windows setup |
| `Microsoft.HEIFImageExtension` | HEIF Image Extensions | 9PMMSR1CGPWG | `.heic`, `.heif` and `.avif` containers; the picture inside needs HEVC or AV1 (WIC) | provisioned by Windows setup |
| `Microsoft.HEVCVideoExtensions` | HEVC Video Extensions (paid) | 9NMZLZ57R3T7 | the same decoder | bought by a user |
| `Microsoft.AV1VideoExtension`, `Microsoft.VP9VideoExtensions`, `Microsoft.MPEG2VideoExtension`, `Microsoft.WebMediaExtensions` | AV1, VP9, MPEG-2, Web Media | see `scripts\Codec-Common.ps1` | other video/audio formats | provisioned by Windows setup |

The first four are the script's default targets. Every row is accepted by `-Package`; anything else is rejected by `ValidateSet`. Store IDs were checked on 2026-10-26 (apps.microsoft.com, Microsoft Learn, winget); the HEVC *from Device Manufacturer* listing is not searchable in winget or the Store, but the Store install API installs it by ID (that is what `Restore-CodecExtension.ps1` does).

## 2. Why they are always "vulnerable"

- **Update channel.** A Store package is updated by the Store's background updater. If *Turn off Automatic Download and Install of updates* is enabled, or a profile never had the Store check in, the package sits at an old version forever and the scanner flags it every cycle. Blocking the Store **app** (*Turn off the Store application*) does **not** block those updates; only that one policy does ([Microsoft Learn](https://learn.microsoft.com/windows/msix/group-policy-msix)).
- **Attack surface.** Each package is a decoder for an attacker-supplied file, reached by opening a file, by an Explorer thumbnail, or by a web page in a WebView2 host. Examples: **CVE-2023-4863** (libwebp heap overflow, exploited in the wild, September 2023), **CVE-2022-21926** and **CVE-2026-58599** (HEVC Video Extensions remote code execution), **CVE-2023-28292** (Raw Image Extension heap overflow). Your scanner has the current list.
- **Per-user state.** Even after an administrator removes a package for one account, the registration for every other profile stays, and the provisioning re-adds it for new profiles - which is why "I removed it and it is still reported" is so common.

Removing the packages ends all three problems. Keeping them means fixing the update channel instead (allow Store auto-updates, or deploy the packages as *Microsoft Store app* in Intune so they stay current).

## 3. What stops working, and what does not

**Stops working after removal**

- Opening `.webp` files in Photos, Paint, Snipping Tool; Explorer thumbnails for `.webp`. Drag the file into a browser instead, browsers have their own decoder.
- H.265/HEVC video in Photos, Media Player, Movies & TV, **Edge** and WebView2 apps (Edge decodes HEVC only through the Windows platform decoder, [Microsoft Learn](https://learn.microsoft.com/troubleshoot/microsoft-edge/development/video-playback-issues)); `.heic` photos from iPhones. No browser renders `.heic`; set iPhones to *Most Compatible* or convert on transfer.
- Camera RAW previews in Photos and Explorer. Photo editors bring their own RAW decoder.
- `.heif` and `.avif` pictures in Photos and Explorer thumbnails; HEIF Image Extensions is the container reader for them. Browsers render AVIF with their own decoder.

**Not affected**

- Web pages: Edge, Chrome and Firefox render WebP/AVIF with their own decoders.
- Teams and Zoom calls (their own codecs: H.264, VP8/VP9, AV1).
- JPEG, PNG, GIF, BMP, TIFF and H.264 MP4 are inbox Windows codecs, not Store packages.

## 4. What is in this folder

| Path | What it is |
|---|---|
| [`scripts/Remove-CodecExtension.ps1`](scripts/Remove-CodecExtension.ps1) | The script. Comment-based help: `Get-Help .\Remove-CodecExtension.ps1 -Full`. |
| [`scripts/Codec-Common.ps1`](scripts/Codec-Common.ps1) | Shared functions and the package catalog (names, Store IDs, origin, what breaks). Pure, dot-sourced by the script and the tests. |
| [`scripts/Codec-System.ps1`](scripts/Codec-System.ps1) | The `-RunAsSystem` helpers: PsExec verification against the pinned SHA256, the child command, the one-shot scheduled task, the Restart Manager query, the AppX log export, the child-result reader. |
| [`scripts/Confirm-Change.ps1`](scripts/Confirm-Change.ps1) | The confirmation gate: yellow summary, `Continue? [Y/N]`, `-NoConfirm`, never hangs in a non-interactive session. |
| [`scripts/Restore-CodecExtension.ps1`](scripts/Restore-CodecExtension.ps1) | The undo on a Store-connected computer: deletes the Deprovisioned key and installs the Store listing through the app-install API (Windows PowerShell 5.1). |
| [`tests/Test-CodecRemoval.ps1`](tests/Test-CodecRemoval.ps1) | 180 tests, no Pester needed, both editions; nothing on the computer is changed and nothing runs as SYSTEM. |
| [`tools/`](tools/) | `Get-PsExec.ps1` (downloads PsTools, checks the pinned hashes, copies PsExec here), `THIRD-PARTY-NOTICES.md` (version, hashes, signature, license notes), `SHA256SUMS.txt`, `Sysinternals-EULA.txt`. `PsExec64.exe` and `PsExec.exe` appear here after `Get-PsExec.ps1` and are git-ignored. |
| [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md) | Runbook: reference computer in audit mode, offline WIM/VHDX, Intune / ConfigMgr / GPO, `-RunAsSystem` from an administrator's session, keeping them gone, the live runs. |
| `Logs/`, `Outputs/` | Created on first run: transcripts, step logs, CSV, AppX events, inventory JSON, the `-ListPackages` CSV. Git-ignored. |

## 5. Quick start

Elevated PowerShell 7 or Windows PowerShell 5.1, in `scripts\` (from the folder root, type `.\scripts\Remove-CodecExtension.ps1` instead; the commands the script prints use the path you started it with):

```powershell
.\Remove-CodecExtension.ps1 -ListPackages                         # read-only: every codec package it can handle, its state, the name to pass to -Package
.\Remove-CodecExtension.ps1                                       # read-only: what is installed, for whom, provisioned, keyed, and which processes hold the files
.\Remove-CodecExtension.ps1 -Mode Remove -Package Microsoft.HEVCVideoExtension   # just the packages named
.\Remove-CodecExtension.ps1 -Mode Remove -WhatIf                  # the exact plan, nothing changed, nothing asked
.\Remove-CodecExtension.ps1 -Mode Remove                          # removes after Continue? [Y/N]; tried even while Edge holds a file
.\Remove-CodecExtension.ps1 -Mode Remove -StopBlockingProcesses   # if Windows refuses (in use), closes the holders and retries
.\Remove-CodecExtension.ps1 -Mode Remove -RunAsSystem             # the removal runs as NT AUTHORITY\SYSTEM (PsExec from tools\, else a one-shot task)
.\Remove-CodecExtension.ps1 -Mode Remove -RunAsSystem -SystemLauncher ScheduledTask -StopBlockingProcesses -NoConfirm   # unattended, no PsExec
.\Remove-CodecExtension.ps1 -Mode Remove -NoConfirm               # automation (image build, Intune, ConfigMgr, startup script)
.\Remove-CodecExtension.ps1 -Mode Remove -MountedImagePath C:\Mount -NoConfirm   # offline WIM/VHDX
powershell -File .\Restore-CodecExtension.ps1 -Package Microsoft.HEVCVideoExtension   # undo on a Store-connected computer
```

Before the first `-RunAsSystem` on the isolated network, run `.\tools\Get-PsExec.ps1` once on a connected computer so `tools\` holds the verified PsExec (or use `-SystemLauncher ScheduledTask`, which needs nothing).

Exit code 1 means: in Check mode a target is still present (use it as a compliance check); in Remove mode a removal failed or Windows refused it. The last lines of the output say why and print the command to run again: close the apps it names (or add `-StopBlockingProcesses` or `-RunAsSystem`) when Windows refused a package in use; just run it again after an access denied from the deployment service. The script only does what is still missing.

## 6. How the script works

1. **Pre-flight, nothing changed:** elevated session; Windows build 17134 or later (10 1803, where a deprovisioned package stays removed across feature updates); one instance at a time (global mutex); Appx and Dism modules - PowerShell 7 loads Dism through the Windows PowerShell compatibility layer because the native import answers "Class not registered"; each module is probed with a read-only call. The *Modules* row names the module that actually answered. A `-MountedImagePath` must hold a `SOFTWARE` hive and a kernel of build 17134+, and may not be the running OS. With `-RunAsSystem`: the folder and the log folders must be local, and PsExec (if it is to be used) must match the pinned SHA256.
2. **Inventory, read-only:** every target registered to any user (`Get-AppxPackage -AllUsers`, with the user list), every target in the provisioning list (`Get-AppxProvisionedPackage`), the Deprovisioned keys, and every running process that holds a package file - found two ways: the loaded-module scan (which file of which package, in which process) and Windows' Restart Manager over every file of the package folders (the API Windows Installer uses to ask "which applications are using these files"; it also sees open handles, services and processes whose modules cannot be read). A package whose publisher ID is not the Store's is flagged as sideloaded. **`-ListPackages` stops here** with the catalog, the state of each package, the CSV and the `-Mode Remove -Package` commands for the ones present.
3. **Plan.** Per package: remove for every user / deprovision / write key, or "nothing to do". `-Mode Check` stops here with FAIL rows for anything present, the holders named, and a WARN when users can reinstall from the Store (no Store policy).
4. **Confirm.** The plan in yellow - packages, versions, users, the processes that hold a file and what happens if Windows refuses, the SYSTEM launcher and the child command when `-RunAsSystem` is set, the effect, how to undo - then `Continue? [Y/N]`. `-NoConfirm` skips the prompt (the plan is still printed and transcribed), `-WhatIf` shows the plan only, and a non-interactive session without `-NoConfirm` stops before any change.
5. **Apply, per package:** `Remove-AppxPackage -AllUsers` is **tried first even when a process holds a file** (builds 28000 and 26300 move the folder to `WindowsApps\Deleted` and finish; the DLL stays mapped until the process exits). If Windows answers `0x80073D02` ERROR_PACKAGES_IN_USE, the holders are found again and: with `-StopBlockingProcesses` they are stopped and the removal retried (three tries in all; Explorer is started again; system, security and management processes are never killed, the package then stays), without it the package is FAIL "in use by ..." and the run continues. `0x80073CF1` "not found" counts as done. Then `Remove-AppxProvisionedPackage` (`-Online` or `-Path`); when Windows already deprovisioned the package during the all-users removal, the call answers `0x80070002` and the script re-reads the list and reports the step as done. Then the Deprovisioned key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\<PackageFamilyName>` (written into the image hive in offline mode). A failed call is reported with its HRESULT - taken from the exception when the message has none - and, when Windows logged it, with the failing step and the AppX activity ID for `Get-AppPackageLog`. **With `-RunAsSystem`** this whole step runs in a child as SYSTEM (section 7).
6. **Verify from the system:** the three facts are read again, not taken from variables; a package still registered, still provisioned or without its key is a FAIL. Inventory JSON before and after, Windows' AppX deployment events of the run, Application events, CSV, step log, transcript. No reboot is needed.

## 7. "The app is in use" - what the script does, and running as SYSTEM

**What the error means.** `Remove-AppxPackage` reports **0x80073D02 ERROR_PACKAGES_IN_USE** ("resources it modifies are currently in use") when, on a build that checks for it, a running process has a file from the package folder loaded. For the HEVC package that is normally **Microsoft Edge and every WebView2 host** (new Teams, new Outlook, Widgets, Copilot ...), which load `hevcdecoder_store.dll` when they enumerate Media Foundation decoders; for the image codecs it is Photos, Paint, a thumbnail COM surrogate (`dllhost`) or Explorer itself.

**What the script does about it, in order.**

1. **Names the holders before anything happens.** Two detectors: the loaded-module scan (process, PID, which DLL of which package) and the Restart Manager query over every file of the package folders (process, PID, application or service name; it also finds open handles and processes whose modules cannot be read). `-Mode Check` prints them; the step log records both counts.
2. **Tries the removal anyway.** On Windows 11 build 28000 (2026-10-26) and build 26300 (2026-10-28) the deployment service removed the HEVC package while Edge and WebView2 hosts still had the DLL mapped: it renames the package folder into `WindowsApps\Deleted` and finishes. Nothing is closed for nothing.
3. **If Windows refuses with 0x80073D02:** `-StopBlockingProcesses` stops the holders found at that moment (Explorer is started again afterwards; `svchost`, `lsass`, `csrss`, `MsMpEng`, `CcmExec`, PowerShell itself and the like are never killed - the row then says so and the package stays) and retries, three tries in all. Without the switch the package is reported FAIL "in use by ...", event 2001, and the rest of the run continues.
4. **`-RunAsSystem` runs the removal as `NT AUTHORITY\SYSTEM`.** The elevated session does the pre-flight, shows the plan (launcher and the exact child command) and asks Y/N; then it starts a child run in session 0 - Windows PowerShell 5.1 with the native Appx and Dism modules, `-NoConfirm`, the same packages, folders and switches, a run tag so the parent can find its files - through `tools\PsExec64.exe -s` or a one-shot scheduled task running as SYSTEM. While waiting it prints the child's step log live (`SYSTEM>` lines). When the child ends, the parent merges the child's result rows into its own table (prefixed `[SYSTEM]`), verifies from the system itself, restarts Explorer if the SYSTEM session had to stop it, exports Windows' AppX events of the whole window, and exits 1 if anything failed.
   - **Launcher** (`-SystemLauncher`): `Auto` (default) uses PsExec when it is in `tools\` and its SHA256 is the pinned one, otherwise the task, and falls back to the task when PsExec could not start the child (no `ADMIN$` share, an EDR that blocks `PSEXESVC` ...); `PsExec` insists and stops when the file is absent, altered or fails; `ScheduledTask` never touches PsExec.
   - **PsExec** is Sysinternals PsTools 2.54 / PsExec 2.43. Its SHA256 is pinned in `scripts\Codec-System.ps1` and the script refuses to run a copy that does not match. It is not in source control (public repository, Sysinternals license); `tools\Get-PsExec.ps1` downloads, verifies and copies it on a connected computer, and [`tools/THIRD-PARTY-NOTICES.md`](tools/THIRD-PARTY-NOTICES.md) has the hashes, the signature details and the license text. By using it you accept the Sysinternals license (the script passes `-accepteula`).
   - **What SYSTEM changes and what it does not.** An elevated administrator already has every right the removal needs, and SYSTEM does not unmap a DLL from another process. What changes is the session: no browser or WebView2 host of the signed-in user runs in session 0, and the deployment service answers the SYSTEM session's request from there. On build 26300 the elevated session and the SYSTEM session both succeeded with the DLL mapped; on a build that refuses, the SYSTEM child's row shows what Windows answered, and `-StopBlockingProcesses` in the child closes the holders. Both runs leave their logs, so `Logs\` shows which it was.
   - The script folder, `-LogPath` and `-OutputPath` must be on a local drive (a SYSTEM session has no mapped drives or share credentials); a UNC path or a network drive stops the run before anything changes.
5. **Before anyone signs in** nothing holds the files: a startup script, an image build in audit mode, or `-RunAsSystem -StopBlockingProcesses` in a maintenance window.

**Access denied (0x80070005) is a different error, and SYSTEM does not help with it either.** The script refuses to start unless the session is elevated, so this code comes from Windows' app deployment service, not from your rights. On build 28000, `Remove-AppxPackage -AllUsers` on a package that was still provisioned removed it for the other account and Windows deprovisioned it, but the service returned access denied for the signed-in account (Windows' log: *Failure in the OptionalDependenciesHandled state handler*). Nothing held the files. Running the same command again removed the last registration. The FAIL row shows the code, the failing step and the activity ID, and `Get-AppPackageLog -ActivityID <id>` prints Windows' full log of that operation.

## 8. Golden image

Two supported paths, both in [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md):

- **Reference computer in audit mode**, then `sysprep /generalize`: run `-Mode Remove -NoConfirm` on it. Removing for every user *and* deprovisioning is required, otherwise sysprep fails ([Microsoft KB](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps)); the script does both.
- **Offline `install.wim` / VHDX**: `Mount-WindowsImage`, then `-Mode Remove -MountedImagePath <mount> -NoConfirm`, then `Dismount-WindowsImage -Save`. The script deprovisions with DISM and writes the Deprovisioned keys into the image's `SOFTWARE` hive. A captured image that already contains user profiles keeps their registrations - use the audit-mode path for it.

After deployment, `-Mode Check` (exit code 1 = drift) is the compliance check, and `Turn off the Store application` or an AppLocker / App Control packaged-app rule keeps users from reinstalling.

## 9. Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-Mode Check\|Remove` | `Check` | Check is read-only and exits 1 while a target is present. Remove performs the removal. |
| `-Package <names>` | WebP, HEVC, Raw, HEIF | Which packages. Only the catalog names are accepted (see section 1). |
| `-ListPackages` | off | Read-only list of every catalog package with its state, the name to use with `-Package`, and the removal commands for the ones present; CSV in `-OutputPath`. Works with `-MountedImagePath`; cannot be combined with the Run parameters. |
| `-MountedImagePath <folder>` | empty = running OS | Offline servicing of a mounted image. The running OS is refused. |
| `-StopBlockingProcesses` | off | When Windows refuses a removal with `0x80073D02`, stop the holders and retry; Explorer is restarted. Never up front; never a system, security or management process. Without it a refused package is FAIL and skipped. |
| `-RunAsSystem` | off | `-Mode Remove`, running OS only. Run the removal in a child as `NT AUTHORITY\SYSTEM` and wait for it; the child's rows are merged, prefixed `[SYSTEM]`. Nothing is relaunched when the session already is SYSTEM. Folder and log folders must be local. |
| `-SystemLauncher Auto\|PsExec\|ScheduledTask` | `Auto` | How the child is started: PsExec when present and hash-verified, otherwise (or on a launch failure) a one-shot scheduled task; `PsExec` insists; `ScheduledTask` never uses PsExec. |
| `-PsExecPath <file>` | `tools\PsExec64.exe` | Another copy of PsExec64.exe or PsExec.exe; its SHA256 must still be a pinned one. |
| `-RunTag <text>` | empty | Letters, digits, hyphens; appended to this run's file names. The SYSTEM parent passes `system-<its timestamp>` to the child. |
| `-LogPath`, `-OutputPath` | `<folder>\Logs`, `<folder>\Outputs` | Transcript, step log, CSV, AppX events; inventory JSON. Point them at `%ProgramData%` when deploying from a read-only share (local paths only with `-RunAsSystem`). |
| `-NoConfirm` | off | No prompt; the plan is still printed and transcribed. Required for unattended runs. |
| `-WhatIf` | off | Plan only, nothing changed, nothing asked; with `-RunAsSystem` the launcher and child command are shown. |
| `-DeprovisionedKeyRoot` | the real key | Tests only. |

### Changing the default targets

Everything in this folder runs in Windows PowerShell 5.1 or PowerShell 7 alone: the script, the tests and the maintenance steps below. No other shell or tool is needed, apart from `git` if you keep the folder in a repository.

- **For one run**, pass `-Package` and change nothing; `-ListPackages` prints every accepted name. For example, to keep HEIF, run this in `scripts\`:

  ```powershell
  .\Remove-CodecExtension.ps1 -Mode Remove -Package Microsoft.WebpImageExtension, Microsoft.HEVCVideoExtension, Microsoft.RawImageExtension
  ```

- **For good**, edit the default list where it is defined, with any editor. There are three places, and they must be identical and in the same order (a test fails otherwise):
  - `$CodecDefaultPackages` in `scripts\Codec-Common.ps1`
  - the `-Package` default in the `param()` block of `scripts\Remove-CodecExtension.ps1`
  - the `-Package` default in `scripts\Restore-CodecExtension.ps1`

  A name must already be in the catalog (`$CodecCatalog`) and in the `-Package` `ValidateSet`; the tests check both. The tests take every count from the list, so they need no edit. The end-to-end tests model the in-use and retry cases on WebP, HEVC and Raw, so those three stay in the list (the tests stop with a message otherwise). Then, from the folder root, find the text that names the defaults, run the tests in both editions and review the change:

  ```powershell
  Select-String -Path .\scripts\*.ps1, .\README.md, .\docs\*.md -Pattern 'RawImageExtension|Raw Image Extension'
  pwsh       -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
  powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
  git diff --stat
  ```

  Keep the files ASCII-only; the tests check that too.

## 10. Evidence - the logs of a run

Every run leaves, in `-LogPath` (`Logs\` by default; `<tag>` only when `-RunTag` was given or for a SYSTEM child):

- `Remove-CodecExtension-<Check|Remove|List>-<timestamp>[-<tag>].log` - the transcript of everything printed.
- `Remove-CodecExtension-...-<timestamp>[-<tag>].steps.log` - **every step with a millisecond timestamp**: each command sent to Windows (`Remove-AppxPackage ...`, `Remove-AppxProvisionedPackage ...`, `Stop-Process ...`, the SYSTEM launch with the launcher and the decoded child command), its answer, the holders found by each detector, the retries, the exit of the child. Grep this one when something went wrong.
- `Remove-CodecExtension-...-<timestamp>[-<tag>].csv` - the result rows: `When, Status, Check, Detail`.
- `Remove-CodecExtension-Remove-<timestamp>[-<tag>].appx-events.csv` - Windows' own AppX deployment events (`Microsoft-Windows-AppXDeploymentServer/Operational` and `AppXDeployment/Operational`) from the start of the run to its end: time, ID, level, activity ID, message. A SYSTEM parent's file covers the child's window too.

And in `-OutputPath` (`Outputs\`):

- `codec-inventory-<computer>-<timestamp>[-<tag>]-before.json` and `-after.json` - package full names, versions, users, provisioning, keys, the holders (process, PID, module or handle, package, detector), who ran it, the launcher.
- `codec-packages-<computer>-<timestamp>.csv` - the `-ListPackages` list.

A `-RunAsSystem` run leaves two sets: the parent's, and the child's tagged `system-<parent timestamp>`; the parent's table and transcript contain the child's rows and its live step log. Application log, source **CodecExtensionRemoval**: 1000 removal started, 1001 package removed and verified, 1002 nothing to do, 2001 package in use (Windows refused), 2002 warning, 3000 run stopped, 3001 a removal failed. Windows' own trail is also in `%SystemRoot%\Logs\DISM\dism.log` for the provisioning.

## 11. Automation

`-NoConfirm` is the only switch an unattended run needs. Exit code 1 on any failure, so Intune, ConfigMgr and task schedulers see it. The install and detection command lines, the GPO startup-script variant and the `-RunAsSystem` commands for an administrator's session are in [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md#c-computers-that-are-already-deployed). A GPO startup script runs before anyone signs in, so nothing holds the files; a logon-time run on a user's computer tries the removal first and needs `-StopBlockingProcesses` (and a heads-up, because it may close their browser) only on a build that refuses.

## 12. Tests

```powershell
pwsh       -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
```

Expected last line: `ALL 180 TESTS PASSED` (one test per default target checks its catalog entry, so the number moves with the list; one test is skipped with a note when `tools\PsExec64.exe` is not present). Groups: parse + ASCII of every script (scripts, tests, tools); the catalog; family names; HRESULT texts, including the code taken from the exception; the module-origin rule and a read-only query of the AppX deployment log; the `-ListPackages` listing; "in use" detection against fake processes and the stop/restart/refuse rule; the Restart Manager query against a file the test process holds open (real API); the plan for every installed/provisioned/keyed combination; mounted-image validation; the Deprovisioned key with `-WhatIf`; a real offline hive (elevated sessions); the confirmation gate; the SYSTEM helpers (PsExec verification with a missing file, a wrong hash and the shipped copy, the child command and its encoded form, CreateProcess quoting, the task XML, local-path detection, the child-result reader); and 27 end-to-end runs of the script against mocked Appx, DISM, process and launcher commands: Check, WhatIf, the non-interactive STOP, a full removal with verification, a holder on a build that succeeds anyway, a build that refuses with and without `-StopBlockingProcesses`, the retry after stopping the holder, a refusal whose holder cannot be found, `0x80073CF1`, the provisioning Windows already removed, already current, a holder that must not be killed, not elevated, an old build, `-Package`, a sideloaded publisher, offline mode, the access denied seen live and its rerun, `-RunAsSystem` through PsExec with the child run in-process, already SYSTEM, the fallback to the task on a bad hash and on a launch failure, `-SystemLauncher PsExec` refusing a bad hash, `-RunAsSystem -WhatIf`, `-ListPackages` on the running OS and on a mounted image, `-ListPackages` with `-Mode` refused, and last the guard that refuses harness mode if any system command is real. Run with `-NonInteractive` so the non-interactive STOP is meaningful.

## 13. Troubleshooting

| Message | Meaning | What to do |
|---|---|---|
| `NOT removed: Windows refused, ... is in use by <process>` (`0x80073D02`) | this build refuses while a process holds a package file | close it, or `-StopBlockingProcesses`, or `-RunAsSystem`, or run at startup / in audit mode |
| `... must not be killed, no retry` | the holder is a system, security or management process | stop the owning service, sign users out, or run before anyone signs in |
| `0x80073CF1 ERROR_INSTALL_PACKAGE_NOT_FOUND` | already gone | nothing; the script treats it as done |
| `already deprovisioned by Windows during the removal for every user (0x80070002 ...)` | Windows deprovisioned the package itself | nothing; the step is done |
| `0x80073CF3 ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED` | another package depends on it | `Get-AppxPackage -AllUsers \| Where-Object { $_.Dependencies.Name -contains '<name>' }` |
| `0x80073CFA ERROR_REMOVE_FAILED` | the deployment service failed | the run's `.appx-events.csv`, or Event Viewer, `Microsoft-Windows-AppXDeploymentServer/Operational` |
| `0x80073D01 ERROR_DEPLOYMENT_BLOCKED_BY_POLICY` | app deployment is blocked by policy | check AppLocker / App Control and the Store policies |
| `0x80070005 E_ACCESSDENIED` (in PowerShell 7 just "Access is denied.") | the app deployment service refused a step; the session is elevated, the script checked | run the same command again; the closing lines print it. Details: `Get-AppPackageLog -ActivityID <id from the FAIL row>` (section 7) |
| `0x80070032 ERROR_NOT_SUPPORTED` | part of Windows | not a codec package |
| `STOP: -SystemLauncher PsExec, but PsExec not found at ...` / `... is not the pinned ...` | no PsExec in `tools\`, or a copy with another hash | `tools\Get-PsExec.ps1` on a connected computer (hashes in `tools\THIRD-PARTY-NOTICES.md`), or `-SystemLauncher ScheduledTask` |
| `WARN SYSTEM run (PsExec) ... the child left no result file ... trying the scheduled task launcher` | PsExec could not start the child (`ADMIN$` not reachable, Server service stopped, EDR blocked `PSEXESVC`) | nothing, the task took over; the step log has PsExec's own messages |
| `FAIL SYSTEM run - no result file from the SYSTEM session` | neither launcher produced a child run | the step log shows the launcher output; check that the folder is local, that Task Scheduler runs, and run `-SystemLauncher ScheduledTask` once more |
| `STOP: '...' is not on a local drive` | the folder or a log folder is a UNC path or a network drive | copy the folder to `C:\Temp\...` and use local `-LogPath`/`-OutputPath` |
| `WARN Explorer ... (LocalSystem session)` in a SYSTEM child | Explorer was stopped from session 0 | the parent restarts it; in a pure SYSTEM deployment the user starts it from Task Manager or signs in again |
| *Modules* row: `Windows PowerShell compatibility (loaded earlier in this session)` | a second run in the same PowerShell 7 window | nothing; DISM still runs through the compatibility layer |
| `STOP: the Dism module was loaded through Windows PowerShell compatibility but its probe failed` | PowerShell 7 could not run DISM | run from an elevated Windows PowerShell 5.1 console |
| `STOP: another instance ... is running` | the mutex is held | wait, or find the other run in Task Manager |
| Sysprep: "was installed for a user, but not provisioned for all users" | per-user registration left behind | run `-Mode Remove` on the reference computer before sysprep |
| The package is back after a feature update | no Deprovisioned key | `-Mode Remove` writes it; check `HKLM\...\AppxAllUserStore\Deprovisioned` |
| A user reinstalled it from the Store | Store not blocked | *Turn off the Store application* or a packaged-app rule |
| `Restore-CodecExtension.ps1`: `STOP: run this script in Windows PowerShell 5.1` | the Store install API is a Windows Runtime type | `powershell -File .\Restore-CodecExtension.ps1 ...` |

## 14. References

- [Keep removed apps from returning during an update](https://learn.microsoft.com/windows/application-management/remove-provisioned-apps-during-update) - the Deprovisioned key
- [Sysprep fails after you remove or update Microsoft Store apps](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps)
- [Group Policy and packaged apps](https://learn.microsoft.com/windows/msix/group-policy-msix) - which Store policies block what
- [Add Microsoft Store apps to Intune](https://learn.microsoft.com/intune/app-management/deployment/add-microsoft-store) - the alternative: keep them and keep them updated
- [Troubleshoot video playback problems in Microsoft Edge](https://learn.microsoft.com/troubleshoot/microsoft-edge/development/video-playback-issues) - Edge needs the HEVC extension
- [HEIF extension codec](https://learn.microsoft.com/windows/win32/wic/heif-codec) - HEIF needs HEVC or AV1 to decode
- [Remove-AppxProvisionedPackage](https://learn.microsoft.com/powershell/module/dism/remove-appxprovisionedpackage), [Remove-AppxPackage](https://learn.microsoft.com/powershell/module/appx/remove-appxpackage)
- [PsExec](https://learn.microsoft.com/sysinternals/downloads/psexec) and the [Sysinternals license terms](https://learn.microsoft.com/sysinternals/license-terms)
- [Restart Manager](https://learn.microsoft.com/windows/win32/rstmgr/restart-manager-portal) - how the script asks Windows which processes use the package files
- [AppInstallManager](https://learn.microsoft.com/uwp/api/windows.applicationmodel.store.preview.installcontrol.appinstallmanager) - the Store install API behind `Restore-CodecExtension.ps1`

---

## Appendix A - Live runs

### 2026-10-28 - Windows 11 Enterprise 26H2, build 26300, the SYSTEM path

Before: HEVC 2.5.33.0 installed for the signed-in account and provisioned, no Deprovisioned key, two WebView2 hosts (PIDs 13920 and 21788) with `x64\hevcdecoder_store.dll` loaded. `-Mode Check -Package Microsoft.HEVCVideoExtension` (PowerShell 7) named both from the module scan; the Restart Manager query over the 181 files of the package folder agreed.

- **03:37:41** - `-Mode Remove -Package Microsoft.HEVCVideoExtension -RunAsSystem -NoConfirm` in an elevated Windows PowerShell 5.1 window. PsExec 2.43 from `tools\` passed the hash check; the plan showed the launcher and the decoded child command; **03:37:56** PsExec started the child; **03:37:58** the child ran as `NT AUTHORITY\SYSTEM` (session 0, Windows PowerShell 5.1, `Appx: native; Dism: native`), found the same two holders (**03:38:12**), and `Remove-AppxPackage -AllUsers` **succeeded on the first try** at **03:38:13** with the DLL still mapped (folder moved to `WindowsApps\Deleted`). Windows deprovisioned the package during that call and created the key; the script's own `Remove-AppxProvisionedPackage` answered `0x80070002` - reported as FAIL by that version, fixed the same hour (the list is re-read and the step reported as done; test K11b). The parent merged the child's rows, verified *not registered, not provisioned, key present* at **03:38:14**, and exported 25 AppX deployment events. 33 seconds in all; the WebView2 hosts kept running.
- **03:40** - HEVC 2.5.48.0 reinstalled through the Store install API (`AppInstallManager.StartAppInstallAsync('9N4WGH0Z6VHQ')`, 30 seconds); this became `Restore-CodecExtension.ps1`.
- **03:42:23** - `-Mode Remove -Package Microsoft.HEVCVideoExtension -RunAsSystem -SystemLauncher ScheduledTask -StopBlockingProcesses -NoConfirm`: the one-shot task `Remove-CodecExtension-System-20261028-034223` ran the child as SYSTEM; nothing had loaded the new copy yet, so nothing was stopped; removed on the first try, verified, task deleted, exit 0; 18 seconds for the child.
- **03:44** - `Restore-CodecExtension.ps1 -Package Microsoft.HEVCVideoExtension -NoConfirm`: key deleted, HEVC 2.5.48.0 installed again for the signed-in account (not provisioned - only setup, the OEM or a Store deployment provisions).
- Test suite: 180 tests passed in both editions before and after these runs.

### 2026-10-26 and 2026-10-27 - Windows 11 Enterprise 26H1, build 28000

Computer: PowerShell 7.6.9 and 5.1.28000. Before: WebP, HEVC and Raw installed for both accounts (a local and a domain account) and provisioned; Edge and three WebView2 processes had `hevcdecoder_store.dll` loaded; no Store policy configured.

**2026-10-26**

- **20:56:18-20** - `Remove-AppxPackage -AllUsers` and the deprovisioning ran for WebP, HEVC and Raw. AppX deployment log: event 603 *Started deployment Remove operation ... Options RemoveForAllUsers*, 400 *Deployment DeprovisionPackageOperation ... finished successfully*, 472 *Moving package folder ... to WindowsApps\Deleted*. Windows created the three Deprovisioned keys itself. `Remove-AppxProvisionedPackage` afterwards reported "The system cannot find the path specified" because the package was already gone (DISM log: *Failed to open ...AppxBundleManifest.xml*); that version reported it as FAIL, which exposed the harness leak described below and, on 2026-10-28, was changed to re-read the provisioning list and report the step as done. Honest note: this live removal was triggered by an intermediate test run whose harness still let the real DISM module through, not by a deliberate confirmed run; the harness now refuses to run unless every system command resolves to a mock (test K0 and the script's own guard).
- **21:05** - `-Mode Check` (PowerShell 7): every target *not installed, not provisioned, Deprovisioned key present - nothing to do*; WARN *users can open the Store and reinstall*; exit 0.
- **21:12** - `-Mode Remove` non-interactive without `-NoConfirm` (Windows PowerShell 5.1): *Already current*, no prompt needed, exit 0. Snapshot before and after identical.
- **21:24 / 21:27** - `-Mode Remove -WhatIf` in both editions: *Already current*, modules loaded (`Appx: native; Dism: Windows PowerShell compatibility` in 7, both native in 5.1), state unchanged.
- Edge and the WebView2 hosts still show the DLL mapped from the old path; the folder now lives under `WindowsApps\Deleted\` until those processes exit. Nothing needed a reboot.
- **23:39** - HEIF Image Extensions added as the fourth default target. `-Mode Check` (PowerShell 7): WebP, HEVC and Raw clean; HEIF *PRESENT - installed 1.2.48.0 for both accounts; provisioned; no Deprovisioned key*; exit 1. **23:41** - `-Mode Remove -WhatIf` (Windows PowerShell 5.1): the three HEIF steps planned, nothing changed.
- **23:45** - Edge restarted through a one-shot scheduled task with *RunLevel Limited*, so the browser did not inherit the elevated session's token; the task was deleted right after. Edge no longer maps `hevcdecoder_store.dll`; the WebView2 hosts of Widgets, Windows Search and Microsoft 365 Copilot still do until those apps restart or the user signs out.

**2026-10-27**

- **00:15:52** - `-Mode Remove` for HEIF, confirmed with Y, in an elevated PowerShell 7 window. Windows ran one request: removal for the local account *finished successfully* (event 400); then its own *DeprovisionPackageOperation* for the signed-in domain account failed with *Error 0x80070005: Failure in the OptionalDependenciesHandled state handler* (events 605/401/404), and the removal for that account in the same request failed too (648/401/404, activity `6c3a0a34-645e-0004-d77c-686c5e64dd01`). No process had HEIF files open and nothing depends on HEIF. The script's own `Remove-AppxProvisionedPackage` then deprovisioned it and the Deprovisioned key was present. Result: FAILED, one registration left. PowerShell 7 reported only "Access is denied." with no code, and the closing hint told the user to close apps, which did not apply - both fixed since: the row carries the code, the failing step and the activity ID, and the hint is specific to the error.
- **00:23:24** - The same command limited to HEIF: one removal request, *finished successfully*; verified *not registered to any user, not provisioned, Deprovisioned key present*; exit 0.
- **00:42** - `-ListPackages` in both editions: WebP, HEVC, Raw and HEIF *removed*; AV1, VP9, MPEG-2 and Web Media installed and provisioned (not default targets). Package snapshot unchanged by these read-only runs.

Generative AI was used in the creation and validation of this project; the result was reviewed and run by a person.
