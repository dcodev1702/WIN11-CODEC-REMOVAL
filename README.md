# WIN11-CODEC-REMOVAL - remove the Microsoft Store codec packages from Windows 11

> [!NOTE]
> **`scripts\Remove-CodecExtension.ps1`** removes the Store-delivered codec packages that keep appearing in vulnerability scans - **WebP Image Extension**, **HEVC Video Extensions** and **Raw Image Extension** by default - from a Windows 10/11 computer or from a **mounted golden image**: for **every user profile**, from the **provisioning list**, and with the **registry key that stops feature updates from bringing them back**. It needs only the inbox Appx and Dism modules and an elevated session. Written for **PowerShell 7**; also runs in **Windows PowerShell 5.1**. **Read-only by default** (`-Mode Check`), asks **Y/N** before any change, supports **`-WhatIf`** and **`-NoConfirm`**, verifies the result from the system, and leaves a transcript, a CSV of PASS/WARN/FAIL rows, an inventory JSON (before and after) and Application events.

> [!IMPORTANT]
> **Verified live on 2026-10-26** on a Windows 11 Enterprise computer (build 28000), both editions: the three packages were **removed for every user, deprovisioned and keyed** in three seconds (AppX deployment events 603/400/472), the HEVC package went **even though Edge and three WebView2 hosts had its decoder DLL loaded**, `-Mode Check` then reported every target "not installed, not provisioned, Deprovisioned key present" and a second `-Mode Remove` reported **Already current** without prompting. The removal path is also proven by **103 tests against mocked Appx/DISM/process commands** ([`tests/`](tests/Test-CodecRemoval.ps1)) in both editions. Honest note: that live removal was triggered by an **intermediate test run** whose harness still let the real DISM module through, not by a deliberate confirmed run; the harness now **refuses to run** unless every system command resolves to a mock (test K0 and the script's own guard). Details in [Appendix A](#appendix-a--live-run-2026-10-26).

---

## Contents

1. [What these packages are and where they come from](#1-what-these-packages-are-and-where-they-come-from)
2. [Why they are always "vulnerable"](#2-why-they-are-always-vulnerable)
3. [What stops working, and what does not](#3-what-stops-working-and-what-does-not)
4. [What is in this folder](#4-what-is-in-this-folder)
5. [Quick start](#5-quick-start)
6. [How the script works](#6-how-the-script-works)
7. ["The app is in use" - and do I need SYSTEM?](#7-the-app-is-in-use---and-do-i-need-system)
8. [Golden image](#8-golden-image)
9. [Parameters](#9-parameters)
10. [Evidence](#10-evidence)
11. [Automation](#11-automation)
12. [Tests](#12-tests)
13. [Troubleshooting](#13-troubleshooting)
14. [References](#14-references)
- [Appendix A - Live run (2026-10-26)](#appendix-a--live-run-2026-10-26)

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
| `Microsoft.HEVCVideoExtensions` | HEVC Video Extensions (paid) | 9NMZLZ57R3T7 | the same decoder | bought by a user |
| `Microsoft.HEIFImageExtension` | HEIF Image Extensions | 9PMMSR1CGPWG | `.heic`/`.heif` containers (needs HEVC) | provisioned by Windows setup |
| `Microsoft.AV1VideoExtension`, `Microsoft.VP9VideoExtensions`, `Microsoft.MPEG2VideoExtension`, `Microsoft.WebMediaExtensions` | AV1, VP9, MPEG-2, Web Media | see `scripts\Codec-Common.ps1` | other video/audio formats | provisioned by Windows setup |

The first three are the script's default targets. Every row is accepted by `-Package`; anything else is rejected by `ValidateSet`. Store IDs were checked on 2026-10-26 (apps.microsoft.com, Microsoft Learn, winget).

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

**Not affected**

- Web pages: Edge, Chrome and Firefox render WebP/AVIF with their own decoders.
- Teams and Zoom calls (their own codecs: H.264, VP8/VP9, AV1).
- JPEG, PNG, GIF, BMP, TIFF and H.264 MP4 are inbox Windows codecs, not Store packages.

## 4. What is in this folder

| Path | What it is |
|---|---|
| [`scripts/Remove-CodecExtension.ps1`](scripts/Remove-CodecExtension.ps1) | The script. Comment-based help: `Get-Help .\Remove-CodecExtension.ps1 -Full`. |
| [`scripts/Codec-Common.ps1`](scripts/Codec-Common.ps1) | Shared functions and the package catalog (names, Store IDs, origin, what breaks). Pure, dot-sourced by the script and the tests. |
| [`scripts/Confirm-Change.ps1`](scripts/Confirm-Change.ps1) | The confirmation gate: yellow summary, `Continue? [Y/N]`, `-NoConfirm`, never hangs in a non-interactive session. |
| [`tests/Test-CodecRemoval.ps1`](tests/Test-CodecRemoval.ps1) | 103 tests, no Pester needed, both editions; nothing on the computer is changed. |
| [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md) | Runbook: reference computer in audit mode, offline WIM/VHDX, Intune / ConfigMgr / GPO, keeping them gone. |
| `Logs/`, `Outputs/` | Created on first run: transcripts + CSV, inventory JSON. Git-ignored. |

## 5. Quick start

Elevated PowerShell 7 or Windows PowerShell 5.1, in `scripts\`:

```powershell
.\Remove-CodecExtension.ps1                                       # read-only: what is installed, for whom, provisioned, keyed, and which processes hold the files
.\Remove-CodecExtension.ps1 -Mode Remove -WhatIf                  # the exact plan, nothing changed, nothing asked
.\Remove-CodecExtension.ps1 -Mode Remove                          # removes after Continue? [Y/N]
.\Remove-CodecExtension.ps1 -Mode Remove -StopBlockingProcesses   # also closes Edge / WebView2 apps / Photos that hold a package file
.\Remove-CodecExtension.ps1 -Mode Remove -NoConfirm               # automation (image build, Intune, ConfigMgr, startup script)
.\Remove-CodecExtension.ps1 -Mode Remove -MountedImagePath C:\Mount -NoConfirm   # offline WIM/VHDX
```

Exit code 1 means: in Check mode a target is still present (use it as a compliance check); in Remove mode a removal failed or was blocked. Run the same command again after closing the apps named in the output; the script only does what is still missing.

## 6. How the script works

1. **Pre-flight, nothing changed:** elevated session; Windows build 17134 or later (10 1803, where a deprovisioned package stays removed across feature updates); one instance at a time (global mutex); Appx and Dism modules - PowerShell 7 loads Dism through the Windows PowerShell compatibility layer because the native import answers "Class not registered"; each module is probed with a read-only call. A `-MountedImagePath` must hold a `SOFTWARE` hive and a kernel of build 17134+, and may not be the running OS.
2. **Inventory, read-only:** every target registered to any user (`Get-AppxPackage -AllUsers`, with the user list), every target in the provisioning list (`Get-AppxProvisionedPackage`), the Deprovisioned keys, and every running process that has a file from a package folder loaded (the "in use" cause). A package whose publisher ID is not the Store's is flagged as sideloaded.
3. **Plan.** Per package: remove for every user / deprovision / write key, or "nothing to do". `-Mode Check` stops here with FAIL rows for anything present and a WARN when users can reinstall from the Store (no Store policy).
4. **Confirm.** The plan in yellow - packages, versions, users, processes that will be stopped or that block, the effect, how to undo - then `Continue? [Y/N]`. `-NoConfirm` skips the prompt (the plan is still printed and transcribed), `-WhatIf` shows the plan only, and a non-interactive session without `-NoConfirm` stops before any change.
5. **Apply, per package:** `Remove-AppxPackage -AllUsers` (three tries when a process still holds a file and `-StopBlockingProcesses` is set; 0x80073CF1 "not found" counts as done), `Remove-AppxProvisionedPackage` (`-Online` or `-Path`), then the Deprovisioned key `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\<PackageFamilyName>` (written into the image hive in offline mode). Explorer, if it had to be stopped, is started again.
6. **Verify from the system:** the three facts are read again, not taken from variables; a package still registered, still provisioned or without its key is a FAIL. Inventory JSON before and after, Application events, CSV, transcript. No reboot is needed.

## 7. "The app is in use" - and do I need SYSTEM?

**No.** An elevated administrator has every right the removal needs; `psexec -s` or a SYSTEM scheduled task changes nothing about a DLL another process holds, the same error comes back. SYSTEM is simply the context Intune, ConfigMgr and startup scripts run in, and the script supports it (`-NoConfirm`, logs to any `-LogPath`).

What the error means: `Remove-AppxPackage` reports **0x80073D02 ERROR_PACKAGES_IN_USE** ("resources it modifies are currently in use") when a running process has a file from the package folder loaded. For the HEVC package that is normally **Microsoft Edge and every WebView2 host** (new Teams, new Outlook, Widgets, Copilot ...), which load `hevcdecoder_store.dll` when they enumerate Media Foundation decoders; for the image codecs it is Photos, Paint, a thumbnail COM surrogate (`dllhost`) or Explorer itself. `-Mode Check` names those processes with PID and module. `-StopBlockingProcesses` stops them (and restarts Explorer); system, security and management processes (`svchost`, `lsass`, `csrss`, `MsMpEng`, `CcmExec`, PowerShell itself ...) are never killed - the run refuses and tells you to stop the service or run at startup.

On the computer this was verified on (build 28000) the deployment engine **did not need that**: it renamed the package folder into `WindowsApps\Deleted` and finished while Edge still had the DLL mapped. Whether your build blocks or not, the handling is in place. A golden-image build in audit mode has no browser open and never hits it.

## 8. Golden image

Two supported paths, both in [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md):

- **Reference computer in audit mode**, then `sysprep /generalize`: run `-Mode Remove -NoConfirm` on it. Removing for every user *and* deprovisioning is required, otherwise sysprep fails ([Microsoft KB](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps)); the script does both.
- **Offline `install.wim` / VHDX**: `Mount-WindowsImage`, then `-Mode Remove -MountedImagePath <mount> -NoConfirm`, then `Dismount-WindowsImage -Save`. The script deprovisions with DISM and writes the Deprovisioned keys into the image's `SOFTWARE` hive. A captured image that already contains user profiles keeps their registrations - use the audit-mode path for it.

After deployment, `-Mode Check` (exit code 1 = drift) is the compliance check, and `Turn off the Store application` or an AppLocker / App Control packaged-app rule keeps users from reinstalling.

## 9. Parameters

| Parameter | Default | Meaning |
|---|---|---|
| `-Mode Check\|Remove` | `Check` | Check is read-only and exits 1 while a target is present. Remove performs the removal. |
| `-Package <names>` | WebP, HEVC, Raw | Which packages. Only the catalog names are accepted (see section 1). |
| `-MountedImagePath <folder>` | empty = running OS | Offline servicing of a mounted image. The running OS is refused. |
| `-StopBlockingProcesses` | off | Stop the processes that hold a package file first; Explorer is restarted. Without it a package in use is FAIL and skipped. |
| `-LogPath`, `-OutputPath` | `<folder>\Logs`, `<folder>\Outputs` | Transcript + CSV, inventory JSON. Point them at `%ProgramData%` when deploying from a read-only share. |
| `-NoConfirm` | off | No prompt; the plan is still printed and transcribed. Required for unattended runs. |
| `-WhatIf` | off | Plan only, nothing changed, nothing asked. |
| `-DeprovisionedKeyRoot` | the real key | Tests only. |

## 10. Evidence

- `Logs\Remove-CodecExtension-<Mode>-<timestamp>.log` - transcript; `.csv` - the PASS/WARN/FAIL rows.
- `Outputs\codec-inventory-<computer>-<timestamp>-before.json` and `-after.json` - package full names, versions, users, provisioning, keys, blocking processes.
- Application log, source **CodecExtensionRemoval**: 1000 removal started, 1001 package removed and verified, 1002 nothing to do, 2001 package in use, 2002 warning, 3000 run stopped, 3001 a removal failed.
- Windows' own trail: `Microsoft-Windows-AppXDeploymentServer/Operational` (events 603 remove started, 400 finished, 472 folder moved) and `%SystemRoot%\Logs\DISM\dism.log` for the provisioning.

## 11. Automation

`-NoConfirm` is the only switch an unattended run needs. Exit code 1 on any failure, so Intune, ConfigMgr and task schedulers see it. The install and detection command lines, and the GPO startup-script variant, are in [`docs/GOLDEN-IMAGE.md`](docs/GOLDEN-IMAGE.md#c-computers-that-are-already-deployed). A GPO startup script runs before anyone signs in, so nothing holds the files; a logon-time run on a user's computer needs `-StopBlockingProcesses` and a heads-up, because it closes their browser.

## 12. Tests

```powershell
pwsh       -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File .\tests\Test-CodecRemoval.ps1
```

Expected last line: `ALL 103 TESTS PASSED`. Groups: parse + ASCII of every script; the catalog; family names from full, provisioned and bare names; HRESULT texts; "in use" detection against fake processes and the stop/restart/refuse rule; the plan for every installed/provisioned/keyed combination; mounted-image validation; the Deprovisioned key with `-WhatIf`; a real offline hive (`reg.exe save`, load, write, unload, read back - elevated sessions); the confirmation gate (Y, yes, N, invalid x3, non-interactive, `-NoConfirm`); and 16 end-to-end runs of the script against mocked Appx, DISM and process commands (Check, WhatIf, the non-interactive STOP, a full removal with verification, in-use with and without `-StopBlockingProcesses`, the 0x80073D02 retry, 0x80073CF1, already current, a refused blocker, not elevated, an old build, `-Package`, a sideloaded publisher, offline mode, and the guard that refuses harness mode if any system command is real). Run with `-NonInteractive` so the non-interactive STOP is meaningful.

## 13. Troubleshooting

| Message | Meaning | What to do |
|---|---|---|
| `0x80073D02 ERROR_PACKAGES_IN_USE` | a process has a package file loaded | the row names it; close it, or `-StopBlockingProcesses`, or run at startup / in audit mode |
| `0x80073CF1 ERROR_INSTALL_PACKAGE_NOT_FOUND` | already gone | nothing; the script treats it as done |
| `0x80073CF3 ERROR_INSTALL_RESOLVE_DEPENDENCY_FAILED` | another package depends on it | `Get-AppxPackage -AllUsers \| Where-Object { $_.Dependencies.Name -contains '<name>' }` |
| `0x80073CFA ERROR_REMOVE_FAILED` | the deployment service failed | Event Viewer, `Microsoft-Windows-AppXDeploymentServer/Operational` |
| `0x80073D01 ERROR_DEPLOYMENT_BLOCKED_BY_POLICY` | app deployment is blocked by policy | check AppLocker / App Control and the Store policies |
| `0x80070032`, `0x80070005` | part of Windows / access denied | not a codec package, or not elevated |
| `STOP: the Dism module was loaded through Windows PowerShell compatibility but its probe failed` | PowerShell 7 could not run DISM | run from an elevated Windows PowerShell 5.1 console |
| `STOP: another instance ... is running` | the mutex is held | wait, or find the other run in Task Manager |
| `STOP: a process that must not be killed has a package file loaded` | `svchost`, `lsass`, antivirus, ConfigMgr ... hold a file | stop the owning service, sign users out, or run at startup |
| Sysprep: "was installed for a user, but not provisioned for all users" | per-user registration left behind | run `-Mode Remove` on the reference computer before sysprep |
| The package is back after a feature update | no Deprovisioned key | `-Mode Remove` writes it; check `HKLM\...\AppxAllUserStore\Deprovisioned` |
| A user reinstalled it from the Store | Store not blocked | *Turn off the Store application* or a packaged-app rule |

## 14. References

- [Keep removed apps from returning during an update](https://learn.microsoft.com/windows/application-management/remove-provisioned-apps-during-update) - the Deprovisioned key
- [Sysprep fails after you remove or update Microsoft Store apps](https://learn.microsoft.com/troubleshoot/windows-client/setup-upgrade-and-drivers/sysprep-fails-remove-or-update-store-apps)
- [Group Policy and packaged apps](https://learn.microsoft.com/windows/msix/group-policy-msix) - which Store policies block what
- [Add Microsoft Store apps to Intune](https://learn.microsoft.com/intune/app-management/deployment/add-microsoft-store) - the alternative: keep them and keep them updated
- [Troubleshoot video playback problems in Microsoft Edge](https://learn.microsoft.com/troubleshoot/microsoft-edge/development/video-playback-issues) - Edge needs the HEVC extension
- [HEIF extension codec](https://learn.microsoft.com/windows/win32/wic/heif-codec) - HEIF needs HEVC or AV1 to decode
- [Remove-AppxProvisionedPackage](https://learn.microsoft.com/powershell/module/dism/remove-appxprovisionedpackage), [Remove-AppxPackage](https://learn.microsoft.com/powershell/module/appx/remove-appxpackage)

---

## Appendix A - Live run (2026-10-26)

Computer: Windows 11 Enterprise 26H1, build 28000, PowerShell 7.6.9 and 5.1.28000. Before: all three packages installed for both local accounts and provisioned; Edge and three WebView2 processes had `hevcdecoder_store.dll` loaded; no Store policy configured.

- **20:56:18-20** - `Remove-AppxPackage -AllUsers` and the deprovisioning ran for WebP, HEVC and Raw. AppX deployment log: event 603 *Started deployment Remove operation ... Options RemoveForAllUsers*, 400 *Deployment DeprovisionPackageOperation ... finished successfully*, 472 *Moving package folder ... to WindowsApps\Deleted*. Windows created the three Deprovisioned keys itself. `Remove-AppxProvisionedPackage` afterwards reported "The system cannot find the path specified" because the package was already gone (DISM log: *Failed to open ...AppxBundleManifest.xml*); the script treats that as a FAIL row, which is correct for a real run and was the symptom that exposed the harness leak described in the note at the top.
- **21:05** - `-Mode Check` (PowerShell 7): every target *not installed, not provisioned, Deprovisioned key present - nothing to do*; WARN *users can open the Store and reinstall*; exit 0.
- **21:12** - `-Mode Remove` non-interactive without `-NoConfirm` (Windows PowerShell 5.1): *Already current*, no prompt needed, exit 0. Snapshot before and after identical.
- **21:24 / 21:27** - `-Mode Remove -WhatIf` in both editions: *Already current*, modules loaded (`Appx: native; Dism: Windows PowerShell compatibility` in 7, both native in 5.1), state unchanged.
- Edge and the WebView2 hosts still show the DLL mapped from the old path; the folder now lives under `WindowsApps\Deleted\` until those processes exit. Nothing needed a reboot.

Generative AI was used in the creation and validation of this project; the result was reviewed and run by a person.
