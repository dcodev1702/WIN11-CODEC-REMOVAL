# Third-party software in this folder

## PsExec (Sysinternals PsTools)

| Item | Value |
|---|---|
| Files | `PsExec64.exe` (x64, used by default), `PsExec.exe` (x86, for a 32-bit host) |
| Version | 2.43 (from the PsTools 2.54 package) |
| Publisher | Sysinternals, a wholly owned subsidiary of Microsoft Corporation |
| Source | <https://download.sysinternals.com/files/PSTools.zip> |
| Downloaded | 2026-10-28, on an Internet-connected computer |
| PSTools.zip SHA256 | `C26C6BA44997E650A733DF257C8FEB83898D3FAEF2D2E391869D107E40863553` |
| PsExec64.exe SHA256 | `EDFAE1A69522F87B12C6DAC3225D930E4848832E3C551EE1E7D31736BF4525EF` |
| PsExec.exe SHA256 | `078163D5C16F64CAA5A14784323FD51451B8C831C73396B967B4E35E6879937B` |
| Authenticode | Valid, signer `CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US`, certificate thumbprint `97221B97098F37A135DCC212E2B41E452BCE51F2`, timestamped by Microsoft Time-Stamp Service |
| License | [Sysinternals Software License Terms](Sysinternals-EULA.txt), byte-for-byte the `Eula.txt` from the ZIP (SHA256 `8329BCBADC7F81539A4969CA13F0BE5B8EB7652B912324A1926FC9BFB6EC005A`) |

The same hashes are pinned in `scripts\Codec-Common.ps1` (`$CodecPsExecHash`) and listed in `SHA256SUMS.txt`.
`Remove-CodecExtension.ps1 -RunAsSystem` refuses to start a PsExec whose SHA256 does not match the pinned value,
and it passes `-accepteula` to PsExec: by using `-RunAsSystem` with PsExec you accept the license terms above on
behalf of your organisation.

### License notes you should read before redistributing this folder

The Sysinternals license grants the right to "install and use any number of copies of the software on your
devices". It says you may not "publish the software for others to copy" and may not "transfer the software or this
agreement to any third party". Carrying this folder into an isolated network for your own organisation's use is
covered by the first sentence. Publishing the binaries in a public repository is what the second sentence is about,
and this repository is public, so **the binaries are not in source control** (`.gitignore`): on an
Internet-connected computer run `tools\Get-PsExec.ps1`, which downloads the ZIP, checks the pinned hashes and
copies `PsExec64.exe`, `PsExec.exe` and the license here; then copy the whole folder to the isolated network. If
you make the repository private and want the binaries committed, delete the two `tools/PsExec*.exe` lines from
`.gitignore`. The script works without PsExec: `-RunAsSystem` then uses a one-shot scheduled task running as SYSTEM
(`-SystemLauncher ScheduledTask`), which needs no third-party file at all.

### Verifying the files on the isolated network

```powershell
Get-FileHash -Algorithm SHA256 .\tools\PsExec64.exe, .\tools\PsExec.exe
Get-AuthenticodeSignature .\tools\PsExec64.exe | Format-List Status, SignerCertificate
```

Compare the hashes with the table above (or run `.\tools\Get-PsExec.ps1 -VerifyOnly`).
