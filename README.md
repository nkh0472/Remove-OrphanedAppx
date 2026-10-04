# Remove-OrphanedAppx

A PowerShell tool that finds and safely removes **orphaned and stale AppX payload folders** in
`C:\Program Files\WindowsApps` — the leftovers that `Remove-AppxPackage` and
`Remove-AppxProvisionedPackage` cannot clean up.

Runs read-only by default. Deletes nothing unless you pass `-Execute`, and refuses to delete
anything at all if it cannot read the package repository.

---

## The problem

Windows stores AppX/UWP/MSIX package payloads unpacked under `C:\Program Files\WindowsApps`.
When an app is uninstalled, deprovisioned, superseded by an update, or an install is interrupted,
its folder can be left behind with nothing in the package repository pointing at it.

Those folders are hard to reclaim:

- `Remove-AppxPackage` acts on *repository entries*. If there is no entry, it has nothing to do —
  it reports success and the folder stays.
- `Remove-AppxProvisionedPackage` only works on packages still **provisioned in the image**.
- The folder ACLs are owned by `TrustedInstaller`, so a plain `Remove-Item` gets *Access denied*
  even from an elevated prompt.
- `Get-ChildItem 'C:\Program Files\WindowsApps'` is denied to non-elevated users, which makes the
  leftovers invisible in the first place.

The result is that a fully "uninstalled" app can still occupy hundreds of megabytes, and
`Get-AppxPackage -AllUsers` gives no obvious answer about which folders are genuinely safe to
remove.

This tool answers that question explicitly, and acts on the answer only when told to.

---

## What it does

Every folder under `WindowsApps` is classified. **The first matching rule wins**, and only the
last two categories are ever removable.

| Classification | Meaning | Removable |
|---|---|---|
| `SYSTEM` | Known non-package folder owned by Windows, or a reparse point/junction | never |
| `UNKNOWN` | Folder name is not a valid `PackageFullName` shape | never |
| `PROVISIONED` | The folder's package **family** is provisioned in the image | never |
| `INSTALLED` | Some user has this exact payload installed | never |
| `RECENT` | Modified within `-MinAgeMinutes`; a deployment may be in flight | skipped |
| `STAGED` | The repository still tracks the package (`Staged` / `Paused` / …) but **no user has it installed** — a cached payload | `-Mode Staged` / `All` |
| `ORPHAN` | No repository entry references the folder at all — a pure leftover | `-Mode Orphans` / `All` |

Typical output:

```
--- classification summary ---
  INSTALLED      35 folder(s)   1,462.60 MB
  PROVISIONED   134 folder(s)   2,217.35 MB
  STAGED         54 folder(s)     174.79 MB
  SYSTEM          7 folder(s)       5.58 MB

--- removable candidates ---
  (none)
```

### What it will NOT do

It is **not** a debloater. It will never remove an app you have installed, and never touch a
package provisioned in the image. To remove an app that is still installed or provisioned, use the
supported cmdlets:

```powershell
Get-AppxPackage -AllUsers -Name <AppName> | Remove-AppxPackage -AllUsers
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like '<AppName>*' |
    Remove-AppxProvisionedPackage -Online
```

This tool handles the case those two commands leave behind.

---

## Safety model

The design is deliberately paranoid, because "delete folders under `C:\Program Files\WindowsApps`"
is a genuinely destructive operation. Every guard below is enforced independently.

1. **Classification uses `InstallState`, not `InstallLocation`.**
   A folder whose path appears in the repository is *not* necessarily in use. A package can be
   merely `Staged` (cached payload, no user installation) while its folder looks identical to an
   installed one. Only `InstallState -eq 'Installed'` marks a folder as protected.

2. **Family-level protection for provisioned packages.**
   Provisioned protection matches on the package family name (`Name_PublisherId`), not just on the
   exact folder path, so a provisioned app cannot have any of its versioned or resource payloads
   removed.

3. **Fail closed when the repository cannot be read.**
   If `Get-AppxPackage -AllUsers` or `Get-AppxProvisionedPackage -Online` fails, or the repository
   returns zero packages, the script aborts with exit code `1` and deletes nothing. It never
   guesses from a partial view.

4. **Re-verification immediately before each deletion.**
   The live repository is queried again for every individual folder. If that folder is now
   `Installed` for any user, or its family is now provisioned, the deletion is refused with an
   explicit `SAFETY:` message and the script moves on.

5. **Path containment checks.**
   A folder is only ever deleted if it is a *direct child* of `C:\Program Files\WindowsApps` and is
   not in the protected system-folder list.

6. **Age gate against races.**
   `-MinAgeMinutes` (default `30`) skips anything modified recently, so an in-progress
   install/update is never raced.

7. **Dry run by default, confirmation on by default.**
   Without `-Execute` nothing is deleted, whatever `-Mode` says. With `-Execute` you must type
   `YES` before the first deletion, unless you explicitly pass `-Force`.

8. **Full audit trail.**
   Everything is written to a timestamped log, and `-ReportJson` produces a machine-readable
   record of every classification and deletion.

---

## Requirements

- Windows 10 / 11 (any edition; tested on Windows 11 build 26300)
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator rights — required both to read the full package repository and to take ownership
  of `TrustedInstaller`-owned folders. The script asks for elevation itself via UAC.

---

## Usage

Download `Remove-OrphanedAppx.ps1`. There is nothing to install and no modules are required.

```powershell
# Analyse only — prints every folder with its classification and size. Deletes nothing.
powershell -ExecutionPolicy Bypass -File .\Remove-OrphanedAppx.ps1

# Remove pure leftovers (no repository entry at all). Asks for confirmation.
powershell -ExecutionPolicy Bypass -File .\Remove-OrphanedAppx.ps1 -Mode Orphans -Execute

# Also reclaim cached payloads of apps that are neither installed nor provisioned.
powershell -ExecutionPolicy Bypass -File .\Remove-OrphanedAppx.ps1 -Mode All -Execute

# Unattended, with a JSON audit trail.
powershell -ExecutionPolicy Bypass -File .\Remove-OrphanedAppx.ps1 `
    -Mode All -Execute -Force -ReportJson .\orphans.json

# Never treat any Photos folder as removable.
powershell -ExecutionPolicy Bypass -File .\Remove-OrphanedAppx.ps1 -ExcludeName 'Microsoft.Windows.Photos*'
```

> `-ExecutionPolicy Bypass` is only needed if your machine's execution policy is `Restricted`
> (the default on many consumer Windows installs). The elevated relaunch already applies it.

Full help:

```powershell
Get-Help .\Remove-OrphanedAppx.ps1 -Full
```

### Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-Mode` | `Report` \| `Orphans` \| `Staged` \| `All` | `Report` | Which classification to act on. `Report` prints candidates but never deletes. |
| `-Execute` | switch | off | Master switch. Without it the run is always a dry run. |
| `-MinAgeMinutes` | int | `30` | Skip folders modified more recently than this. |
| `-IncludeName` | string[] | — | Only consider folders matching these wildcards. |
| `-ExcludeName` | string[] | — | Never consider folders matching these wildcards. |
| `-LogPath` | string | `<script dir>\Remove-OrphanedAppx_<timestamp>.log` | Log file. |
| `-ReportJson` | string | — | Also write findings as JSON. |
| `-Force` | switch | off | Skip the `YES` confirmation prompt. |
| `-NoElevate` | switch | off | Fail instead of self-elevating. Useful in automation that is already elevated. |
| `-WhatIf` | switch | off | Standard `ShouldProcess` dry run. |

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Nothing to do, or everything requested was removed successfully |
| `1` | Fatal error (not elevated, repository unreadable, `WindowsApps` unlistable) |
| `2` | Removable items found but not removed (`Report` mode, or cancelled at the prompt) |
| `4` | Some deletions failed |

Exit code `2` makes the tool usable as a monitoring check: run it in `Report` mode and alert when
leftovers appear.

---

## Recommended workflow

```
1.  -Mode Report                     # see what exists; look at the classification table
2.  -Mode Orphans -Execute           # clean pure leftovers, with confirmation
3.  -Mode Report                     # confirm the result and the reclaimed space
4.  -Mode Staged -Execute            # only if you want the cached payloads gone too
```

Deleting `STAGED` payloads is safe — they are caches, and Windows re-downloads a payload from the
Store when an app is next installed — but understand the trade-off before you do it: that later
install will need network access.

---

## Worked example

A real run on a Windows 11 machine that had been in use for a while:

| Classification | Folders | Size |
|---|---|---|
| `PROVISIONED` | 134 | 2,217.35 MB |
| `INSTALLED` | 35 | 1,462.60 MB |
| `STAGED` | 54 | 174.79 MB |
| `SYSTEM` | 7 | 5.58 MB |
| `ORPHAN` | **0** | — |

```
[STEP ] --- removable candidates ---
[INFO ]   TOTAL: 54 folder(s), 174.79 MB
[STEP ] Deleting...
[OK   ]   removed
...
[STEP ] C: free after : 59.79 GB
[STEP ] reclaimed     : 175.61 MB
[STEP ] done. exit code 0
```

The 54 `STAGED` entries were the cached payloads of apps the user had uninstalled long before —
`Microsoft.ZuneVideo` (35.92 MB), `Microsoft.ZuneMusic` (32.88 MB), `Microsoft.Getstarted`
(21.22 MB), `Microsoft.GetHelp` (14.69 MB), `Microsoft.Paint` (9.44 MB), Xbox overlays and so on —
none of them installed for any user, none provisioned in the image. Reclaimed without disturbing a
single installed app.

Re-running `-Mode Report` afterwards tells the whole story: **230 folders before, 176 after** —
exactly the 54 that were removed — with `STAGED 0`, `ORPHAN 0`, no removable candidates, and no
dangling repository records.

---

## FAQ

**Will this break my apps?**
No. Folders classified `INSTALLED` or `PROVISIONED` are never deleted, and both the classification
and the pre-deletion re-check are enforced against the live repository. The worst case for a
`STAGED` payload is that Windows re-downloads it the next time that app is installed.

**It found 0 orphans on my machine. Is it broken?**
No — that is the healthy state. `ORPHAN` folders only appear after an interrupted deployment or a
failed uninstall. `STAGED` leftovers are far more common and are what most people are looking for.

**Why does it need administrator rights?**
`Get-AppxPackage -AllUsers` requires elevation, and the payload folders are owned by
`TrustedInstaller` — removing them requires taking ownership first.

**Does purging a payload leave stale records in the package repository?**
This tool deliberately does not touch those records, because rewriting
`C:\ProgramData\Microsoft\Windows\AppRepository\StateRepository-Machine.srd` directly is
unsupported and can corrupt the package store. In practice the AppX deployment service reconciles
them on its own: in the run above, the follow-up report showed 0 dangling records. If a record does
linger for a while, it is harmless.

The tool reports such records in a dedicated *dangling repository records* section rather than
silently ignoring them — a folder that is missing while the repository still points at it is worth
knowing about, even when no action is taken.

**What does it actually do to delete a folder?**
`takeown /F <path> /R /A` to take ownership from `TrustedInstaller`, then
`icacls <path> /grant *S-1-5-32-544:(F) /T` to grant `Administrators` full control, then
`Remove-Item -Recurse -Force`. If that fails it falls back to `cmd /c rd /s /q`, and finally to
mirroring an empty folder over the target with `robocopy /MIR`.

**Does it touch anything outside `C:\Program Files\WindowsApps`?**
No. It does not touch `WinSxS`, and it does not delete per-user app data under
`%LOCALAPPDATA%\Packages`, which you may want to keep or clear separately.
