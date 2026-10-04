<#
.SYNOPSIS
    Detect and safely remove orphaned / stale AppX payload folders in C:\Program Files\WindowsApps.

.DESCRIPTION
    Windows keeps AppX package payloads under C:\Program Files\WindowsApps. When an app is
    uninstalled, deprovisioned, superseded by an update, or an install is interrupted, its
    folder can be left behind with nothing in the package repository pointing at it.
    Remove-AppxPackage / Remove-AppxProvisionedPackage cannot clean those up, because they act
    on repository entries, not on stray folders. This script finds and (optionally) purges them.

    Every folder under WindowsApps is classified; the FIRST matching rule wins:

      SYSTEM       Known non-package folder owned by Windows, or a reparse point. Never touched.
      UNKNOWN      Name is not a valid PackageFullName shape. Never touched (reported only).
      PROVISIONED  The folder's package family is provisioned in the image. Never touched.
      INSTALLED    Some user has this exact payload installed. Never touched.
      RECENT       Modified within -MinAgeMinutes; a deployment may be in flight. Skipped.
      STAGED       The repository still tracks the package (state Staged / Paused / ...) but no
                   user has it installed. A cached payload: safe to purge to reclaim space,
                   although Windows normally keeps it on purpose.
      ORPHAN       No repository entry references the folder at all. Pure leftover.

    Nothing is deleted unless -Execute is given. Even then, the safety checks are re-run
    against the live repository immediately before each folder is removed, and the script
    REFUSES TO DELETE ANYTHING AT ALL if the repository cannot be queried.

.PARAMETER Mode
    Report  (default) analyse and print, delete nothing.
    Orphans           remove ORPHAN folders only.
    Staged            remove STAGED folders only.
    All               remove ORPHAN and STAGED folders.

.PARAMETER Execute
    Master switch. Without it the script is always a dry run, whatever -Mode says.

.PARAMETER MinAgeMinutes
    Skip any folder modified more recently than this many minutes (default 30), so that an
    install/update in progress is never raced.

.PARAMETER IncludeName
    Only consider folders whose name matches one of these wildcard patterns.

.PARAMETER ExcludeName
    Never consider folders whose name matches one of these wildcard patterns.

.PARAMETER LogPath
    Log file path. Default: <script folder>\Remove-OrphanedAppx_<yyyyMMdd-HHmmss>.log

.PARAMETER ReportJson
    Also write the machine-readable findings to this JSON file.

.PARAMETER Force
    Skip the interactive confirmation prompt.

.PARAMETER NoElevate
    Do not auto-elevate; fail instead if not already running elevated.

.EXAMPLE
    .\Remove-OrphanedAppx.ps1
    Analyse only. Prints every WindowsApps folder with its classification and size.

.EXAMPLE
    .\Remove-OrphanedAppx.ps1 -Mode Orphans -Execute
    Remove pure leftover folders, after one confirmation prompt.

.EXAMPLE
    .\Remove-OrphanedAppx.ps1 -Mode All -Execute -Force -ReportJson .\orphans.json
    Unattended cleanup of orphaned AND stale staged payloads, with a JSON audit trail.

.EXAMPLE
    .\Remove-OrphanedAppx.ps1 -ExcludeName 'Microsoft.Windows.Photos*'
    Never classify any Photos folder as removable.

.NOTES
    Removal takes ownership from TrustedInstaller (takeown) and grants Administrators full
    control (icacls) before deleting. Repository records belonging to purged payloads are left
    untouched on purpose: rewriting StateRepository-Machine.srd is unsupported and risky.
    Exit codes: 0 nothing to do / everything requested succeeded, 1 fatal error,
                2 removable items found but not removed (Report mode), 4 some deletions failed.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [ValidateSet('Report', 'Orphans', 'Staged', 'All')]
    [string]$Mode = 'Report',

    [switch]$Execute,

    [int]$MinAgeMinutes = 30,

    [string[]]$IncludeName = @(),

    [string[]]$ExcludeName = @(),

    [string]$LogPath,

    [string]$ReportJson,

    [switch]$Force,

    [switch]$NoElevate
)

if ($PSVersionTable.PSVersion.Major -lt 3) { throw 'PowerShell 3.0 or later is required.' }

$script:Filters = @('Main', 'Framework', 'Resource', 'Bundle', 'Optional', 'Xap')
$script:WindowsApps = Join-Path $env:ProgramFiles 'WindowsApps'
$script:LogFile = $null
$script:ErrorCount = 0

# Folders under WindowsApps that are not app payloads (or that Windows owns).
$script:SystemDirs = @(
    'Deleted', 'DeletedAllUserPackages', 'ModifiableWindowsApps', 'Tokens', 'Temp',
    'Merged', 'MovedPackages', 'Mutable', 'MutableBackup', 'Projected', 'Packages'
)

# PackageFullName shape: Name_Version_Arch_ResourceId_PublisherId
$script:PackageNameRegex = '^[A-Za-z0-9._-]+_[0-9]+(?:\.[0-9]+){1,3}_[A-Za-z0-9]*_[A-Za-z0-9._~-]*_[A-Za-z0-9]+$'

# ---------------------------------------------------------------- logging

function Write-Log {
    param(
        [Parameter(Mandatory)][AllowEmptyString()][string]$Message,
        [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'STEP')][string]$Level = 'INFO'
    )
    $line = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    $colour = switch ($Level) {
        'OK' { 'Green' }
        'WARN' { 'Yellow' }
        'ERROR' { 'Red' }
        'STEP' { 'Cyan' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $colour
    if ($script:LogFile) {
        try { Add-Content -LiteralPath $script:LogFile -Value $line -Encoding UTF8 } catch { }
    }
}

# ---------------------------------------------------------------- helpers

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-SelfElevation {
    $exe = (Get-Process -Id $PID).Path
    if (-not $exe) { $exe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe" }

    # NOTE: never use $args here - it is an automatic variable.
    $elevArgs = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath))
    $elevArgs += @('-Mode', $Mode, '-MinAgeMinutes', $MinAgeMinutes)
    if ($Execute) { $elevArgs += '-Execute' }
    if ($Force) { $elevArgs += '-Force' }
    if ($LogPath) { $elevArgs += @('-LogPath', ('"{0}"' -f $LogPath)) }
    if ($ReportJson) { $elevArgs += @('-ReportJson', ('"{0}"' -f $ReportJson)) }
    foreach ($n in $IncludeName) { $elevArgs += @('-IncludeName', ('"{0}"' -f $n)) }
    foreach ($n in $ExcludeName) { $elevArgs += @('-ExcludeName', ('"{0}"' -f $n)) }

    Write-Host 'Administrator privileges are required - requesting elevation (UAC)...' -ForegroundColor Yellow
    try {
        $p = Start-Process -FilePath $exe -Verb RunAs -PassThru -Wait -ArgumentList $elevArgs
        exit $p.ExitCode
    } catch {
        Write-Host "Elevation was refused or failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

function Get-NormPath {
    param([AllowEmptyString()][string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    $Path.Trim().TrimEnd('\')
}

# PackageFullName -> family name (Name_PublisherId)
function Get-FamilyName {
    param([AllowEmptyString()][string]$PackageFullName)
    if ([string]::IsNullOrWhiteSpace($PackageFullName)) { return '' }
    $parts = $PackageFullName.Trim() -split '_'
    if ($parts.Count -lt 2) { return '' }
    return ('{0}_{1}' -f $parts[0], $parts[-1])
}

function Get-FolderSize {
    param([Parameter(Mandatory)][string]$Path)
    $errs = @()
    $items = @(Get-ChildItem -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue -ErrorVariable +errs)
    $bytes = ($items | Measure-Object -Property Length -Sum).Sum
    if (-not $bytes) { $bytes = 0 }
    [pscustomobject]@{
        Files         = $items.Count
        Bytes         = [int64]$bytes
        AccessDenied  = $errs.Count
    }
}

function Format-MB {
    param([int64]$Bytes)
    '{0:N2} MB' -f ($Bytes / 1MB)
}

# ---------------------------------------------------------------- repository snapshot

function Get-RepositorySnapshot {
    <#
        Returns $null (and logs the reason) if the repository cannot be read. Callers MUST
        treat $null as "do not delete anything".
    #>
    $snapshot = [pscustomobject]@{
        Packages          = @()
        Provisioned       = @()
        InstalledPaths    = @{}
        TrackedPaths      = @{}
        TrackedNames      = @{}
        ProvisionedFams   = @{}
        ProvisionedPaths  = @{}
        RegistryNames     = @{}
    }

    try {
        $snapshot.Packages = @(Get-AppxPackage -AllUsers -PackageTypeFilter $script:Filters -ErrorAction Stop)
    } catch {
        Write-Log "FATAL: Get-AppxPackage -AllUsers failed: $($_.Exception.Message)" 'ERROR'
        return $null
    }
    if ($snapshot.Packages.Count -eq 0) {
        # Zero packages across all users is not a state a real Windows install can be in.
        Write-Log 'FATAL: the package repository returned zero packages - refusing to guess.' 'ERROR'
        return $null
    }

    try {
        $snapshot.Provisioned = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
    } catch {
        Write-Log "FATAL: Get-AppxProvisionedPackage -Online failed: $($_.Exception.Message)" 'ERROR'
        return $null
    }

    foreach ($p in $snapshot.Packages) {
        $states = @()
        $prop = $p.PSObject.Properties['PackageUserInformation']
        if ($prop -and $p.PackageUserInformation) {
            foreach ($u in @($p.PackageUserInformation)) {
                $sp = $u.PSObject.Properties['InstallState']
                if ($sp -and $null -ne $u.InstallState) { $states += [string]$u.InstallState }
            }
        }

        $loc = ''
        if ($p.PSObject.Properties['InstallLocation'] -and $p.InstallLocation) {
            $loc = Get-NormPath ([string]$p.InstallLocation)
        }

        if ($loc) {
            if (-not $snapshot.TrackedPaths.ContainsKey($loc)) { $snapshot.TrackedPaths[$loc] = @() }
            $snapshot.TrackedPaths[$loc] += [pscustomobject]@{ Name = $p.PackageFullName; States = $states }
            if ($states -contains 'Installed') {
                $snapshot.InstalledPaths[$loc] = $p.PackageFullName
            }
        }

        if ($p.PSObject.Properties['PackageFullName'] -and $p.PackageFullName) {
            $snapshot.TrackedNames[[string]$p.PackageFullName] = $true
        }
        $fam = Get-FamilyName ([string]$p.PackageFullName)
        if ($fam) { $snapshot.TrackedNames[$fam] = $true }
    }

    foreach ($pp in $snapshot.Provisioned) {
        if ($pp.PSObject.Properties['InstallLocation'] -and $pp.InstallLocation) {
            $snapshot.ProvisionedPaths[(Get-NormPath ([string]$pp.InstallLocation))] = $true
        }
        foreach ($nm in @($pp.PackageName, $pp.DisplayName)) {
            if ([string]::IsNullOrWhiteSpace($nm)) { continue }
            $snapshot.ProvisionedFams[[string]$nm] = $true
            $f = Get-FamilyName ([string]$nm)
            if ($f) { $snapshot.ProvisionedFams[$f] = $true }
        }
    }

    # Legacy/auxiliary store lists - a name here means the package is still tracked somehow.
    $regRoot = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore'
    foreach ($sub in @('Applications', 'Staged', 'DeferredRemoval', 'UpdatedApplications',
                       'Upgrade', 'DownlevelInstalled', 'EndOfLife', 'InboxApplications')) {
        foreach ($k in @(Get-ChildItem (Join-Path $regRoot $sub) -ErrorAction SilentlyContinue)) {
            $snapshot.RegistryNames[[string]$k.PSChildName] = $true
        }
    }

    return $snapshot
}

# ---------------------------------------------------------------- classification

function Get-FolderClassification {
    param(
        [Parameter(Mandatory)][System.IO.DirectoryInfo]$Folder,
        [Parameter(Mandatory)]$Snapshot
    )

    $name = $Folder.Name
    $path = Get-NormPath $Folder.FullName

    if ($script:SystemDirs -contains $name) {
        return [pscustomobject]@{ Kind = 'SYSTEM'; Reason = 'known Windows system folder' }
    }
    if ($Folder.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        return [pscustomobject]@{ Kind = 'SYSTEM'; Reason = 'reparse point / junction' }
    }
    if ($name -notmatch $script:PackageNameRegex) {
        return [pscustomobject]@{ Kind = 'UNKNOWN'; Reason = 'not a PackageFullName' }
    }

    $family = Get-FamilyName $name

    if ($Snapshot.ProvisionedPaths.ContainsKey($path) -or
        ($family -and $Snapshot.ProvisionedFams.ContainsKey($family))) {
        return [pscustomobject]@{ Kind = 'PROVISIONED'; Reason = "family '$family' is provisioned in the image" }
    }

    if ($Snapshot.InstalledPaths.ContainsKey($path)) {
        return [pscustomobject]@{
            Kind   = 'INSTALLED'
            Reason = "Installed for a user: $($Snapshot.InstalledPaths[$path])"
        }
    }

    if ($Snapshot.TrackedPaths.ContainsKey($path) -or $Snapshot.TrackedNames.ContainsKey($name)) {
        $states = @()
        if ($Snapshot.TrackedPaths.ContainsKey($path)) {
            foreach ($t in $Snapshot.TrackedPaths[$path]) { $states += $t.States }
        }
        $stateText = if ($states.Count) { ($states | Select-Object -Unique) -join ',' } else { 'tracked' }
        return [pscustomobject]@{ Kind = 'STAGED'; Reason = "repository tracks it (state: $stateText) but no user has it installed" }
    }

    return [pscustomobject]@{ Kind = 'ORPHAN'; Reason = 'no repository entry references this folder' }
}

# ---------------------------------------------------------------- deletion

function Remove-PayloadFolder {
    param(
        [Parameter(Mandatory)][string]$Path,
        [switch]$DryRun
    )

    $Path = Get-NormPath $Path
    if (-not (Test-Path -LiteralPath $Path)) {
        Write-Log "  already gone: $Path" 'WARN'
        return $true
    }

    # --- guard rails, re-evaluated against the live repository right before touching anything ---
    $parent = Get-NormPath (Split-Path -Parent $Path)
    if (-not [string]::Equals($parent, (Get-NormPath $script:WindowsApps), [StringComparison]::OrdinalIgnoreCase)) {
        throw "SAFETY: '$Path' is not a direct child of '$($script:WindowsApps)'."
    }
    if ($script:SystemDirs -contains (Split-Path -Leaf $Path)) {
        throw "SAFETY: '$Path' is a protected system folder."
    }

    $live = @(Get-AppxPackage -AllUsers -PackageTypeFilter $script:Filters -ErrorAction Stop)
    if ($live.Count -eq 0) { throw 'SAFETY: package repository returned nothing; refusing to delete.' }

    foreach ($p in $live) {
        if (-not $p.InstallLocation) { continue }
        if (-not [string]::Equals((Get-NormPath ([string]$p.InstallLocation)), $Path, [StringComparison]::OrdinalIgnoreCase)) { continue }
        foreach ($u in @($p.PackageUserInformation)) {
            $sp = $u.PSObject.Properties['InstallState']
            if ($sp -and [string]$u.InstallState -eq 'Installed') {
                throw "SAFETY: '$Path' is currently Installed for a user ($($p.PackageFullName))."
            }
        }
    }

    $liveProv = @(Get-AppxProvisionedPackage -Online -ErrorAction Stop)
    $family = Get-FamilyName (Split-Path -Leaf $Path)
    foreach ($pp in $liveProv) {
        $ppPath = ''
        if ($pp.PSObject.Properties['InstallLocation'] -and $pp.InstallLocation) {
            $ppPath = Get-NormPath ([string]$pp.InstallLocation)
        }
        if ($ppPath -and [string]::Equals($ppPath, $Path, [StringComparison]::OrdinalIgnoreCase)) {
            throw "SAFETY: '$Path' is a provisioned payload."
        }
        foreach ($nm in @($pp.PackageName, $pp.DisplayName)) {
            if ([string]::IsNullOrWhiteSpace($nm)) { continue }
            $f = Get-FamilyName ([string]$nm)
            if ($f -and $family -and $f -eq $family) {
                throw "SAFETY: family '$family' is provisioned in the image."
            }
        }
    }

    if ($DryRun) {
        Write-Log "  [dry-run] would delete: $Path"
        return $true
    }

    Write-Log '  taking ownership (takeown)...'
    & takeown.exe /F $Path /R /A /D Y 2>&1 | Out-Null
    Write-Log '  granting Administrators full control (icacls)...'
    & icacls.exe $Path /grant '*S-1-5-32-544:(F)' /T /C /Q 2>&1 | Out-Null

    try { Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop }
    catch { Write-Log "  Remove-Item: $($_.Exception.Message)" 'WARN' }

    if (Test-Path -LiteralPath $Path) {
        Write-Log '  fallback: cmd rd /s /q' 'WARN'
        & cmd.exe /c "rd /s /q `"$Path`"" 2>&1 | Out-Null
    }
    if (Test-Path -LiteralPath $Path) {
        Write-Log '  fallback: robocopy an empty folder over it' 'WARN'
        $empty = Join-Path $env:TEMP ('orphan_empty_' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $empty -Force | Out-Null
        & robocopy.exe $empty $Path /MIR /NFL /NDL /NJH /NJS /NC /NS /NP | Out-Null
        Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $empty -Recurse -Force -ErrorAction SilentlyContinue
    }

    return (-not (Test-Path -LiteralPath $Path))
}

# ================================================================ main

if (-not (Test-IsAdmin)) {
    if ($NoElevate) {
        Write-Host 'Administrator privileges are required (Get-AppxPackage -AllUsers needs elevation).' -ForegroundColor Red
        exit 1
    }
    Invoke-SelfElevation
}

if (-not $LogPath) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $scriptDir) { $scriptDir = (Get-Location).Path }
    $LogPath = Join-Path $scriptDir ('Remove-OrphanedAppx_{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
}
$script:LogFile = $LogPath

Write-Log '===================================================================' 'STEP'
Write-Log "Remove-OrphanedAppx  mode=$Mode  execute=$([bool]$Execute)  minAge=${MinAgeMinutes}m" 'STEP'
Write-Log "user    : $([Security.Principal.WindowsIdentity]::GetCurrent().Name)" 'STEP'
Write-Log "target  : $($script:WindowsApps)" 'STEP'
Write-Log "log     : $LogPath" 'STEP'
Write-Log '===================================================================' 'STEP'

if (-not (Test-Path -LiteralPath $script:WindowsApps)) {
    Write-Log "WindowsApps folder not found: $($script:WindowsApps)" 'ERROR'
    exit 1
}

$freeBefore = (Get-PSDrive C).Free
Write-Log ("C: free before: {0:N2} GB" -f ($freeBefore / 1GB))

Write-Log 'Reading the package repository...' 'STEP'
$snapshot = Get-RepositorySnapshot
if ($null -eq $snapshot) {
    Write-Log 'The package repository could not be read reliably. Nothing will be deleted.' 'ERROR'
    exit 1
}
Write-Log ("registered packages : {0}" -f $snapshot.Packages.Count)
Write-Log ("provisioned packages: {0}" -f $snapshot.Provisioned.Count)
Write-Log ("tracked payload paths: {0}" -f $snapshot.TrackedPaths.Count)

Write-Log 'Scanning WindowsApps...' 'STEP'
$folders = @(Get-ChildItem -LiteralPath $script:WindowsApps -Directory -Force -ErrorAction SilentlyContinue)
if ($folders.Count -eq 0) {
    Write-Log 'Could not enumerate WindowsApps even when elevated. Aborting.' 'ERROR'
    exit 1
}
Write-Log ("folders found: {0}" -f $folders.Count)

$cutoff = (Get-Date).AddMinutes(-1 * [Math]::Abs($MinAgeMinutes))
$findings = @()

foreach ($f in ($folders | Sort-Object Name)) {
    $cls = Get-FolderClassification -Folder $f -Snapshot $snapshot

    if ($IncludeName.Count -and -not ($IncludeName | Where-Object { $f.Name -like $_ })) {
        $cls = [pscustomobject]@{ Kind = 'FILTERED'; Reason = 'excluded by -IncludeName' }
    }
    if ($ExcludeName.Count -and ($ExcludeName | Where-Object { $f.Name -like $_ })) {
        $cls = [pscustomobject]@{ Kind = 'FILTERED'; Reason = 'excluded by -ExcludeName' }
    }
    if ($cls.Kind -in @('ORPHAN', 'STAGED') -and $f.LastWriteTime -gt $cutoff) {
        $cls = [pscustomobject]@{ Kind = 'RECENT'; Reason = "modified $($f.LastWriteTime.ToString('yyyy-MM-dd HH:mm')) - within ${MinAgeMinutes}m" }
    }

    $size = Get-FolderSize -Path $f.FullName
    $findings += [pscustomobject]@{
        Name          = $f.Name
        Kind          = $cls.Kind
        Reason        = $cls.Reason
        SizeBytes     = $size.Bytes
        SizeText      = (Format-MB $size.Bytes)
        Files         = $size.Files
        AccessDenied  = $size.AccessDenied
        Created       = $f.CreationTime
        LastWrite     = $f.LastWriteTime
        FullName      = $f.FullName
    }
}

# ---- report ----
Write-Log '' 
Write-Log '--- classification summary ---' 'STEP'
foreach ($g in ($findings | Group-Object Kind | Sort-Object Name)) {
    $sum = ($g.Group | Measure-Object -Property SizeBytes -Sum).Sum
    Write-Log ("  {0,-12} {1,4} folder(s)  {2,12}" -f $g.Name, $g.Count, (Format-MB ([int64]$sum)))
}

Write-Log ''
Write-Log '--- removable candidates ---' 'STEP'
$wanted = switch ($Mode) {
    'Orphans' { @('ORPHAN') }
    'Staged' { @('STAGED') }
    'All' { @('ORPHAN', 'STAGED') }
    default { @('ORPHAN') }   # Report mode lists orphans as the candidates
}
$candidates = @($findings | Where-Object { $wanted -contains $_.Kind })
if ($candidates.Count -eq 0) {
    Write-Log '  (none)'
} else {
    foreach ($c in $candidates) {
        Write-Log ("  {0,-14} {1,10}  {2}" -f $c.Kind, $c.SizeText, $c.Name)
        Write-Log ("                 reason: {0}" -f $c.Reason)
    }
    $candBytes = ($candidates | Measure-Object -Property SizeBytes -Sum).Sum
    Write-Log ("  TOTAL: {0} folder(s), {1}" -f $candidates.Count, (Format-MB ([int64]$candBytes)))
}

Write-Log ''
Write-Log '--- protected / skipped ---' 'STEP'
$protected = @($findings | Where-Object { $_.Kind -notin @('ORPHAN', 'STAGED') })
Write-Log ("  protected or skipped: {0} folder(s)" -f $protected.Count)
foreach ($p in ($protected | Where-Object { $_.Kind -in @('PROVISIONED', 'INSTALLED', 'RECENT', 'UNKNOWN') })) {
    Write-Log ("  {0,-12} {1} :: {2}" -f $p.Kind, $p.Name, $p.Reason) 'WARN'
}

# ---- dangling repository records (informational) ----
Write-Log ''
Write-Log '--- dangling repository records (payload missing, records left as-is) ---' 'STEP'
$dangling = @()
foreach ($loc in $snapshot.TrackedPaths.Keys) {
    if (-not (Test-Path -LiteralPath $loc)) {
        $dangling += [pscustomobject]@{ Path = $loc; Names = ($snapshot.TrackedPaths[$loc] | ForEach-Object { $_.Name }) }
    }
}
if ($dangling.Count -eq 0) { Write-Log '  (none)' }
foreach ($d in $dangling) { Write-Log ("  {0}" -f $d.Path) 'WARN' }

# ---- JSON report ----
if ($ReportJson) {
    $payload = [pscustomobject]@{
        GeneratedAt   = (Get-Date).ToString('s')
        Computer      = $env:COMPUTERNAME
        User          = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        Mode          = $Mode
        Executed      = [bool]$Execute
        WindowsApps   = $script:WindowsApps
        RepoPackages  = $snapshot.Packages.Count
        RepoProvisioned = $snapshot.Provisioned.Count
        FreeBytesBefore = $freeBefore
        Findings      = $findings
        DanglingRecords = $dangling
    }
    try {
        $payload | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $ReportJson -Encoding UTF8
        Write-Log "JSON report written: $ReportJson" 'OK'
    } catch {
        Write-Log "Could not write JSON report: $($_.Exception.Message)" 'ERROR'
    }
}

# ---- act ----
$exitCode = 0
if (-not $Execute) {
    if ($candidates.Count -gt 0) { $exitCode = 2 }
    Write-Log ''
    Write-Log 'DRY RUN (no -Execute): nothing was deleted.' 'WARN'
} elseif ($Mode -eq 'Report') {
    Write-Log ''
    Write-Log '-Mode Report never deletes. Use -Mode Orphans|Staged|All with -Execute.' 'WARN'
    if ($candidates.Count -gt 0) { $exitCode = 2 }
} else {
    Write-Log ''
    if ($candidates.Count -eq 0) {
        Write-Log 'Nothing to remove.' 'OK'
    } else {
        $candBytes = ($candidates | Measure-Object -Property SizeBytes -Sum).Sum
        if (-not $Force -and -not $WhatIfPreference) {
            Write-Host ''
            Write-Host ("About to permanently delete {0} folder(s) totalling {1}:" -f $candidates.Count, (Format-MB ([int64]$candBytes))) -ForegroundColor Yellow
            Write-Host '  These are app payloads, not user documents. Repository records stay untouched.' -ForegroundColor Yellow
            $answer = Read-Host 'Type YES to proceed'
            if ($answer -ne 'YES') {
                Write-Log 'Cancelled by the user.' 'WARN'
                exit 2
            }
        }

        Write-Log 'Deleting...' 'STEP'
        foreach ($c in $candidates) {
            Write-Log ("--- {0} [{1}, {2}]" -f $c.Name, $c.Kind, $c.SizeText)
            try {
                $ok = Remove-PayloadFolder -Path $c.FullName
                if ($ok) { Write-Log '  removed' 'OK' } else { Write-Log '  STILL PRESENT after removal attempts' 'ERROR'; $script:ErrorCount++ }
            } catch {
                Write-Log "  refused/failed: $($_.Exception.Message)" 'ERROR'
                $script:ErrorCount++
            }
        }
        $freeAfter = (Get-PSDrive C).Free
        Write-Log ''
        Write-Log ("C: free after : {0:N2} GB" -f ($freeAfter / 1GB)) 'STEP'
        Write-Log ("reclaimed     : {0}" -f (Format-MB ([int64]($freeAfter - $freeBefore)))) 'STEP'
        if ($script:ErrorCount -gt 0) { $exitCode = 4 }
    }
}

Write-Log ''
Write-Log ('done. exit code {0}' -f $exitCode) 'STEP'
exit $exitCode
