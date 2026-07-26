<#
.SYNOPSIS
  Stop Git Bash / MSYS from creating stray <drive>:\c\... trees, on every Windows node.

.DESCRIPTION
  Git Bash converts a standalone POSIX path ARGUMENT (/c/projects/x) to Windows form
  before handing it to a native Windows binary. It cannot see a path embedded in an
  inline script body, a heredoc, a //c/ escape, or one produced under
  MSYS_NO_PATHCONV=1. The native binary then resolves the leading "/" against the
  CURRENT DRIVE, so /c/projects/x is written to <drive>:\c\projects\x.

      python -c "import os; print(os.path.abspath('/c/projects/x'))"   ->  C:\c\projects\x

  There is no MSYS or git setting that fixes this, because the conversion layer never
  sees the string. So this installer applies two independent layers:

    1. PREVENT  - a PreToolUse(Bash) hook that blocks the four leak shapes before they
                  run and tells the caller the portable form to use instead.
    2. CONTAIN  - a read-only "canary" FILE at <root>\<letter> (e.g. C:\c). A file and a
                  directory cannot share a name, so any leak that slips past layer 1
                  fails loudly at mkdir instead of silently writing to the wrong place.

  Idempotent: safe to re-run, and safe to run on a node that is already configured.

.PARAMETER Quarantine
  Move any existing stray <root>\<letter> directories here instead of just reporting
  them. Nothing is ever deleted.

.PARAMETER NoCanary
  Install the hook only; do not create canary files at drive roots.

.PARAMETER Disarm
  Remove canary files created by a previous run, then exit.

.PARAMETER DryRun
  Print what would change; write nothing.

.EXAMPLE
  .\install.ps1
.EXAMPLE
  .\install.ps1 -Quarantine C:\tmp\stray-posix-roots
.EXAMPLE
  .\install.ps1 -Disarm
#>
[CmdletBinding()]
param(
    [string]$Quarantine,
    [switch]$NoCanary,
    [switch]$Disarm,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$kit       = Split-Path -Parent $MyInvocation.MyCommand.Path
$claudeDir = Join-Path $env:USERPROFILE '.claude'
$hooksDir  = Join-Path $claudeDir 'hooks'
$settings  = Join-Path $claudeDir 'settings.json'
$MARKER    = 'msys-pathconv-canary'

function Say  ($m) { Write-Host $m }
function Step ($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn ($m) { Write-Host "  ! $m" -ForegroundColor Yellow }
function Ok   ($m) { Write-Host "  + $m" -ForegroundColor Green }
function Skip ($m) { Write-Host "  . $m" -ForegroundColor DarkGray }

# Local fixed disks only: never write canaries to network or cloud-synced drives.
function Get-LocalRoots {
    Get-CimInstance Win32_LogicalDisk -Filter 'DriveType=3' |
        ForEach-Object { $_.DeviceID + '\' } | Sort-Object
}
# Every drive letter that exists is a plausible first path segment (/c/, /d/, ...).
function Get-GuardLetters {
    Get-CimInstance Win32_LogicalDisk |
        ForEach-Object { $_.DeviceID.Substring(0,1).ToLower() } | Sort-Object -Unique
}

# ---------------------------------------------------------------- disarm and exit
if ($Disarm) {
    Step 'Removing canary files'
    foreach ($root in Get-LocalRoots) {
        foreach ($l in Get-GuardLetters) {
            $p = Join-Path $root $l
            if ((Test-Path -LiteralPath $p -PathType Leaf) -and
                ((Get-Content -LiteralPath $p -Raw -EA SilentlyContinue) -match $MARKER)) {
                if ($DryRun) { Say "  would remove $p" }
                else {
                    Set-ItemProperty -LiteralPath $p -Name IsReadOnly -Value $false
                    Remove-Item -LiteralPath $p -Force
                    Ok "removed $p"
                }
            }
        }
    }
    Say ''
    Say 'Canaries removed. The PreToolUse hook is left in place; to remove it, delete the'
    Say "msys_pathconv_guard.py entry from $settings"
    return
}

# ---------------------------------------------------------------- 1. hook payload
Step 'Installing hook scripts'
$payload = Join-Path $kit 'hooks'
if (-not (Test-Path $payload)) { throw "Kit is incomplete: expected $payload" }
if (-not $DryRun) { New-Item -ItemType Directory -Force -Path $hooksDir | Out-Null }

foreach ($src in Get-ChildItem (Join-Path $payload '*.py')) {
    $dst = Join-Path $hooksDir $src.Name
    if ($src.FullName -eq $dst) { Skip "$($src.Name) (running from install target)"; continue }
    $same = (Test-Path $dst) -and
            ((Get-FileHash $src.FullName).Hash -eq (Get-FileHash $dst).Hash)
    if ($same)      { Skip "$($src.Name) already current" }
    elseif ($DryRun){ Say  "  would copy $($src.Name) -> $dst" }
    else            { Copy-Item $src.FullName $dst -Force; Ok "$($src.Name) -> $dst" }
}

if (-not (Get-Command python -EA SilentlyContinue)) {
    Warn "'python' is not on PATH. The hook will not fire until it is."
}

# ---------------------------------------------------------------- 2. settings.json
Step 'Registering PreToolUse(Bash) hook'
$guardPath = Join-Path $hooksDir 'msys_pathconv_guard.py'
$cmdline   = "python `"$guardPath`""

$cfg = @{}
if (Test-Path $settings) {
    $raw = Get-Content $settings -Raw
    if ($raw.Trim()) { $cfg = $raw | ConvertFrom-Json -AsHashtable }
}
if (-not $cfg.ContainsKey('hooks'))                { $cfg['hooks'] = @{} }
if (-not $cfg['hooks'].ContainsKey('PreToolUse'))  { $cfg['hooks']['PreToolUse'] = @() }

$pre   = @($cfg['hooks']['PreToolUse'])
$entry = $pre | Where-Object { $_.matcher -eq 'Bash' } | Select-Object -First 1
if (-not $entry) {
    $entry = @{ matcher = 'Bash'; hooks = @() }
    $pre  += $entry
    $cfg['hooks']['PreToolUse'] = $pre
}
if (-not $entry.ContainsKey('hooks')) { $entry['hooks'] = @() }

if (@($entry['hooks']) | Where-Object { "$($_.command)" -like '*msys_pathconv_guard.py*' }) {
    Skip 'hook already registered'
} elseif ($DryRun) {
    Say "  would add: $cmdline"
} else {
    if (Test-Path $settings) {
        $bak = "$settings.bak-$(Get-Date -Format yyyyMMdd-HHmmss)"
        Copy-Item $settings $bak; Skip "backup -> $bak"
    }
    $entry['hooks'] = @($entry['hooks']) + @{ type = 'command'; command = $cmdline }
    $cfg | ConvertTo-Json -Depth 25 | Set-Content $settings -Encoding utf8
    Ok "registered: $cmdline"
}

# ---------------------------------------------------------------- 3. sweep strays
Step 'Scanning drive roots for stray POSIX-shaped directories'
$letters = Get-GuardLetters
$strays  = @()
foreach ($root in Get-LocalRoots) {
    foreach ($l in $letters) {
        $p = Join-Path $root $l
        if (Test-Path -LiteralPath $p -PathType Container) { $strays += Get-Item -LiteralPath $p -Force }
    }
}
if (-not $strays) { Skip 'none found' }
foreach ($s in $strays) {
    $f = Get-ChildItem -LiteralPath $s.FullName -Recurse -File -Force -EA SilentlyContinue
    $n = ($f | Measure-Object).Count
    $b = [math]::Round((($f | Measure-Object -Property Length -Sum).Sum) / 1KB, 1)
    Warn "$($s.FullName)  ($n files, $b KB, created $($s.CreationTime))"
    if (-not $Quarantine) { continue }
    $dest = Join-Path $Quarantine ("{0}_{1}" -f $s.FullName.Substring(0,1), $s.Name)
    if ($DryRun) { Say "  would move -> $dest"; continue }
    New-Item -ItemType Directory -Force -Path $Quarantine | Out-Null
    if (Test-Path -LiteralPath $dest) { $dest = "$dest-$(Get-Date -Format yyyyMMdd-HHmmss)" }
    Move-Item -LiteralPath $s.FullName -Destination $dest
    Ok "moved -> $dest"
}
if ($strays -and -not $Quarantine) {
    Say '  (re-run with -Quarantine <path> to move these aside; nothing is ever deleted)'
}

# ---------------------------------------------------------------- 4. arm canaries
if ($NoCanary) { Step 'Canaries skipped (-NoCanary)' }
else {
    Step 'Arming canary files at drive roots'
    $body = @"
$MARKER

Intentional zero-risk guard file. A file and a directory cannot share a name, so this
file makes it IMPOSSIBLE to create a directory here by the same name.

It exists because Git Bash hands an unconverted POSIX path such as /c/projects/x to a
native Windows binary, which resolves the leading "/" against the current drive and
silently creates <drive>:\c\projects\x. With this file present that write fails loudly
at the point of the bug instead of scattering junk at the drive root.

Remove with:  .\install.ps1 -Disarm
"@
    foreach ($root in Get-LocalRoots) {
        foreach ($l in $letters) {
            $p = Join-Path $root $l
            if (Test-Path -LiteralPath $p -PathType Container) { Warn "$p is still a directory - skipped"; continue }
            if (Test-Path -LiteralPath $p -PathType Leaf)      { Skip  "$p already armed"; continue }
            if ($DryRun) { Say "  would arm $p"; continue }
            try {
                Set-Content -LiteralPath $p -Value $body -Encoding utf8 -NoNewline
                Set-ItemProperty -LiteralPath $p -Name IsReadOnly -Value $true
                Ok "armed $p"
            } catch {
                Warn "could not arm $p ($($_.Exception.Message.Split([char]10)[0]))"
            }
        }
    }
}

# ---------------------------------------------------------------- verify
Step 'Verifying the installed guard'
$stress = Join-Path $kit 'tests\stress_test.py'
if ((Test-Path $stress) -and (Get-Command python -EA SilentlyContinue) -and -not $DryRun) {
    $out = & python $stress $guardPath 2>&1
    $last = "$($out | Select-Object -Last 2 | Select-Object -First 1)".Trim()
    if ($last -eq 'ALL STRESS TESTS PASSED') { Ok $last } else { Warn $last; $out }
} else { Skip 'stress suite not run' }

Say ''
Say 'Done. Restart Claude Code on this node so it re-reads settings.json.'
Say 'Portable path forms that work in BOTH bash and native binaries:'
Say '    C:/projects/x                 (instead of /c/projects/x)'
Say '    "$(cygpath -m "$PWD")/x"      (instead of "$PWD/x")'
