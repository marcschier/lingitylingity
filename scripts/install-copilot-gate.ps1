#requires -Version 7.2
<#
.SYNOPSIS
Previews, enables, disables, or rolls back the user-global Lingity integration.
.DESCRIPTION
Supply a verified, non-editable staged Python installation and local NLTK data.
The default Preview mode does not create files or execute the runtime. Enable
performs a real gate check before replacing any integration file. No runtime,
launcher, PATH entry, unrelated hook, or settings file is changed.
Disable removes the current owned integration without restoring older versions.
Rollback restores the preceding version, which can leave the hook enabled.
.EXAMPLE
.\scripts\install-copilot-gate.ps1 -Python C:\Lingity\v2\Scripts\python.exe -CorpusRoot C:\Lingity\nltk_data
.EXAMPLE
.\scripts\install-copilot-gate.ps1 -Mode Enable -Python C:\Lingity\v2\Scripts\python.exe -CorpusRoot C:\Lingity\nltk_data
.EXAMPLE
.\scripts\install-copilot-gate.ps1 -Mode Rollback
.EXAMPLE
.\scripts\install-copilot-gate.ps1 -Mode Disable
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'Medium')]
param(
    [ValidateSet('Preview', 'Enable', 'Disable', 'Rollback')]
    [string] $Mode = 'Preview',
    [string] $Python,
    [string] $CorpusRoot,
    [string] $StateRoot,
    [string] $CopilotHome
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Owner = 'lingity-copilot-gate'
$Utf8 = [System.Text.UTF8Encoding]::new($false, $true)
$RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TemplateRoot = Join-Path $RepositoryRoot 'integrations\copilot'

function Get-AbsolutePath([string] $Value, [string] $Label) {
    if ([string]::IsNullOrWhiteSpace($Value) -or
        -not [System.IO.Path]::IsPathFullyQualified($Value)) {
        throw "$Label must be an absolute path."
    }
    if ($Value -match '[*?]' -or $Value -match '^\\\\[?.]\\' -or
        ($Value.Length -gt 2 -and $Value.Substring(2).Contains(':'))) {
        throw "$Label contains an unsupported wildcard, device path, or alternate data stream."
    }
    return [System.IO.Path]::TrimEndingDirectorySeparator([System.IO.Path]::GetFullPath($Value))
}

function Assert-PlainPath([string] $Path) {
    $Cursor = $Path
    while ($Cursor) {
        if (Test-Path -LiteralPath $Cursor) {
            $Item = Get-Item -LiteralPath $Cursor -Force
            if ($Item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) {
                throw "Refusing a symbolic link or junction in managed path: $Cursor"
            }
        }
        $Cursor = [System.IO.Path]::GetDirectoryName($Cursor)
    }
}

function Test-Within([string] $Path, [string] $Root) {
    return $Path.Equals($Root, [System.StringComparison]::OrdinalIgnoreCase) -or
        $Path.StartsWith(
            $Root + [System.IO.Path]::DirectorySeparatorChar,
            [System.StringComparison]::OrdinalIgnoreCase
        )
}

function Get-Hash([byte[]] $Bytes) {
    return [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($Bytes)).ToLowerInvariant()
}

function Get-FileHashExact([string] $Path) {
    Assert-PlainPath $Path
    if (-not [System.IO.File]::Exists($Path)) {
        throw "Expected an unchanged owned file, but it is missing or not a file: $Path"
    }
    return Get-Hash ([System.IO.File]::ReadAllBytes($Path))
}

function ConvertTo-Bytes($Value) {
    return ,$Utf8.GetBytes(($Value | ConvertTo-Json -Depth 20) + "`n")
}

function Read-Json([string] $Path) {
    Assert-PlainPath $Path
    return [System.IO.File]::ReadAllText($Path, $Utf8) | ConvertFrom-Json -AsHashtable
}

function Write-Atomic([string] $Path, [byte[]] $Bytes) {
    Assert-PlainPath $Path
    $Temporary = "$Path.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $Stream = [System.IO.File]::Open(
            $Temporary, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None
        )
        try {
            $Stream.Write($Bytes, 0, $Bytes.Length)
            $Stream.Flush($true)
        }
        finally {
            $Stream.Dispose()
        }
        [System.IO.File]::Move($Temporary, $Path, $true)
    }
    finally {
        if ([System.IO.File]::Exists($Temporary)) {
            [System.IO.File]::Delete($Temporary)
        }
    }
}

function Assert-Manifest($Manifest) {
    if ($Manifest.schemaVersion -ne 1 -or $Manifest.owner -cne $Owner -or
        $Manifest.revision -cnotmatch '^[a-f0-9]{32}$' -or
        ($null -ne $Manifest.previousRevision -and
            $Manifest.previousRevision -cnotmatch '^[a-f0-9]{32}$') -or
        $Manifest.copilotHome -ine $CopilotHome -or
        $Manifest.stateRoot -ine $StateRoot -or $Manifest.files.Count -ne 2) {
        throw 'The ownership manifest is invalid or belongs to different integration paths.'
    }
    foreach ($Kind in @('instructions', 'hook')) {
        $Entries = @($Manifest.files | Where-Object { $_.kind -ceq $Kind })
        if ($Entries.Count -ne 1 -or $Entries[0].path -ine $Targets[$Kind] -or
            $Entries[0].sha256 -cnotmatch '^[a-f0-9]{64}$') {
            throw "The ownership manifest has an invalid $Kind entry."
        }
    }
}

function Get-ActiveManifest {
    if (-not (Test-Path -LiteralPath $ActivePath)) {
        foreach ($Path in $Targets.Values) {
            Assert-PlainPath $Path
            if (Test-Path -LiteralPath $Path) {
                throw "Refusing to overwrite an unowned integration file: $Path"
            }
        }
        return $null
    }
    $Manifest = Read-Json $ActivePath
    Assert-Manifest $Manifest
    foreach ($Entry in $Manifest.files) {
        if ((Get-FileHashExact $Entry.path) -cne $Entry.sha256) {
            throw "Refusing to change a locally modified owned integration file: $($Entry.path)"
        }
    }
    $SavedPath = Join-Path $InstallerRoot "revisions\$($Manifest.revision)\manifest.json"
    if ((Get-FileHashExact $ActivePath) -cne (Get-FileHashExact $SavedPath)) {
        throw 'The active ownership manifest differs from its saved revision.'
    }
    return $Manifest
}

function Get-RevisionContent($Manifest) {
    Assert-Manifest $Manifest
    $Content = @{}
    foreach ($Entry in $Manifest.files) {
        $Path = Join-Path $InstallerRoot "revisions\$($Manifest.revision)\$($Entry.kind).backup"
        if ((Get-FileHashExact $Path) -cne $Entry.sha256) {
            throw "The saved $($Entry.kind) backup has changed; refusing rollback."
        }
        $Content[$Entry.kind] = [System.IO.File]::ReadAllBytes($Path)
    }
    return $Content
}

function Invoke-Runtime([string[]] $Arguments, [int] $TimeoutSeconds = 60) {
    $Start = [System.Diagnostics.ProcessStartInfo]::new()
    $Start.FileName = $Python
    $Start.WorkingDirectory = $RuntimeRoot
    $Start.UseShellExecute = $false
    $Start.RedirectStandardOutput = $true
    $Start.RedirectStandardError = $true
    $Start.Environment['NLTK_DATA'] = $CorpusRoot
    foreach ($Argument in $Arguments) {
        $Start.ArgumentList.Add($Argument)
    }
    $Process = [System.Diagnostics.Process]::new()
    $Process.StartInfo = $Start
    try {
        if (-not $Process.Start()) {
            throw 'The staged Python process did not start.'
        }
        $OutputTask = $Process.StandardOutput.ReadToEndAsync()
        $ErrorTask = $Process.StandardError.ReadToEndAsync()
        if (-not $Process.WaitForExit($TimeoutSeconds * 1000)) {
            $Process.Kill($true)
            $Process.WaitForExit()
            throw "The staged Python health check exceeded $TimeoutSeconds seconds."
        }
        $Output = $OutputTask.GetAwaiter().GetResult()
        $Errors = $ErrorTask.GetAwaiter().GetResult()
        if ($Process.ExitCode -ne 0) {
            throw "Staged Python failed with exit $($Process.ExitCode): $($Errors.Trim()) $($Output.Trim())"
        }
        try {
            return $Output | ConvertFrom-Json -AsHashtable
        }
        catch {
            throw "Staged Python did not return a valid JSON health result: $($_.Exception.Message)"
        }
    }
    finally {
        $Process.Dispose()
    }
}

function Assert-RuntimeHealth {
    $Probe = @'
import importlib.metadata
import json
from pathlib import Path
import sys
import lingity
import lingity.copilot_hook
distribution = importlib.metadata.distribution("lingity")
direct = json.loads(distribution.read_text("direct_url.json") or "{}")
prefix = Path(sys.prefix).resolve()
package = Path(lingity.__file__).resolve()
if direct.get("dir_info", {}).get("editable") or not package.is_relative_to(prefix):
    raise RuntimeError("Lingity must be installed non-editably inside the staged Python prefix")
print(json.dumps({"python": str(Path(sys.executable).resolve()), "prefix": str(prefix), "package": str(package), "version": distribution.version}))
'@
    $Identity = Invoke-Runtime @('-I', '-B', '-c', $Probe)
    if ((Get-AbsolutePath $Identity.python 'Runtime interpreter') -ine $Python -or
        -not (Test-Within $RuntimeRoot (Get-AbsolutePath $Identity.prefix 'Runtime prefix'))) {
        throw 'The staged interpreter returned an unexpected executable or runtime prefix.'
    }
    if (Test-Within $Identity.package $RepositoryRoot) {
        throw 'The gate must use an installed package, not the repository checkout.'
    }
    $SamplePath = Join-Path ([System.IO.Path]::GetTempPath()) "lingity-gate-health-$([guid]::NewGuid().ToString('N')).txt"
    $SampleCreated = $false
    try {
        $Stream = [System.IO.File]::Open(
            $SamplePath, [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write, [System.IO.FileShare]::None
        )
        $SampleCreated = $true
        try {
            $Bytes = $Utf8.GetBytes("The service records each request. The operator reviews the report.`n")
            $Stream.Write($Bytes, 0, $Bytes.Length)
        }
        finally {
            $Stream.Dispose()
        }
        $Result = Invoke-Runtime @('-I', '-m', 'lingity', 'gate', 'check', $SamplePath)
        if (-not $Result.ContainsKey('accepted') -or $Result.accepted -isnot [bool] -or -not $Result.accepted) {
            throw 'The real synthetic gate check did not return accepted: true.'
        }
    }
    finally {
        if ($SampleCreated) {
            [System.IO.File]::Delete($SamplePath)
        }
    }
    return $Identity
}

if (-not $IsWindows) {
    throw 'This installer supports PowerShell 7.2 or later on Windows.'
}
if ([string]::IsNullOrWhiteSpace($CopilotHome)) {
    $CopilotHome = if ($env:COPILOT_HOME) { $env:COPILOT_HOME } else { Join-Path $env:USERPROFILE '.copilot' }
}
if ([string]::IsNullOrWhiteSpace($StateRoot)) {
    $StateRoot = Join-Path $env:LOCALAPPDATA 'Lingity\gate'
}
$CopilotHome = Get-AbsolutePath $CopilotHome 'CopilotHome'
$StateRoot = Get-AbsolutePath $StateRoot 'StateRoot'
if (Test-Within $StateRoot $RepositoryRoot) {
    throw 'StateRoot must be outside the repository checkout.'
}
$InstallerRoot = Join-Path $StateRoot 'installer'
$ActivePath = Join-Path $InstallerRoot 'active.json'
$Targets = [ordered]@{
    instructions = Join-Path $CopilotHome 'instructions\lingity.instructions.md'
    hook = Join-Path $CopilotHome 'hooks\lingity.json'
}
Assert-PlainPath $StateRoot
Assert-PlainPath $CopilotHome
Assert-PlainPath $InstallerRoot
$Current = Get-ActiveManifest
$Desired = @{}
$RuntimeRoot = $null
if ($Mode -in @('Preview', 'Enable')) {
    $Python = Get-AbsolutePath $Python 'Python'
    $CorpusRoot = Get-AbsolutePath $CorpusRoot 'CorpusRoot'
    Assert-PlainPath $Python
    Assert-PlainPath $CorpusRoot
    if (-not [System.IO.File]::Exists($Python) -or
        [System.IO.Path]::GetExtension($Python) -ine '.exe' -or
        -not [System.IO.Directory]::Exists($CorpusRoot)) {
        throw 'Python must name an existing executable and CorpusRoot an existing local data directory.'
    }
    $RuntimeRoot = [System.IO.Path]::GetDirectoryName($Python)
    if ([System.IO.Path]::GetFileName($RuntimeRoot) -ieq 'Scripts') {
        $RuntimeRoot = [System.IO.Path]::GetDirectoryName($RuntimeRoot)
    }
    if (Test-Within $RuntimeRoot $RepositoryRoot) {
        throw 'The staged runtime and hook working directory must be outside the repository.'
    }
    $Template = Read-Json (Join-Path $TemplateRoot 'lingity.hooks.template.json')
    $Configuration = [ordered]@{ version = $Template.version; hooks = [ordered]@{} }
    foreach ($Event in $Template.hooks.Keys) {
        $Command = $Template.commandTemplate | ConvertTo-Json -Depth 10 | ConvertFrom-Json -AsHashtable
        $Command.exec = $Python
        $Command.cwd = $RuntimeRoot
        $Command.env.NLTK_DATA = $CorpusRoot
        $Command.args = @($Command.args | ForEach-Object {
            switch -CaseSensitive ($_) {
                '__EVENT__' { $Event }
                '__STATE_ROOT__' { $StateRoot }
                default { $_ }
            }
        })
        $Configuration.hooks[$Event] = @($Command)
    }
    $Desired.hook = ConvertTo-Bytes $Configuration
    $Desired.instructions = [System.IO.File]::ReadAllBytes((Join-Path $TemplateRoot 'lingity.instructions.md'))
}
$Plan = [ordered]@{
    mode = $Mode
    copilotHome = $CopilotHome
    stateRoot = $StateRoot
    hookPath = $Targets.hook
    instructionPath = $Targets.instructions
    ownershipPath = $ActivePath
    python = $Python
    runtimeCwd = $RuntimeRoot
    corpusRoot = $CorpusRoot
    activeRevision = if ($Current) { $Current.revision } else { $null }
}
if ($Mode -eq 'Preview') {
    $Plan['status'] = 'preview-only; runtime health is checked on Enable'
    [pscustomobject]$Plan
    return
}
if ($Mode -in @('Disable', 'Rollback') -and -not $Current) {
    $Plan['status'] = 'not-enabled; no changes'
    [pscustomobject]$Plan
    return
}
if (-not $PSCmdlet.ShouldProcess($CopilotHome, "$Mode the dedicated Lingity hook and instructions")) {
    [pscustomobject]$Plan
    return
}
$Identity = if ($Mode -eq 'Enable') { Assert-RuntimeHealth } else { $null }
[System.IO.Directory]::CreateDirectory($InstallerRoot) | Out-Null
$LockPath = Join-Path $InstallerRoot 'installer.lock'
Assert-PlainPath $LockPath
$Lock = [System.IO.File]::Open(
    $LockPath, [System.IO.FileMode]::OpenOrCreate,
    [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None
)
try {
    $Current = Get-ActiveManifest
    if ($Mode -in @('Disable', 'Rollback') -and -not $Current) {
        $Plan['status'] = 'not-enabled; no changes'
        [pscustomobject]$Plan
        return
    }
    $CurrentContent = if ($Current) { Get-RevisionContent $Current } else { @{} }
    $Next = $null
    if ($Mode -eq 'Enable') {
        if ($Current -and @($Current.files | Where-Object {
            $_.sha256 -cne (Get-Hash $Desired[$_.kind])
        }).Count -eq 0) {
            $Plan['status'] = 'already-enabled; unchanged'
            [pscustomobject]$Plan
            return
        }
        $Revision = [guid]::NewGuid().ToString('N')
        $Next = [ordered]@{
            schemaVersion = 1
            owner = $Owner
            revision = $Revision
            previousRevision = if ($Current) { $Current.revision } else { $null }
            copilotHome = $CopilotHome
            stateRoot = $StateRoot
            runtime = $Identity
            files = @(
                foreach ($Kind in $Targets.Keys) {
                    [ordered]@{ kind = $Kind; path = $Targets[$Kind]; sha256 = Get-Hash $Desired[$Kind] }
                }
            )
        }
        $RevisionRoot = Join-Path $InstallerRoot "revisions\$Revision"
        Assert-PlainPath $RevisionRoot
        [System.IO.Directory]::CreateDirectory($RevisionRoot) | Out-Null
        foreach ($Kind in $Targets.Keys) {
            Write-Atomic (Join-Path $RevisionRoot "$Kind.backup") $Desired[$Kind]
        }
        Write-Atomic (Join-Path $RevisionRoot 'manifest.json') (ConvertTo-Bytes $Next)
    }
    elseif ($Mode -eq 'Rollback' -and $Current.previousRevision) {
        $Next = Read-Json (Join-Path $InstallerRoot "revisions\$($Current.previousRevision)\manifest.json")
        if ($Next.revision -cne $Current.previousRevision) {
            throw 'The rollback revision does not match the active ownership record.'
        }
        $Desired = Get-RevisionContent $Next
    }
    $Changed = [System.Collections.Generic.List[string]]::new()
    try {
        foreach ($Kind in $Targets.Keys) {
            $Path = $Targets[$Kind]
            Assert-PlainPath $Path
            if ($Current) {
                $Entry = @($Current.files | Where-Object { $_.kind -ceq $Kind })[0]
                if ((Get-FileHashExact $Path) -cne $Entry.sha256) {
                    throw "The owned file changed during installation: $Path"
                }
            }
            elseif (Test-Path -LiteralPath $Path) {
                throw "An unowned file appeared during installation: $Path"
            }
            if ($Next) {
                [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($Path)) | Out-Null
                Write-Atomic $Path $Desired[$Kind]
            }
            else {
                [System.IO.File]::Delete($Path)
            }
            $Changed.Add($Kind)
        }
        if ($Next) {
            Write-Atomic $ActivePath (ConvertTo-Bytes $Next)
        }
        else {
            [System.IO.File]::Delete($ActivePath)
        }
    }
    catch {
        $Failure = $_
        foreach ($Kind in $Changed) {
            $Path = $Targets[$Kind]
            if ($Next -and (Get-FileHashExact $Path) -cne (Get-Hash $Desired[$Kind])) {
                throw "Integration update failed and $Path changed concurrently. Backups remain in $InstallerRoot. Original error: $Failure"
            }
            if (-not $Next -and (Test-Path -LiteralPath $Path)) {
                throw "Integration rollback failed and $Path appeared concurrently. Backups remain in $InstallerRoot. Original error: $Failure"
            }
            if ($Current) {
                Write-Atomic $Path $CurrentContent[$Kind]
            }
            else {
                [System.IO.File]::Delete($Path)
            }
        }
        throw $Failure
    }
    $Plan['status'] = if ($Next) {
        "$Mode complete; restart Copilot to load this revision"
    }
    elseif ($Mode -eq 'Disable') {
        'Disable complete; dedicated integration removed; restart Copilot'
    }
    else {
        'rollback complete; dedicated integration removed'
    }
    $Plan['activeRevision'] = if ($Next) { $Next.revision } else { $null }
    [pscustomobject]$Plan
}
finally {
    $Lock.Dispose()
}
