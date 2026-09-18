#requires -Version 7.2
<#
.SYNOPSIS
Exercises the installer against disposable homes and a supplied staged runtime.
.DESCRIPTION
Requires the same verified non-editable Python and corpus root as the installer.
No real Copilot home is used. Temporary files are individually deleted afterward.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string] $Python,
    [Parameter(Mandatory)]
    [string] $CorpusRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$Installer = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..\scripts\install-copilot-gate.ps1'))
$Root = Join-Path ([System.IO.Path]::GetTempPath()) "lingity-installer-test-$([guid]::NewGuid().ToString('N'))"
$Utf8 = [System.Text.UTF8Encoding]::new($false)

function Assert([bool] $Condition, [string] $Message) {
    if (-not $Condition) {
        throw $Message
    }
}

function Assert-Rejected([scriptblock] $Action, [string] $Pattern) {
    $Failure = $null
    try {
        & $Action | Out-Null
    }
    catch {
        $Failure = $_
    }
    Assert ($null -ne $Failure) "Expected a rejection matching: $Pattern"
    Assert ($Failure.Exception.Message -match $Pattern) "Unexpected rejection: $Failure"
}

function Hash([string] $Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
}

function Snapshot([string] $Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return ''
    }
    return (@(Get-ChildItem -LiteralPath $Path -Recurse -Force -File |
        Sort-Object FullName |
        ForEach-Object { "$($_.FullName) $(Hash $_.FullName) $($_.LastWriteTimeUtc.Ticks)" }) -join "`n")
}

$Tokens = $null
$Errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($Installer, [ref]$Tokens, [ref]$Errors) | Out-Null
Assert ($Errors.Count -eq 0) "Installer parse errors: $Errors"
[System.IO.Directory]::CreateDirectory($Root) | Out-Null
try {
    $HomePath = Join-Path $Root 'copilot home & [literal]'
    $StatePath = Join-Path $Root 'gate state & [literal]'
    $Arguments = @{
        Python = $Python
        CorpusRoot = $CorpusRoot
        CopilotHome = $HomePath
        StateRoot = $StatePath
    }
    $Before = Snapshot $Root
    $Preview = & $Installer @Arguments
    Assert ($Preview.mode -eq 'Preview') 'Default mode is not Preview.'
    Assert ((Snapshot $Root) -ceq $Before) 'Preview mutated the disposable workspace.'
    & $Installer @Arguments -Mode Enable -WhatIf | Out-Null
    Assert ((Snapshot $Root) -ceq $Before) 'WhatIf mutated the disposable workspace.'
    $OldHome = $env:COPILOT_HOME
    try {
        $env:COPILOT_HOME = Join-Path $Root 'environment home'
        $EnvironmentPreview = & $Installer -Python $Python -CorpusRoot $CorpusRoot -StateRoot $StatePath
        Assert ($EnvironmentPreview.copilotHome -ceq $env:COPILOT_HOME) 'COPILOT_HOME was not respected.'
    }
    finally {
        $env:COPILOT_HOME = $OldHome
    }
    [System.IO.Directory]::CreateDirectory((Join-Path $HomePath 'hooks')) | Out-Null
    [System.IO.Directory]::CreateDirectory((Join-Path $HomePath 'instructions')) | Out-Null
    $Unrelated = Join-Path $HomePath 'settings.json'
    $OtherHook = Join-Path $HomePath 'hooks\unrelated.json'
    $OtherInstructions = Join-Path $HomePath 'instructions\unrelated.instructions.md'
    [System.IO.File]::WriteAllText($Unrelated, '{"unrelated":true}', $Utf8)
    [System.IO.File]::WriteAllText($OtherHook, '{"version":1,"hooks":{}}', $Utf8)
    [System.IO.File]::WriteAllText($OtherInstructions, 'Existing instructions.', $Utf8)
    $UnrelatedHashes = @{}
    foreach ($Path in @($Unrelated, $OtherHook, $OtherInstructions)) {
        $UnrelatedHashes[$Path] = Hash $Path
    }
    $Hook = Join-Path $HomePath 'hooks\lingity.json'
    $Instructions = Join-Path $HomePath 'instructions\lingity.instructions.md'
    foreach ($Path in @($Hook, $Instructions)) {
        [System.IO.File]::WriteAllText($Path, 'Unowned content', $Utf8)
        $Unowned = Snapshot $Root
        Assert-Rejected { & $Installer @Arguments -Mode Enable } 'unowned integration'
        Assert ((Snapshot $Root) -ceq $Unowned) 'An unowned-file rejection changed files.'
        [System.IO.File]::Delete($Path)
    }
    $Enabled = & $Installer @Arguments -Mode Enable
    Assert ($Enabled.status -like 'Enable complete*') 'Enable did not finish.'
    $Active = Join-Path $StatePath 'installer\active.json'
    $Manifest = Get-Content -LiteralPath $Active -Raw | ConvertFrom-Json
    $Config = Get-Content -LiteralPath $Hook -Raw | ConvertFrom-Json
    $Events = @('sessionStart', 'userPromptSubmitted', 'preToolUse', 'postToolUse', 'postToolUseFailure', 'agentStop', 'subagentStop')
    Assert (@($Config.hooks.PSObject.Properties).Count -eq $Events.Count) 'Unexpected hook event set.'
    foreach ($Event in $Events) {
        $Command = $Config.hooks.$Event[0]
        Assert ($Config.hooks.$Event.Count -eq 1) "Unexpected hook count for $Event."
        Assert ($Command.exec -ieq $Python) 'Hook executable differs from the supplied Python.'
        $Expected = @('-I', '-m', 'lingity.copilot_hook', '--event', $Event, '--state-dir', $StatePath, '--timeout-seconds', '40')
        Assert (($Command.args | ConvertTo-Json -Compress) -ceq ($Expected | ConvertTo-Json -Compress)) "Invalid arguments for $Event."
        Assert ($Command.env.NLTK_DATA -ieq $CorpusRoot) 'Corpus root was not preserved.'
        Assert ($Command.timeoutSec -eq 60) 'Outer timeout must be 60 seconds.'
        Assert ($Command.type -ceq 'command') 'Hook type must be command.'
        Assert ($null -eq $Command.PSObject.Properties['powershell']) 'Unexpected shell interpolation.'
    }
    $EnabledSnapshot = Snapshot $HomePath
    $ActiveHash = Hash $Active
    $BrokenPython = Join-Path $Root 'broken-runtime.exe'
    [System.IO.File]::WriteAllBytes($BrokenPython, [byte[]]::new(0))
    Assert-Rejected { & $Installer @Arguments -Mode Enable -Python $BrokenPython } '.+'
    Assert ((Snapshot $HomePath) -ceq $EnabledSnapshot) 'A failed runtime replaced the working integration.'
    Assert ((Hash $Active) -ceq $ActiveHash) 'A failed runtime changed the ownership revision.'
    $Again = & $Installer @Arguments -Mode Enable
    Assert ($Again.status -like 'already-enabled*') 'Repeated enable was not idempotent.'
    Assert ((Snapshot $HomePath) -ceq $EnabledSnapshot) 'Repeated enable rewrote integration files.'
    Assert ((Hash $Active) -ceq $ActiveHash) 'Repeated enable changed the ownership revision.'
    foreach ($Path in @($Hook, $Instructions)) {
        $Original = [System.IO.File]::ReadAllBytes($Path)
        try {
            [System.IO.File]::AppendAllText($Path, "`nLocal change", $Utf8)
            $Modified = Snapshot $Root
            Assert-Rejected { & $Installer @Arguments -Mode Enable } 'locally modified'
            Assert-Rejected { & $Installer @Arguments -Mode Disable } 'locally modified'
            Assert-Rejected { & $Installer @Arguments -Mode Rollback } 'locally modified'
            Assert ((Snapshot $Root) -ceq $Modified) 'Modified owned content was overwritten.'
        }
        finally {
            [System.IO.File]::WriteAllBytes($Path, $Original)
        }
    }
    $Backup = Join-Path $StatePath "installer\revisions\$($Manifest.revision)\hook.backup"
    $OriginalBackup = [System.IO.File]::ReadAllBytes($Backup)
    try {
        [System.IO.File]::AppendAllText($Backup, 'Changed backup', $Utf8)
        Assert-Rejected { & $Installer @Arguments -Mode Rollback } 'backup has changed'
        Assert ((Hash $Active) -ceq $ActiveHash) 'A corrupt backup changed the active revision.'
    }
    finally {
        [System.IO.File]::WriteAllBytes($Backup, $OriginalBackup)
    }
    $AlternativeCorpus = $CorpusRoot.ToUpperInvariant()
    if ($AlternativeCorpus -ceq $CorpusRoot) {
        $AlternativeCorpus = $CorpusRoot.ToLowerInvariant()
    }
    $Upgraded = & $Installer @Arguments -Mode Enable -CorpusRoot $AlternativeCorpus
    Assert ($Upgraded.activeRevision -cne $Manifest.revision) 'Changed integration did not get a new revision.'
    & $Installer @Arguments -Mode Rollback | Out-Null
    Assert ((Hash $Active) -ceq $ActiveHash) 'Rollback did not restore the previous ownership revision.'
    foreach ($Entry in $Manifest.files) {
        Assert ((Hash $Entry.path) -ieq $Entry.sha256) 'Rollback did not restore exact prior bytes.'
    }
    & $Installer @Arguments -Mode Rollback | Out-Null
    Assert (-not [System.IO.File]::Exists($Hook)) 'Final rollback left the owned hook.'
    Assert (-not [System.IO.File]::Exists($Instructions)) 'Final rollback left the owned instructions.'
    Assert (-not [System.IO.File]::Exists($Active)) 'Final rollback left active ownership.'
    $RolledBack = Snapshot $Root
    & $Installer @Arguments -Mode Rollback | Out-Null
    Assert ((Snapshot $Root) -ceq $RolledBack) 'Repeated rollback mutated state.'
    $Enabled = & $Installer @Arguments -Mode Enable
    $Upgraded = & $Installer @Arguments -Mode Enable -CorpusRoot $AlternativeCorpus
    Assert ($Upgraded.activeRevision -cne $Enabled.activeRevision) 'Disable test needs two owned revisions.'
    $BeforeDisable = Snapshot $Root
    $ControlArguments = @{ CopilotHome = $HomePath; StateRoot = $StatePath }
    & $Installer @ControlArguments -Mode Disable -WhatIf | Out-Null
    Assert ((Snapshot $Root) -ceq $BeforeDisable) 'Disable WhatIf mutated state.'
    $Retained = Join-Path $StatePath 'retained-baseline.bin'
    [System.IO.File]::WriteAllText($Retained, 'Frozen document bytes', $Utf8)
    $RetainedHash = Hash $Retained
    $RevisionRoot = Join-Path $StatePath 'installer\revisions'
    $RevisionSnapshot = Snapshot $RevisionRoot
    $Disabled = & $Installer @ControlArguments -Mode Disable
    Assert ($Disabled.status -like 'Disable complete*') 'Disable did not finish.'
    Assert (-not [System.IO.File]::Exists($Hook)) 'Disable restored an older hook.'
    Assert (-not [System.IO.File]::Exists($Instructions)) 'Disable left the owned instructions.'
    Assert (-not [System.IO.File]::Exists($Active)) 'Disable left active ownership.'
    Assert ((Hash $Retained) -ceq $RetainedHash) 'Disable changed retained document state.'
    Assert ((Snapshot $RevisionRoot) -ceq $RevisionSnapshot) 'Disable changed revision archives.'
    $DisabledSnapshot = Snapshot $Root
    $Again = & $Installer @ControlArguments -Mode Disable
    Assert ($Again.status -eq 'not-enabled; no changes') 'Repeated disable was not idempotent.'
    Assert ((Snapshot $Root) -ceq $DisabledSnapshot) 'Repeated disable mutated state.'
    & $Installer @Arguments -Mode Enable | Out-Null
    Assert ([System.IO.File]::Exists($Hook)) 'Enable after disable did not restore the hook.'
    Assert ([System.IO.File]::Exists($Instructions)) 'Enable after disable did not restore instructions.'
    Assert ((Hash $Retained) -ceq $RetainedHash) 'Re-enabling changed retained document state.'
    & $Installer @ControlArguments -Mode Disable | Out-Null
    foreach ($Path in $UnrelatedHashes.Keys) {
        Assert ((Hash $Path) -ceq $UnrelatedHashes[$Path]) "Unrelated file changed: $Path"
    }
    'Installer smoke passed: preview, WhatIf, ownership, idempotency, upgrade, rollback, disable, re-enable, unrelated-file preservation.'
}
finally {
    foreach ($File in Get-ChildItem -LiteralPath $Root -File -Recurse -Force) {
        [System.IO.File]::Delete($File.FullName)
    }
    foreach ($Directory in Get-ChildItem -LiteralPath $Root -Directory -Recurse -Force |
        Sort-Object { $_.FullName.Length } -Descending) {
        [System.IO.Directory]::Delete($Directory.FullName)
    }
    [System.IO.Directory]::Delete($Root)
}
