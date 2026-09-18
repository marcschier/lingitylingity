# Copilot hook controls

You must run the commands below from the repository root.
You must use PowerShell 7.2 or later on Windows.
The [authoring guide](../../docs/specification-authoring-gate.md) defines the rules.
It explains repairs and when to ask the user.
It also states what hooks can enforce.
This page covers installation controls and threshold changes.

## Repository contents

The repository contains the gate code and the reusable integration.
It does not contain virtual environments or local document state.

| Path | Purpose |
|---|---|
| `lingity\gate.py` | Evaluates documents against the policy. |
| `lingity\gate_markdown.py` | Locates prose and table cells. |
| `lingity\gate_state.py` | Retains frozen drafts and tracks approved writes. |
| `lingity\copilot_tools.py` | Reconstructs proposed file edits. |
| `lingity\copilot_hook.py` | Handles Copilot events and bounded workers. |
| `lingity\cli.py` | Exposes `gate check` and `gate hook`. |
| `lingity\schemas\v1\gate-*.schema.json` | Defines policy and result formats. |
| `scripts\install-copilot-gate.ps1` | Manages the two owned integration files. |
| `integrations\copilot\lingity.hooks.template.json` | Defines hook events and command arguments. |
| `integrations\copilot\lingity.instructions.md` | Guides model repairs and wording decisions. |
| `integrations\copilot\test-installer.ps1` | Exercises the installer in disposable homes. |
| `tests\test_gate*.py`, `tests\test_copilot*.py` | Cover evaluation, state, tools, and hooks. |
| `tests\fixtures\copilot-hooks.json` | Records sanitized host payloads. |

The wheel contains the Python package, profiles, and schemas.
The installer and integration templates remain repository files.
You must keep `scripts` and `integrations` beside each other when copying them.
You must keep private drafts, transcripts, and machine paths outside Git.

## Existing installation

The deployed setup keeps a runtime pointer under `%LOCALAPPDATA%\Lingity`.
The following commands read that pointer for the current account:

```powershell
$root = Join-Path $env:LOCALAPPDATA 'Lingity'
$deployment = Get-Content -LiteralPath (Join-Path $root 'ACTIVE-GATE.json') -Raw | ConvertFrom-Json
$python = Join-Path $deployment.release 'venv\Scripts\python.exe'
$corpus = Join-Path $deployment.release 'venv\share\nltk_data'
Get-Content -LiteralPath $deployment.manifest
```

That pointer records the selected runtime. It is not an enabled-status flag.
The installer owns `gate\installer\active.json` under the same root.
That ownership record and its two unchanged files identify an enabled setup.
Disable removes the ownership record but retains the runtime pointer.
A fresh setup uses its own reviewed interpreter and corpus paths instead.

## Disabling the hook

The first command previews removal. The second removes only Lingity's
hook and instructions:

```powershell
.\scripts\install-copilot-gate.ps1 -Mode Disable -WhatIf
.\scripts\install-copilot-gate.ps1 -Mode Disable
```

You must restart existing Copilot processes after disabling.
The command leaves other hooks, settings, and instructions unchanged.
It retains the runtime, CLI launcher, frozen drafts, and revision backups.
It requires no Python argument and does not run the interpreter.
Repeated disable calls make no further changes.
The command refuses to remove owned files that someone has edited.

You must supply the original `-CopilotHome` and `-StateRoot` values.
Without those options, the installer honors `COPILOT_HOME`.
It otherwise uses `%USERPROFILE%\.copilot`.
The default state root is `%LOCALAPPDATA%\Lingity\gate`.
This command does not control administrator policy hooks.

`Rollback` means something different: it restores the previous owned version.
That version may still enable the hook. `Disable` removes the
integration regardless of the number of prior versions.
You must run the repository's current script for `Disable`.
An older archived rollback script may not support that mode.

### Re-enabling the hook

These commands reuse the reviewed paths from the inspection commands:

```powershell
.\scripts\install-copilot-gate.ps1 -Python $python -CorpusRoot $corpus
.\scripts\install-copilot-gate.ps1 -Mode Enable -Python $python -CorpusRoot $corpus
```

The first command previews the setup.
The second runs a real gate check before installing the owned files.
You must restart existing Copilot processes to load them.
The installer does not change PATH or replace the runtime.

## Gate thresholds

The current CLI and hook use `GatePolicy()` defaults from the installed wheel.
They do not read a repository configuration file or an environment override.
They have no `--policy` or threshold option.
The deployed `gate\policy-reference.json` is a record, not active configuration.
Editing it does not change the gate.

| Policy field | Default | Allowed values |
|---|---|---|
| `minimum_document_hri` | 85 | 85 through 100 |
| `minimum_block_hri` | 85 | 85 through 100 |
| `max_input_bytes` | 32768 | 1 through 32768 |
| `max_units` | 256 | 1 through 256 |
| `reject_high_severity` | `true` | Only `true`. |
| `reject_specified_owners` | `true` | Only `true`. |
| `require_relative_improvement` | `true` | Only `true`. |

The block threshold applies to each substantive prose unit, including table
prose. An overall passing score cannot hide a failing unit.
The schema permits stricter values but preserves the agreed floor.
It rejects lower score thresholds and attempts to disable the listed checks.

### Thresholds for a Python caller

The Python API accepts an explicit policy for one evaluation.
This example requires a document HRI of 90 and a block HRI of 88:

```python
from pathlib import Path

from lingity.gate import GatePolicy, evaluate_document

policy = GatePolicy.from_dict({
    "minimum_document_hri": 90,
    "minimum_block_hri": 88,
})
candidate = Path("specification.md").read_bytes()
baseline = Path("first-draft.md").read_bytes()
result = evaluate_document(candidate, baseline, policy)
print(result.to_dict())
raise SystemExit(0 if result.accepted else 1)
```

A new document with no earlier draft takes `baseline=None`.
This call does not change the installed hook.
Invalid policy values raise an error rather than falling back to defaults.

### Thresholds for the installed hook

You must review a hook policy change before releasing the runtime:

1. You must change `GatePolicy.minimum_document_hri` and `minimum_block_hri`
   defaults in `lingity\gate.py`. Both values must stay within 85 through 100.
2. You must update the selected values in `lingity.instructions.md` and the
   authoring guide. The schema's 85 minimum stays unless the user approves
   a different standard. Tests of the defaults must match the new policy.
3. You must build a new wheel from that reviewed source. You must install it
   in a new dedicated environment outside the repository. You must retain
   the old runtime.
4. You must run the gate tests and installer smoke with that environment.
   The checks must include passing prose and prose below the new threshold.
5. You must enable the new interpreter with the installer commands above.
   You must restart Copilot and check the new runtime's verdicts.

This command builds the local wheel, rather than taking an index release:

```powershell
$wheelOutput = Join-Path $env:LOCALAPPDATA 'Lingity\wheel-staging'
python -m pip wheel . --no-deps --wheel-dir $wheelOutput
```

You must follow the [trusted installation requirements](../../docs/specification-authoring-gate.md#trusted-local-installation)
when staging that wheel. You must record its hash and source revision.
The record must include the dependency lock and model identity.
The record must include corpus hashes and the advisory assessment.
You must update any runtime pointer or launcher that still names the old
release. The hook installer changes neither.
Editing this checkout alone cannot change a non-editable installed hook.
Editing installed package files directly would invalidate the release record.

The cache identity includes the complete policy.
A changed policy cannot reuse a verdict from the previous thresholds.
Changing score defaults does not change the pinned scoring profile.
It also does not reset baselines or authorize changes to meaning.

### Installer smoke

The following command tests only disposable Copilot homes.
It leaves the active account setup unchanged.

```powershell
.\integrations\copilot\test-installer.ps1 -Python $python -CorpusRoot $corpus
```

## Retained release records

The initial enabled release uses directory `releases\2b3f7ea0dc68d778`.
Its Lingity wheel has this SHA-256:

```text
2b3f7ea0dc68d77885d55807bed2cc0f8294ff928b6eadf696d406666d4fa2b6
```

This identifies the earlier deployed build, not later repository edits.
The deployment retained the original standalone runtime for rollback.
Its release artifacts include the source archive and installation manifest.
They also include a hash-locked wheel set, local corpus hashes, and verification
results. The live check used the account-level hooks.
It confirmed that the gate rejected the poor draft.
It also confirmed that the model repaired the draft itself.
These local records remain outside the repository.

The recorded dependency assessment retains the scoped NLTK exception
`GHSA-8mgp-746c-j5xp`. The model wheel also lacks a PyPI advisory audit.
Neither record establishes a clean dependency scan.
You must reassess both when staging another release.
