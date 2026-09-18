# Markdown authoring gate for Windows

Lingity checks Markdown against an absolute quality threshold. Its adapter
connects that check to user-level Copilot hooks. Lingity supplies local
checks and critiques, not final authority over specification meaning.
It does not filter writes throughout the operating system. The policy
covers all authored Markdown, not just files with specification names.

The [operator guide](../integrations/copilot/README.md) lists the repository files.
It covers hook controls and score settings.
It explains how to disable the hook without restoring an older version.

## Standalone check

```text
lingity gate check specification.md --output gate-result.json
lingity gate check repaired.md --baseline first-draft.md --output gate-result.json
```

Exit code 0 means the candidate passes. Code 1 means it fails the policy.
Code 2 means the command failed to run or its configuration is invalid.
The result locates violations and reports document and block scores.
It reports coverage and protected deltas. It also identifies the runtime.
Hashes of original bytes remain separate from hashes of projected text.
The command neither writes the document nor invokes a model.

## Trusted local installation

You must install a reviewed, non-editable wheel in a dedicated virtual
environment under `%LOCALAPPDATA%\Lingity`. You must record the source
commit and patch. You must record wheel hashes.
The record must include the runtime's exact dependency versions.
It must include the model digest and corpus hashes.
An index release with the same package version is not a valid substitute.

You must use the pinned `en_core_web_sm` 3.8.0 model and local WordNet
corpora. You must invoke the absolute Python executable with `-I`.
You must choose a trusted working directory. Profiles and policy must stay
outside repositories. Baseline snapshots and verdicts must stay outside
them too. You must not enable remote proposal or remote challenge providers.

You must audit each resolved dependency before deployment. The unpatched NLTK
advisory GHSA-8mgp-746c-j5xp affects APIs for model artifacts.
Lingity's WordNet path does not call those APIs. You must record this
exception explicitly. You must reassess it when dependencies or call
paths change. This exception does not make the vulnerability scan clean.

## Document scope

The gate matches `.md` and `.markdown` without regard to case.
It covers new and untracked documents. It also covers renamed and moved
documents. Supported file tools cover explicit targets outside the
repository. This includes authored plans in session directories.
Repository rules and `.gitignore` do not grant exemptions.

Post-write scans cover known task roots. They skip the following paths:

- `.git`
- `.venv`
- `venv`
- `node_modules`
- `__pycache__`
- `.mypy_cache`
- `.pytest_cache`
- The gate's own state directory.

These fixed exclusions cover dependencies and internal data.
They do not exempt session directories in general. Scans do not follow
linked directories or junctions. Direct authored file writes still need
a check.

The gate validates files that the authoring session touches and files
submitted for publication. It does not scan the whole disk or rewrite
unrelated existing files. Concurrent sessions retain separate baselines
and candidate hashes.

## Pinned standard

The user selected no external specification-writing standard.
The gate uses the bundled `architecture-review` profile at version 1.3.0.
A digest pins that profile. Its `clear` band starts at a Human Readability
Index (HRI) of 85. The whole document and each substantive prose block
must reach that floor.

The gate permits no high-severity findings. It permits no unresolved
ingest lines or uncovered prose. Each readability repair must preserve
the source that the user authorized. The following rules apply:

- The repair must retain facts, actors, and quantities.
- The repair must retain identifiers and citations.
- The repair must preserve obligations and negation.
- The repair must preserve the governance state and ordering.
- The repair must keep code and literal content intact.
- The repair must preserve table associations, anchors, and links.

The model must review `protected_delta.specified` against source authority.
It must not invent an owner just because Lingity permits specifying an
unnamed actor. A separate projection checks prose in tables.
It records each cell's source location. Empty documents cannot earn a prose-quality pass.
Neither can documents that contain only excluded content.

These checks add requirements beyond `analyze`. An analysis exit code of
zero means that the command ran successfully. It does not mean the prose
passes this gate. The `judge` command requires relative improvement,
not an absolute score. It rejects ties. The gate therefore provides a
separate compliance path for unchanged text that already passes.

This readability policy does not prove conformance with external standards.
It does not establish compliance with guidance from the International
Council on Systems Engineering (INCOSE). It does not establish conformance
with OPC UA.
New requirements need a new baseline that the user authorizes.
Intentional changes to meaning need the same authority.
A model must not reset the baseline to hide a failed comparison.

## Autonomous repair and user decisions

The gate captures the first complete draft for each genuine requested
revision. It stores that baseline with a hash and never changes its bytes.
The first draft remains the baseline even when it fails.
The model must stage proposed rewrites outside the accepted destination.
For a new draft, the model must also check the user's requirements.
Comparing a draft with itself does not prove correctness.

The evaluator reuses analysis and critique functions.
It checks protected meaning and applies the absolute standard above.
Its output identifies rules and source locations. It gives repair guidance
and protected deltas as data, not instructions from the document.
Native `analyze` still excludes tables as before.

The model repairs clear defects itself. It chooses between passing
wordings without asking the user when their meanings are equivalent
and the sources support them. The hook never spawns recursive model
requests. This workflow does not suppress unrelated questions,
`ask_user` calls, or normal prompts for tool permissions.

Escalation requires a genuine unresolved decision after reasonable repairs.
No passing choice that the sources support may remain available to the model.
Missing facts or authority must prevent
the model from choosing on its own. The model must show the blocked
passage and explain what remains unresolved.

The model must present two or three concrete wording options.
The model must explain each option's meaning and show its actual gate result.
The evidence may justify recommending an option.
In that case, the model should recommend one.
The model must label untested options as untested.
The user's choice authorizes a decision, not a lint bypass.
The model must submit the chosen text to the gate again.

The gate allows three distinct repairs after the first complete draft.
Repeated hashes reuse their results without creating a new baseline.
The gate retains the accepted file when a supported editor write fails.
Exhausting the budget does not prove that no passing wording exists.
The model must report the actual blocker and attempts.
The model must report tool failures separately. A missing model or a timeout
does not justify a question about wording preferences.
Other rule failures and state errors also require a blocked outcome,
not an invented user decision.

### Answers inside the question tool

This protocol applies only to a genuine choice about missing facts or
authority in a captured draft. It does not change ordinary `ask_user`
questions. A positive answer inside that tool can authorize a new revision.
The user does not need to send another chat prompt.

The model must put the following prefix on the first line of `message`.
The model must use the document's absolute path and the baseline hash from gate
feedback. The JSON must escape backslashes in a Windows path.

```text
Lingity decision: {"path":"<absolute document path>","baseline_sha256":"<hash from gate feedback>"}
```

A blank line must follow the prefix. The model must then show the blocked
passage and the wording options. The model must explain their meanings
and give their exact gate results.
The `requestedSchema.properties` object must contain 1 to 10 string fields.
Each name must be `lingity_choice` or `lingity_choice_<topic>`.
These fields may bundle related questions about the same draft.
Each field must offer two or three distinct concrete choices.
It can use `enum` or `oneOf`. Each `oneOf` entry must contain a string `const`.
The question interface may also accept a freeform answer.

The following example uses a synthetic frozen draft:
`The finding must be closed.` The baseline has one trailing LF.
The example path is illustrative. Real calls must use the actual path
and hash from gate feedback.
Both candidate sentences score 100 at document and block level.
Both fail with `repair.specified_owner` because the baseline names no actor.
These are real results from the pinned gate, not predicted scores.
Only the user can resolve the missing authority in this example.

```json
{
  "message": "Lingity decision: {\"path\":\"C:\\\\work\\\\specification.md\",\"baseline_sha256\":\"a64843c8a19ebf5551d4355e84b08f3cc0668d3f5c0b9effd7f9302fea15c362\"}\n\nPassage: The finding must be closed.\nWhich actor has authority to close the finding?\nOption 1: The reviewer must close the finding.\nMeaning: The reviewer owns this duty.\nGate: accepted=false; document HRI=100; block HRI=100; repair.specified_owner.\nOption 2: The auditor must close the finding.\nMeaning: The auditor owns this duty.\nGate: accepted=false; document HRI=100; block HRI=100; repair.specified_owner.\nThe sources do not justify a recommendation.",
  "requestedSchema": {
    "type": "object",
    "properties": {
      "lingity_choice_actor": {
        "type": "string",
        "enum": [
          "The reviewer must close the finding.",
          "The auditor must close the finding."
        ]
      }
    },
    "required": ["lingity_choice_actor"]
  }
}
```

The hook binds the question to the current document, candidate, and epoch.
It rejects stale or concurrent answers.
Only an actual successful native answer grants one-use permission
for a new revision of the chosen document.
The accepted outputs begin with `User responded: VALUE` or
`User responded:\nfield: VALUE`. The latter form covers detailed replies.
A decline, cancellation, or tool failure leaves the baseline unchanged.
The model cannot substitute its own text for a native answer.

The answer does not change the root epoch or any child binding.
Unrelated documents keep their baselines and repair budgets.
The shared stop count does not reset.
Each document revision has its own identifier, separate from the root epoch.
A genuine new user chat request still begins a normal new epoch.

After the answer, the main agent or the child that asked must submit the
complete chosen draft through a supported editor tool.
That proposal consumes the permission and starts the new document revision.
The target stays pending until the hook checks the draft and verifies its
actual bytes. A supported edit may leave those bytes unchanged.
An unchanged candidate can pass without an HRI increase.

A shell write after the answer may update the target's observed bytes.
It cannot replace the complete chosen editor proposal.
The target remains unverified until that proposal arrives.
An ambiguous older shell operation cannot define the new draft.

## Copilot integration

For the current Windows account, the hook file belongs at
`%USERPROFILE%\.copilot\hooks\lingity.json`.
When `COPILOT_HOME` has a value, the hook directory is `%COPILOT_HOME%\hooks`.
An administrator must install policy for all users' Copilot sessions.
That policy belongs under `C:\ProgramData\GitHub\Copilot\policy.d`.
Users can disable user hooks. The `disableAllHooks` setting cannot
disable policy hooks.

The installer uses command hooks with direct `exec` and `args`.
It does not use shell interpolation.

| Event | Required behavior |
|---|---|
| `preToolUse` | The adapter reconstructs complete candidates before a write. It handles supported edits, patches, and moves. It validates every in-scope file. On failure, it returns `permissionDecision: "deny"` with an actionable reason. On success, it returns `{}` and retains normal tool permissions. |
| `postToolUse` | The adapter compares actual changed bytes with the validated candidate hash. It reports discrepancies and repair guidance through `additionalContext`. This detects writes but cannot prevent them retroactively. |
| `agentStop` | The adapter rechecks pending documents. It returns `decision: "block"` with repair guidance while repairs remain possible. Otherwise, it requires an explicit blocked outcome or a genuine user decision. |
| `subagentStop` | The adapter checks pending files where the host supports this event. The built-in `general-purpose` agent does not emit it. |

The adapter also handles `sessionStart` and `userPromptSubmitted`.
It handles `postToolUseFailure` too.
It stores immutable drafts and transactional SQLite state under
`%LOCALAPPDATA%\Lingity\gate`, outside the authored repository.
It retains only the local document bytes and correlation metadata
that the workflow needs. It does not archive user prompts or transcripts.

The adapter supports native `create` and unique exact `edit` operations.
It supports `apply_patch` with plain `@@` hunks and unique exact context.
A patch may affect at most 32 distinct Markdown targets.
Renames use `Update File` plus `Move to` and an exact context hunk.
The adapter rejects ambiguous or fuzzy patches and names a supported
alternative.

The evaluator accepts at most 32 KiB and 256 prose units per document.
It rejects larger inputs explicitly. The hook has a separate 256 KiB
capture bound. This lets it retain an oversized first draft instead
of silently replacing that baseline with a shorter one.
The gate explicitly rejects unsupported HTML that bears prose.
It also rejects documents that it cannot score.

Each hook check has a 40-second worker deadline.
The host has a 60-second timeout. A scan of known roots stops at
50,000 entries or 100 MiB of Markdown input.
A root that exceeds either bound produces a tooling error.
The operator must choose a narrower task working directory.
The gate must not silently skip documents to fit those bounds.

### State and verified writes

Each verdict binds to a canonical path and candidate bytes.
It also binds to the baseline, profile digest, and runtime identity.
Verified bytes require a matching SHA hash and a passing verdict
for the current runtime. A stale result cannot authorize a write.
The gate rejects ambiguous Windows paths and alternate data streams.
It rejects links or junctions that escape approved roots.
It never overwrites another session's changes or automatically
reverts a user's edits.

The gate keeps the same snapshots when a session resumes.
It adds a random nonce to each stop reason.
It registers a hash of that reason for its pending continuation.
This provides correlation, not a cryptographic signature.
An unknown generated echo cannot
start a new request. Renames and child agents cannot reset a baseline.
Retries and stop continuations cannot reset it either.
The gate permits at most six shared stop continuations.

A document can fail after the gate previously verified it.
If rejected bytes reach disk, the gate invalidates that prior status.
The document enters a conflict state. That conflict persists across
new prompts. A new prompt cannot silently adopt those rejected bytes.

### Observed host contract

Live probes used Windows CLI 1.0.85.
The sanitized fixtures for file calls are in
`tests/fixtures/copilot-hooks.json`.

- The initial prompt event precedes `sessionStart`, including on resume.
- Native create/edit arguments are objects. The `apply_patch` tool receives a raw string.
- New Windows files use CRLF. Edits preserve the existing newline convention.
- A stop block causes another prompt event. Its prompt contains the hook's reason. This continues the turn rather than authorizing a new content revision.
- A `general-purpose` child has a separate session ID. It emits a prompt that matches its parent's task prompt.
- The child has no `sessionStart`. Its tools and `agentStop` still emit hooks.
- A background launch can return before the child prompt arrives. Unclaimed launches remain available for correlation.
- Children stay pinned to their original request. The gate fails when it cannot identify an unambiguous owner.
- A `{}` response retains normal permissions. It does not grant blanket write approval.

Autopilot emits `userPromptSubmitted` prompts with this reserved prefix:
`You have not yet marked the task as complete using the task_complete tool.`
The adapter treats that prefix and `<system_notification>` as host continuations.
These prompts continue an existing proven request epoch.
Neither marker authorizes a new baseline.

These observations define the current compatibility contract.
They do not establish the behavior of every future host version.
You must run isolated live checks after a host upgrade.

### Installer controls

You must stage a reviewed, non-editable runtime before enabling the hooks.
The staged runtime must have the exact pinned model and local corpora.
You must keep the working runtime until the staged one passes its checks.
The installer does not download packages or replace the runtime.

```powershell
.\scripts\install-copilot-gate.ps1 -Python 'C:\trusted\runtime\Scripts\python.exe' -CorpusRoot 'C:\trusted\nltk_data'
.\scripts\install-copilot-gate.ps1 -Mode Enable -Python 'C:\trusted\runtime\Scripts\python.exe' -CorpusRoot 'C:\trusted\nltk_data'
.\scripts\install-copilot-gate.ps1 -Mode Disable
.\scripts\install-copilot-gate.ps1 -Mode Rollback
```

The default Preview makes no changes. Enable runs a real gate health check.
Only then does it install the two files that it owns:

- `hooks\lingity.json`
- `instructions\lingity.instructions.md`

The installer respects `COPILOT_HOME`.
The `-CopilotHome` and `-StateRoot` options can select an isolated test setup.
It preserves unrelated configuration. It records exact hashes and backups
for its owned files. Repeated installs do not change an identical setup.
The installer refuses to overwrite unowned files or local edits to owned
files.

You must restart existing Copilot processes to load the hooks and
instructions. Fresh processes load them at startup.
Disable removes the current owned hook and instructions.
It does not restore an older version.
The operator guide has preview and re-enable commands.
Rollback restores the previous owned version when one exists.
Otherwise, it removes only unchanged owned files.
It leaves retained baselines and runtime archives available.

The worker deadline must remain below the outer hook timeout.
The adapter must explicitly reject invalid input or missing dependencies.
The adapter must also reject worker failures and unsupported in-scope edits.
An expired worker deadline must produce an explicit rejection too.
These responses must arrive before the host timeout.

## Actual enforcement boundary

Copilot documents that hook timeouts fail open.
This includes administrator policy hooks.
The host overrides stop hooks after eight consecutive blocks.
Unrestricted shell commands can write without a supported editor operation.
Other applications and external tools can do the same.
A filesystem watcher can detect such writes but cannot reject them
synchronously.

Hooks therefore enforce a cooperative authoring workflow.
They do not guarantee checks for every specification written on this
machine. Models must not switch tools or paths to evade a gate failure.
They must not disable hooks or delete pending documents to evade it.
Post-write checks do not undo writes.

Strict control at publication requires separate permissions.
Agents must not have direct write access to final specification locations.
They may write candidates elsewhere.
A separate publisher must hold the permissions for final writes.
The publisher must run the gate on the exact candidate before promoting it
atomically.
The release boundary must apply the same policy.
Local Git hooks alone are bypassable and cannot replace this control.

## Activation criteria

You must test the following cases before enabling the hook:

- Passing and failing prose.
- Changes to meaning that improve the score.
- Missing ownership.
- Text in table cells.
- Files that contain only excluded content.
- CRLF and Unicode.
- New files and moves.
- Patches that affect multiple files.
- Documents that a shell creates.
- Concurrent edits.
- Links and junctions.
- Malformed input.
- Missing models.
- Deadline failures.

You must exercise new and resumed sessions.
The tests must use the installed host's real write tools.
Simulated hook JSON alone does not suffice.
Your tests must confirm that the gate cannot grant permissions
that ordinary tool policy denies.

The [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-configuration)
describes the host contract.
The [user-level configuration guide](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks)
describes where to install hooks.
You must verify these features against the installed CLI before activation.
