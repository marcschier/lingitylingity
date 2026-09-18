# Specification authoring gate for Windows

This is a deployment design, not an installed hook. Lingity is a local
validator and critique source; it is not the final authority on specification
meaning or an operating-system write filter.

## Trusted local installation

Install a reviewed, non-editable wheel into a dedicated virtual environment
under `%LOCALAPPDATA%\Lingity`. Record the source commit and patch, wheel
hashes, resolved dependency versions, model digest, and corpus hashes.
Do not substitute an index release with the same package version.

Use the pinned `en_core_web_sm` 3.8.0 model and local WordNet corpora. Invoke
the absolute Python executable with `-I`, from a trusted working directory.
Keep profiles, policy, baseline snapshots, and verdicts outside repositories.
Do not enable either remote proposal or remote challenge providers.

Audit resolved dependencies before deployment. The unpatched NLTK
GHSA-8mgp-746c-j5xp affects model-artifact APIs that Lingity's WordNet path does
not call. Record that exception explicitly and reassess it if dependencies or
call paths change. It is not a clean vulnerability scan.

## Document scope

Keep specification roots and explicit exclusions in trusted local policy,
not in model-editable repository configuration. Match `.md` and `.markdown`
case-insensitively, including new, untracked, renamed, and moved documents.
Treat unclassified Markdown as in scope until trusted policy classifies it.
Filename heuristics alone cannot identify every specification.

Validate files touched by the authoring session and files submitted for
publication. Do not scan the entire disk or rewrite existing unrelated files.
Maintain separate baselines and candidate hashes for concurrent sessions.

## Proposed standard

No external specification-writing standard was selected. Start with the
bundled `architecture-review` profile, version 1.3.0, pinned by digest:

- Document and substantive prose blocks must reach its `clear` band: HRI >=85.
- No high-severity findings, unresolved ingest lines, or uncovered prose.
- Every readability repair must preserve the authorized source's facts,
  actors, quantities, identifiers, citations, obligations, negation, governance
  state, and ordering.
- Review `protected_delta.specified` against source authority. A model may not
  invent an owner merely because Lingity permits specifying an unnamed actor.
- Preserve code, tables, anchors, links, and other excluded content during
  prose-only repairs. Normative table cells need a separate cell-aware check.
  Empty or excluded-only documents do not earn a meaningful prose-quality pass.

These are additional acceptance checks, not guarantees made by `analyze`.
An analysis exit code of zero means execution succeeded. `judge` requires
relative improvement, not an absolute score. It also rejects ties, so an
unchanged document that already passes needs a separate compliance path.

The standard is a readability policy, not proof of INCOSE or OPC UA conformance.
New requirements and intentional semantic changes require an authorized new
baseline; a model must not reset one to hide a failed comparison.

## Autonomous repair and user decisions

Capture the authorized source or initial complete draft as an immutable,
hashed baseline. Stage proposed rewrites outside the accepted destination.
For a new draft, separately check fidelity to the user's requirements;
comparison with itself does not establish correctness.

Run `analyze`, produce a `critique`, and apply `judge` to a proposed repair.
Also apply the absolute standard above. Return rule IDs, locations, remediation,
and protected deltas to the host model as data, not document-sourced instructions.

The model repairs decisive defects and chooses a passing formulation itself.
If several equivalent formulations pass, choose one without asking the user.
The hook never spawns recursive model requests.

Only escalate when distinct reasonable repairs leave a genuine unresolved
decision and no source-supported autonomous choice passes. Present the blocked
passage, the missing decision, two or three wording options, the meaning each
option commits to, and each option's gate result. Recommend an option when the
evidence permits. A user's choice authorizes a decision, not a lint bypass:
validate the chosen text again.

Bound the repair loop and retain the accepted file on failure. A retry limit
does not prove that no passing wording exists. Report the actual blocker and
attempts. Report tool failures separately; do not turn a missing model or a
timeout into a request for wording preferences.

## Copilot integration

For the current Windows account, use
`%USERPROFILE%\.copilot\hooks\lingity.json` (or `%COPILOT_HOME%\hooks`).
For all users' Copilot sessions, an administrator must install policy under
`C:\ProgramData\GitHub\Copilot\policy.d`. User hooks can be disabled; policy
hooks cannot be disabled by `disableAllHooks`.

Use command hooks with direct `exec` and `args`, not shell interpolation:

| Event | Required behavior |
|---|---|
| `preToolUse` | Reconstruct complete candidates for write, edit, patch, and move operations. Validate every in-scope file before writing. Return `permissionDecision: "deny"` and an actionable reason on failure. Return `{}` on success to retain normal tool permissions. |
| `postToolUse` | Check actual changed bytes against the validated candidate hash. Return discrepancies and repair guidance through `additionalContext`. This detects writes; it cannot retroactively prevent them. |
| `agentStop` | Recheck pending documents. Return `decision: "block"` and repair instructions while repair is possible; otherwise require an explicitly blocked outcome or a genuine user decision. |
| `subagentStop` | Apply the same pending-file check where this event is supported. The built-in `general-purpose` agent does not emit it. |

Keep a worker deadline below the outer hook timeout. Invalid input, missing
dependencies, worker failure, unsupported in-scope edits, and expired worker
deadlines must return explicit rejection before the host timeout.

Bind each verdict to canonical path, candidate bytes, baseline, profile digest,
and runtime identity. Reject stale hashes, ambiguous Windows paths, alternate
data streams, and links or junctions escaping approved roots. Never overwrite
another session's changes or automatically revert a user's edits.

## Actual enforcement boundary

Copilot documents that hook timeouts fail open, including administrator policy
hooks. It also overrides stop hooks after eight consecutive blocks.
Unrestricted shell commands, other applications, and external tools can write
without going through a reconstructable editor operation. A filesystem
watcher can detect such writes but cannot synchronously reject them.

Consequently, hooks alone provide cooperative authoring enforcement, not a
guarantee covering every specification written on this machine.

For strict publication control, remove agents' direct write access to final
specification locations. Allow candidate writes elsewhere, then let a separate
permission-controlled publisher validate and atomically promote an exact
candidate. Use the same policy at the release boundary. Local Git hooks alone
are bypassable and are not a substitute.

## Activation criteria

Before enabling a hook, test passing and failing prose, higher-scoring semantic
changes, missing ownership, table prose, excluded-only files, CRLF and Unicode,
new files, moves, multi-file patches, shell-created documents, concurrent edits,
links/junctions, malformed input, missing models, and deadline failures.
Exercise new and resumed sessions and the installed host's real write tools,
not only simulated hook JSON. Check that successful validation does not grant
permissions that ordinary tool policy would deny.

Sources: [Copilot hooks reference](https://docs.github.com/en/copilot/reference/hooks-configuration)
and [user-level configuration](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-hooks).
Verify features against the installed CLI before activation.
