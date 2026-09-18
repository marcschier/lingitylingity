from __future__ import annotations

import io
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from lingity import copilot_hook
from lingity.copilot_tools import reconstruct
from lingity.gate_state import GateState, GateStateError, StateConflict


def _invoke(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    payload: str = '{"sessionId":"test","cwd":"ignored"}',
    event: str = "preToolUse",
) -> dict[str, Any]:
    monkeypatch.setattr(sys, "stdin", io.StringIO(payload))
    assert copilot_hook.main(["--event", event, "--state-dir", str(tmp_path / "state")]) == 0
    output = capsys.readouterr()
    assert len(output.out.strip().splitlines()) == 1
    result: dict[str, Any] = json.loads(output.out)
    return result


def test_success_retains_ordinary_permissions(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    calls: list[dict[str, Any]] = []

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        calls.append({"command": command, **kwargs})
        return subprocess.CompletedProcess(command, 0, b"{}", b"")

    monkeypatch.setattr(subprocess, "run", run)
    assert _invoke(monkeypatch, capsys, tmp_path) == {}
    assert calls[0]["command"][:4] == [sys.executable, "-I", "-m", "lingity.copilot_hook"]
    assert calls[0]["cwd"] == tmp_path / "state"
    assert calls[0]["timeout"] == 40.0
    assert not calls[0].get("shell", False)


def test_internal_timeout_denies_before_outer_timeout(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        raise subprocess.TimeoutExpired(command, kwargs["timeout"])

    monkeypatch.setattr(subprocess, "run", run)
    result = _invoke(monkeypatch, capsys, tmp_path)
    assert result["permissionDecision"] == "deny"
    assert "internal worker deadline" in result["permissionDecisionReason"]


@pytest.mark.parametrize("output,code", [
    (b'{"permissionDecision":"allow"}', 2),
    (b"{}\n{}", 0),
    (b"[]", 0),
    (b"x" * 32_769, 0),
], ids=["nonzero", "multiple-json", "array", "oversized"])
def test_worker_failures_never_look_like_success(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    tmp_path: Path, output: bytes, code: int,
) -> None:
    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        return subprocess.CompletedProcess(command, code, output, b"synthetic worker failure")

    monkeypatch.setattr(subprocess, "run", run)
    result = _invoke(monkeypatch, capsys, tmp_path)
    assert result["permissionDecision"] == "deny"
    assert "no compliance verdict" in result["permissionDecisionReason"]


@pytest.mark.parametrize("payload", ["not json", "[]", "x" * 1_048_577], ids=["invalid", "array", "oversized"])
def test_malformed_event_is_explicit_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    tmp_path: Path, payload: str,
) -> None:
    result = _invoke(monkeypatch, capsys, tmp_path, payload)
    assert result["permissionDecision"] == "deny"
    assert not (tmp_path / "state").exists()


def test_post_failure_reports_context_not_an_impossible_rollback(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path,
) -> None:
    result = _invoke(monkeypatch, capsys, tmp_path, "invalid", "postToolUse")
    assert set(result) == {"additionalContext"}
    assert "no compliance verdict" in result["additionalContext"]


def test_scan_covers_untracked_markdown_without_gitignore_waivers(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("new.md\n", encoding="utf-8")
    (tmp_path / "new.md").write_bytes(b"The server must retain the record.\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "README.md").write_text("Dependency.", encoding="utf-8")
    result = copilot_hook._scan([str(tmp_path)], tmp_path / "state")
    assert len(result) == 1
    assert next(iter(result)).lower().endswith("new.md")
    before = next(iter(result.values()))
    (tmp_path / "new.md").write_bytes(b"The server must retain the message.\n")
    after = next(iter(copilot_hook._scan([str(tmp_path)], tmp_path / "state").values()))
    assert before != after


def _initialize(tmp_path: Path) -> tuple[Path, dict[str, Any]]:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    root = tmp_path / "state"
    event: dict[str, Any] = {"sessionId": "main", "cwd": str(workspace), "timestamp": 1}
    assert copilot_hook.dispatch("userPromptSubmitted", {**event, "prompt": "Write the specification."}, root) == {}
    assert copilot_hook.dispatch("sessionStart", {**event, "source": "new"}, root) == {}
    return root, event


def _drafts() -> tuple[str, str]:
    clauses = [
        f"The board must review the {target}"
        for target in ("framework", "database", "proposal", "implementation", "migration", "interface", "contract", "record")
    ]
    return "; ".join(clauses) + ".\n", ". ".join(clauses) + ".\n"


def _create_event(event: dict[str, Any], text: str) -> dict[str, Any]:
    return {**event, "toolName": "create", "toolArgs": {"path": str(Path(event["cwd"]) / "draft.md"), "file_text": text}}


def _write_approved(event: dict[str, Any]) -> bytes:
    changes = reconstruct(event["toolName"], event["toolArgs"], event["cwd"])
    assert len(changes) == 1 and changes[0].candidate is not None
    Path(changes[0].path).write_bytes(changes[0].candidate)
    return changes[0].candidate


def test_real_gate_rejects_then_accepts_faithful_repair(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    first = _create_event(event, original)
    rejected = copilot_hook.dispatch("preToolUse", first, root)
    assert rejected["permissionDecision"] == "deny"
    assert "82.59" in rejected["permissionDecisionReason"]
    assert not Path(first["toolArgs"]["path"]).exists()
    with GateState(root) as state:
        baseline = state.pending("main")[0].baseline
    second = _create_event(event, repair)
    assert copilot_hook.dispatch("preToolUse", second, root) == {}
    written = _write_approved(second)
    assert copilot_hook.dispatch("postToolUse", second, root) == {}
    assert copilot_hook.dispatch("agentStop", event, root) == {}
    with GateState(root) as state:
        assert state.pending("main") == []
        assert state.tracked("main")[0].baseline == baseline
        assert state.tracked("main")[0].candidate_hash == copilot_hook._digest(written)


def test_stop_prompt_is_not_a_new_revision(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, _ = _drafts()
    assert copilot_hook.dispatch("preToolUse", _create_event(event, original), root)["permissionDecision"] == "deny"
    with GateState(root) as state:
        before = state.pending("main")[0]
    stopped = copilot_hook.dispatch("agentStop", event, root)
    assert stopped["decision"] == "block"
    assert copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": stopped["reason"]}, root) == {}
    with GateState(root) as state:
        after = state.pending("main")[0]
        assert after.epoch == before.epoch
        assert after.baseline_hash == before.baseline_hash
        assert after.repairs == before.repairs
    stopped_again = copilot_hook.dispatch("agentStop", {**event, "stop_hook_active": True}, root)
    assert "2/6" in stopped_again["reason"]


def test_background_child_shares_parent_baseline_after_launch_returns(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    launch = {**event, "toolName": "task", "toolArgs": {"prompt": "Repair this draft.", "agent_type": "general-purpose", "mode": "background"}}
    assert copilot_hook.dispatch("preToolUse", launch, root) == {}
    copilot_hook.dispatch("postToolUse", launch, root)
    child = {**event, "sessionId": "child", "timestamp": 2}
    assert copilot_hook.dispatch("userPromptSubmitted", {**child, "prompt": "Repair this draft."}, root) == {}
    candidate = _create_event(child, repair)
    assert copilot_hook.dispatch("preToolUse", candidate, root) == {}
    _write_approved(candidate)
    assert copilot_hook.dispatch("postToolUse", candidate, root) == {}
    with GateState(root) as state:
        assert state.pending("main") == state.pending("child") == []
        document = state.tracked("main")[0]
        assert document.repairs == 1
        assert document.baseline.decode().replace("\r\n", "\n") == original


def test_new_user_request_allows_intentional_content_revision(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    first = _create_event(event, "The server must retain the record.\n")
    assert copilot_hook.dispatch("preToolUse", first, root) == {}
    _write_approved(first)
    copilot_hook.dispatch("postToolUse", first, root)
    edit = {**event, "toolName": "edit", "toolArgs": {"path": first["toolArgs"]["path"], "old_str": "record", "new_str": "message"}}
    assert copilot_hook.dispatch("preToolUse", edit, root)["permissionDecision"] == "deny"
    copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": "Change the requirement to retain the message instead."}, root)
    assert copilot_hook.dispatch("preToolUse", edit, root) == {}
    _write_approved(edit)
    assert copilot_hook.dispatch("postToolUse", edit, root) == {}
    assert copilot_hook.dispatch("agentStop", event, root) == {}


def test_shell_created_markdown_is_detected_and_repaired_without_revert(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    target = Path(event["cwd"]) / "draft.md"
    shell = {**event, "toolName": "powershell", "toolArgs": {"command": "synthetic writer"}}
    assert copilot_hook.dispatch("preToolUse", shell, root) == {}
    target.write_bytes(original.encode())
    after = copilot_hook.dispatch("postToolUse", shell, root)
    assert "rejected" in after["additionalContext"]
    assert target.read_bytes() == original.encode()
    assert copilot_hook.dispatch("agentStop", event, root)["decision"] == "block"
    target.write_bytes(repair.encode())
    assert copilot_hook.dispatch("postToolUse", shell, root) == {}
    assert target.read_bytes() == repair.encode()
    assert copilot_hook.dispatch("agentStop", event, root) == {}
    with GateState(root) as state:
        assert state.tracked("main")[0].baseline == original.encode()


def test_failed_tool_keeps_baseline_without_claiming_write(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    candidate = _create_event(event, "The server must retain the record.\n")
    assert copilot_hook.dispatch("preToolUse", candidate, root) == {}
    failed = copilot_hook.dispatch("postToolUseFailure", {**candidate, "error": "permission denied"}, root)
    assert "unverified" in failed["additionalContext"]
    assert not Path(candidate["toolArgs"]["path"]).exists()
    assert copilot_hook.dispatch("preToolUse", candidate, root) == {}
    _write_approved(candidate)
    assert copilot_hook.dispatch("postToolUse", candidate, root) == {}


def test_unowned_child_cannot_create_a_fresh_baseline(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    event = {"sessionId": "unowned-child", "timestamp": 1, "cwd": str(workspace)}
    root = tmp_path / "state"
    copilot_hook.dispatch("userPromptSubmitted", {**event, "prompt": "Uncorrelated generated prompt"}, root)
    with pytest.raises(StateConflict):
        copilot_hook.dispatch("preToolUse", _create_event(event, "The server must retain the record."), root)
    assert not (workspace / "draft.md").exists()


def test_error_stop_echo_cannot_replace_a_rejected_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
) -> None:
    root, event = _initialize(tmp_path)
    original, _ = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    with GateState(root) as state:
        frozen = state.pending("main")[0]
    obstacle = Path(event["cwd"]) / "bad~name.md"
    obstacle.write_text("The server must retain the record.", encoding="utf-8")
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    assert copilot_hook.main(["--event", "agentStop", "--state-dir", str(root)]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["decision"] == "block"
    try:
        copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": stopped["reason"]}, root)
    except GateStateError:
        # Notification-hook failures do not stop host prompt delivery.
        pass
    obstacle.unlink()
    result = copilot_hook.dispatch("preToolUse", _create_event(event, "The board must delete the record.\n"), root)
    assert result.get("permissionDecision") == "deny"
    with GateState(root) as state:
        retained = state.pending("main")[0]
        assert retained.epoch == frozen.epoch
        assert retained.baseline_hash == frozen.baseline_hash


def test_same_epoch_resume_cannot_adopt_unapproved_bytes(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    first = _create_event(event, "The board must delete the record.\n")
    assert copilot_hook.dispatch("preToolUse", first, root) == {}
    _write_approved(first)
    copilot_hook.dispatch("postToolUse", first, root)
    bad, _ = _drafts()
    target = Path(first["toolArgs"]["path"])
    target.write_bytes(bad.encode())
    copilot_hook.dispatch("sessionStart", {**event, "source": "resume"}, root)
    stopped = copilot_hook.dispatch("agentStop", event, root)
    assert stopped.get("decision") == "block"
    assert target.read_bytes() == bad.encode()


def test_snapshot_equality_is_not_proof_of_approved_content(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    first = _create_event(event, "The board must delete the record.\n")
    assert copilot_hook.dispatch("preToolUse", first, root) == {}
    approved = _write_approved(first)
    copilot_hook.dispatch("postToolUse", first, root)
    bad, _ = _drafts()
    target = Path(first["toolArgs"]["path"])
    target.write_bytes(bad.encode())
    with GateState(root) as state:
        state.update_snapshot("main", target, copilot_hook._digest(bad.encode()))
    completed = copilot_hook.dispatch("preToolUse", {**event, "toolName": "task_complete", "toolArgs": {}}, root)
    assert completed.get("permissionDecision") == "deny"
    assert copilot_hook.dispatch("agentStop", event, root).get("decision") == "block"
    with GateState(root) as state:
        assert state.pending("main")[0].status == "conflict"
    copilot_hook.dispatch("userPromptSubmitted", {
        **event, "timestamp": 2,
        "prompt": "Continue repairing the rejected Markdown without changing its requirements.",
    }, root)
    assert copilot_hook.dispatch("preToolUse", {**event, "toolName": "task_complete", "toolArgs": {}}, root).get("permissionDecision") == "deny"
    assert copilot_hook.dispatch("agentStop", event, root).get("decision") == "block"
    target.write_bytes(approved)
    assert copilot_hook.dispatch("agentStop", event, root) == {}


def test_unregistered_error_echo_is_conservative_when_correlation_failed(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, _ = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    reason = copilot_hook._failure("agentStop", "state correlation unavailable")["reason"]
    with pytest.raises(StateConflict, match="unregistered gate continuation"):
        copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": reason}, root)
    with GateState(root) as state:
        assert state.pending("main")[0].epoch == 1


@pytest.mark.parametrize("failure", ["timeout", "nonzero", "oversized"])
def test_supervisor_error_stops_are_registered_without_new_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
    failure: str,
) -> None:
    root, event = _initialize(tmp_path)
    original, _ = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)

    def run(command: list[str], **kwargs: Any) -> subprocess.CompletedProcess[bytes]:
        if failure == "timeout":
            raise subprocess.TimeoutExpired(command, kwargs["timeout"])
        if failure == "nonzero":
            return subprocess.CompletedProcess(command, 2, b"", b"worker failure")
        return subprocess.CompletedProcess(command, 0, b"x" * 32_769, b"")

    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(event)))
    assert copilot_hook.main(["--event", "agentStop", "--state-dir", str(root)]) == 0
    stopped = json.loads(capsys.readouterr().out)
    assert stopped["decision"] == "block"
    assert copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": stopped["reason"]}, root) == {}
    with GateState(root) as state:
        assert state.pending("main")[0].epoch == 1


def test_resume_of_initially_empty_root_detects_new_untracked_file(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    bad, _ = _drafts()
    target = Path(event["cwd"]) / "new.md"
    target.write_bytes(bad.encode())
    resumed = copilot_hook.dispatch("sessionStart", {**event, "source": "resume"}, root)
    assert "rejected" in resumed["additionalContext"]
    assert copilot_hook.dispatch("agentStop", event, root)["decision"] == "block"


def test_current_runtime_identity_must_still_accept_verified_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    import lingity.gate as gate

    root, event = _initialize(tmp_path)
    first = _create_event(event, "The release must be approved by the reviewer.\n")
    assert copilot_hook.dispatch("preToolUse", first, root) == {}
    _write_approved(first)
    copilot_hook.dispatch("postToolUse", first, root)
    evaluate = gate.evaluate_document

    def tightened(
        candidate: bytes, baseline: bytes | None = None, policy: gate.GatePolicy | None = None,
    ) -> gate.GateResult:
        return evaluate(candidate, baseline, gate.GatePolicy(minimum_document_hri=99, minimum_block_hri=99))

    monkeypatch.setattr(gate, "evaluate_document", tightened)
    monkeypatch.setattr(gate, "cache_identity", lambda policy=None: "1" * 64)
    stopped = copilot_hook.dispatch("agentStop", event, root)
    assert stopped["decision"] == "block"
    assert "99" in stopped["reason"]
    with GateState(root) as state:
        assert state.pending("main")[0].status == "repair_required"


def test_missing_configured_corpus_cannot_fall_back_to_global_data(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, event = _initialize(tmp_path)
    monkeypatch.setenv("NLTK_DATA", str(tmp_path / "missing-corpora"))
    with pytest.raises(ValueError, match="global fallback is disabled"):
        copilot_hook.dispatch("preToolUse", _create_event(event, "The reviewer must approve the release."), root)
    assert not (Path(event["cwd"]) / "draft.md").exists()


@pytest.mark.parametrize("prompt", [
    "You have not yet marked the task as complete using the task_complete tool.\n\nKeep working autonomously.",
    "<system_notification>Agent finished. Read the result.</system_notification>",
])
def test_host_control_prompts_do_not_authorize_new_baselines(tmp_path: Path, prompt: str) -> None:
    root, event = _initialize(tmp_path)
    original, _ = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    with GateState(root) as state:
        frozen = state.pending("main")[0]
    assert copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": prompt}, root) == {}
    refused = copilot_hook.dispatch("preToolUse", _create_event(event, "The board must delete the record.\n"), root)
    assert refused.get("permissionDecision") == "deny"
    with GateState(root) as state:
        assert state.pending("main")[0].epoch == frozen.epoch
        assert state.pending("main")[0].baseline_hash == frozen.baseline_hash


def _decision_event(event: dict[str, Any], baseline: str, first: str, second: str) -> dict[str, Any]:
    scope = {"path": str(Path(event["cwd"]) / "draft.md"), "baseline_sha256": baseline}
    return {
        **event, "toolName": "ask_user",
        "toolArgs": {
            "message": "Lingity decision: " + json.dumps(scope) + "\nChoose the requested action for the record.",
            "requestedSchema": {"properties": {
                "lingity_choice": {"type": "string", "enum": [first, second]},
            }},
        },
    }


@pytest.mark.parametrize("session", ["main", "child"])
@pytest.mark.parametrize("prefix", ["User responded: ", "User responded:\nlingity_choice: "])
def test_scoped_human_answer_authorizes_a_new_checked_revision(
    tmp_path: Path, session: str, prefix: str,
) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    with GateState(root) as state:
        frozen = state.pending("main")[0]
        if session == "child":
            state.bind_child("child", "main", event["cwd"])
    event = {**event, "sessionId": session}
    choice = repair.replace("review the record", "delete the record")
    other = repair.replace("review the record", "encrypt the record")
    question = _decision_event(event, frozen.baseline_hash, choice, other)
    assert copilot_hook.dispatch("preToolUse", question, root) == {}
    answered = {**question, "timestamp": 2, "toolResult": {"resultType": "success", "textResultForLlm": prefix + choice}}
    assert "new requested revision" in copilot_hook.dispatch("postToolUse", answered, root)["additionalContext"]
    candidate = _create_event({**event, "timestamp": 3}, choice)
    assert copilot_hook.dispatch("preToolUse", candidate, root) == {}
    _write_approved(candidate)
    assert copilot_hook.dispatch("postToolUse", candidate, root) == {}
    with GateState(root) as state:
        revised = state.tracked(session)[0]
        assert revised.epoch == frozen.epoch
        assert revised.revision_id != frozen.revision_id
        assert revised.baseline_hash != frozen.baseline_hash
        assert state.artifact_path(frozen.baseline_hash).read_bytes() == frozen.baseline
        assert state.pending(session) == []
    assert copilot_hook.dispatch("postToolUse", answered, root) == {}


@pytest.mark.parametrize("response", ["User declined to answer.", "User cancelled.", ""])
def test_declined_scoped_question_preserves_the_frozen_revision(tmp_path: Path, response: str) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    with GateState(root) as state:
        frozen = state.pending("main")[0]
    question = _decision_event(event, frozen.baseline_hash, repair, repair.replace("review the record", "delete the record"))
    assert copilot_hook.dispatch("preToolUse", question, root) == {}
    answer = {**question, "timestamp": 2, "toolResult": {"resultType": "success", "textResultForLlm": response}}
    assert copilot_hook.dispatch("postToolUse", answer, root) == {}
    with GateState(root) as state:
        assert state.pending("main")[0].epoch == frozen.epoch


def test_unrelated_human_question_cannot_reset_a_draft(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, _ = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    question = {**event, "toolName": "ask_user", "toolArgs": {"message": "Which unrelated database?", "requestedSchema": {"properties": {}}}}
    assert copilot_hook.dispatch("preToolUse", question, root) == {}
    assert copilot_hook.dispatch("postToolUse", {**question, "toolResult": {"resultType": "success", "textResultForLlm": "User responded: SQLite"}}, root) == {}
    with GateState(root) as state:
        assert state.pending("main")[0].epoch == 1


def test_stale_scoped_answer_cannot_replace_a_new_request(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    with GateState(root) as state:
        frozen = state.pending("main")[0]
    question = _decision_event(event, frozen.baseline_hash, repair, repair.replace("review the record", "delete the record"))
    copilot_hook.dispatch("preToolUse", question, root)
    copilot_hook.dispatch("userPromptSubmitted", {**event, "timestamp": 2, "prompt": "Keep the original requirements."}, root)
    answer = {**question, "timestamp": 3, "toolResult": {"resultType": "success", "textResultForLlm": "User responded: " + repair}}
    with pytest.raises(StateConflict, match="stale request"):
        copilot_hook.dispatch("postToolUse", answer, root)


def test_noop_tool_failure_can_verify_already_compliant_bytes(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    path = Path(event["cwd"]) / "draft.md"
    path.write_bytes(b"The reviewer must approve the release.\n")
    edit = {**event, "toolName": "edit", "toolArgs": {
        "path": str(path), "old_str": "approve", "new_str": "approve",
    }}
    assert copilot_hook.dispatch("preToolUse", edit, root) == {}
    assert copilot_hook.dispatch("postToolUseFailure", {**edit, "error": "no change"}, root) == {}
    assert copilot_hook.dispatch("agentStop", event, root) == {}


def test_native_mismatch_stays_a_conflict_instead_of_becoming_a_shell_repair(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    candidate = _create_event(event, "The reviewer must approve the release.\n")
    assert copilot_hook.dispatch("preToolUse", candidate, root) == {}
    path = Path(candidate["toolArgs"]["path"])
    changed = b"The operator must reject the release.\n"
    path.write_bytes(changed)
    assert "do not restore" in copilot_hook.dispatch("postToolUse", candidate, root)["additionalContext"]
    assert copilot_hook.dispatch("agentStop", event, root)["decision"] == "block"
    assert path.read_bytes() == changed
    with GateState(root) as state:
        assert state.pending("main")[0].status == "conflict"


def test_pending_question_prevents_simultaneous_writes(tmp_path: Path) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    copilot_hook.dispatch("preToolUse", _create_event(event, original), root)
    with GateState(root) as state:
        baseline = state.pending("main")[0].baseline_hash
    question = _decision_event(event, baseline, repair, repair.replace("review the record", "delete the record"))
    copilot_hook.dispatch("preToolUse", question, root)
    with pytest.raises(StateConflict, match="wording decision is still pending"):
        copilot_hook.dispatch("preToolUse", _create_event(event, repair), root)


@pytest.mark.parametrize("answering_session", ["main", "child"])
def test_answer_for_one_document_cannot_replace_another_baseline(
    tmp_path: Path, answering_session: str,
) -> None:
    root, event = _initialize(tmp_path)
    original, repair = _drafts()
    a_source = original.replace("board must review", "reviewer must approve")
    copilot_hook.dispatch("preToolUse", _create_event(event, a_source), root)
    b_event = _create_event(event, original)
    b_event["toolArgs"]["path"] = str(Path(event["cwd"]) / "other.md")
    copilot_hook.dispatch("preToolUse", b_event, root)
    with GateState(root) as state:
        a = state.draft("main", Path(event["cwd"]) / "draft.md")
        b = state.draft("main", Path(event["cwd"]) / "other.md")
        assert a is not None and b is not None
        if answering_session == "child":
            state.bind_child("child", "main", event["cwd"])
    changed_b = {**b_event, "toolArgs": {
        **b_event["toolArgs"], "file_text": "The board must delete the record.\n",
    }}
    assert copilot_hook.dispatch("preToolUse", changed_b, root)["permissionDecision"] == "deny"
    with GateState(root) as state:
        budget = state.draft("main", b.path)
        assert budget is not None
    choice = repair.replace("board must review", "reviewer must approve").replace("approve the record", "approve the release")
    question = _decision_event({**event, "sessionId": answering_session}, a.baseline_hash, choice, choice.replace("reviewer", "operator"))
    copilot_hook.dispatch("preToolUse", question, root)
    copilot_hook.dispatch("postToolUse", {
        **question, "timestamp": 2,
        "toolResult": {"resultType": "success", "textResultForLlm": "User responded: " + choice},
    }, root)
    assert copilot_hook.dispatch("preToolUse", {**changed_b, "timestamp": 3}, root)["permissionDecision"] == "deny"
    with GateState(root) as state:
        retained = state.draft("main", b.path)
        assert retained is not None
        assert retained.baseline_hash == b.baseline_hash
        assert retained.revision_id == b.revision_id
        assert retained.repairs == budget.repairs
    Path(b.path).write_bytes(b"The board must delete the record.\n")
    result = copilot_hook.dispatch("postToolUse", {
        **event, "timestamp": 4, "toolName": "powershell", "toolArgs": {"command": "synthetic writer"},
    }, root)
    assert "rejected" in result["additionalContext"]
    with GateState(root) as state:
        retained = state.draft("main", b.path)
        assert retained is not None and retained.baseline_hash == b.baseline_hash
    assert copilot_hook.dispatch("agentStop", event, root)["decision"] == "block"
