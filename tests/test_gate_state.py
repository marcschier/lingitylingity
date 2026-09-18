from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import sqlite3
import subprocess
from threading import Barrier
from typing import Iterator

import pytest

import lingity.gate_state as gate_state_module
from lingity.gate_state import (
    AttemptLimit,
    Draft,
    GateState,
    GateStateError,
    MAX_CONTENT_BYTES,
    MAX_DELEGATIONS,
    MAX_REPAIRS,
    MAX_ROOTS,
    MAX_STOPS,
    StateConflict,
    StopLimit,
    UnsafePath,
    canonical_path,
    content_hash,
)
from lingity.models import JsonValue


IDENTITY = content_hash(b"policy, projection, analyzer, model, and runtime identities")
OTHER_IDENTITY = content_hash(b"different policy")
BASELINE = b"The server must retain 2 records.\r\n"
PASS: dict[str, JsonValue] = {
    "accepted": True, "candidate_sha256": content_hash(BASELINE),
    "baseline_sha256": content_hash(BASELINE),
}
REJECT: dict[str, JsonValue] = {
    **PASS, "accepted": False, "violations": ["low readability"],
}


@pytest.fixture
def state(tmp_path: Path) -> Iterator[GateState]:
    with GateState(tmp_path / "state") as value:
        value.start_session("session", tmp_path)
        value.begin_request("session", "100")
        yield value


def _capture(state: GateState, content: bytes = BASELINE, path: str = "doc.md") -> Draft:
    return state.capture("session", path, content, None)


def _result(
    state: GateState, content: bytes = BASELINE, result: dict[str, JsonValue] = REJECT,
    path: str = "doc.md", identity: str = IDENTITY,
) -> Draft:
    return state.record_result(
        "session", path, content, {**result, "candidate_sha256": content_hash(content)}, identity
    )


def _approve(state: GateState, content: bytes = BASELINE, path: str = "doc.md") -> Draft:
    _result(state, content, PASS, path)
    return state.approve("session", path, content, IDENTITY)


def _evaluation_result(draft: Draft, candidate: bytes, *, accepted: bool = False) -> dict[str, JsonValue]:
    return {
        "accepted": accepted, "candidate_sha256": content_hash(candidate),
        "baseline_sha256": draft.baseline_hash,
    }


def _answer(
    state: GateState, path: str = "a.md", *, session_id: str = "session", event_time: int = 2000,
) -> str:
    draft = state.draft(session_id, path)
    assert draft is not None
    token = content_hash(f"{session_id}:{draft.revision_id}:{event_time}".encode())
    state.stage_decision(session_id, token, path, draft.baseline_hash)
    assert state.resolve_decision(
        session_id, token, content_hash(b"selected wording"), f"answer-{event_time}", event_time=event_time,
    )
    return token


def test_prompt_before_session_start_and_resume_preserve_epoch(tmp_path: Path) -> None:
    with GateState(tmp_path / "state") as value:
        assert value.begin_request("session", "1789720038969") == 1
        value.start_session("session", tmp_path)
        first = _capture(value)
        value.start_session("session", tmp_path, "resume")
        value.start_session("session", tmp_path, "new")
        assert value.begin_request("session", "1789720038969") == 1
        assert _capture(value, b"repair").baseline == first.baseline
        assert value.next_stop("session") == 1


def test_missing_genuine_request_is_explicit_conflict(tmp_path: Path) -> None:
    with GateState(tmp_path / "state") as value:
        value.start_session("session", tmp_path)
        with pytest.raises(StateConflict, match="genuine"):
            _capture(value)
        with pytest.raises(StateConflict, match="genuine"):
            value.next_stop("session")
        value.start_session("other", tmp_path, "resume")
        with pytest.raises(StateConflict, match="genuine"):
            value.capture("other", "doc.md", BASELINE, None)


def test_first_draft_is_frozen_exact_bytes_and_durable(state: GateState, tmp_path: Path) -> None:
    draft = _capture(state)
    assert draft.baseline == BASELINE
    assert draft.baseline_hash == content_hash(BASELINE)
    assert draft.expected_hash is None
    with pytest.raises(FrozenInstanceError):
        setattr(draft, "baseline", b"new baseline")
    _result(state)
    repaired = _capture(state, b"The server must retain 2 records.\n")
    assert repaired.baseline == BASELINE
    with GateState(tmp_path / "state") as resumed:
        resumed.start_session("session", tmp_path, "resume")
        assert resumed.pending("session")[0].baseline == BASELINE
    assert not (tmp_path / "doc.md").exists()
    blobs = [path for path in (tmp_path / "state" / "content").iterdir()]
    assert len(blobs) == 2
    assert all(path.name == content_hash(path.read_bytes()) for path in blobs)


def test_expected_existing_bytes_are_separate_from_first_draft(state: GateState, tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    document.write_bytes(b"previous accepted document")
    draft = state.capture("session", document, BASELINE, document.read_bytes())
    assert draft.baseline == BASELINE
    assert draft.expected_hash == content_hash(b"previous accepted document")
    assert document.read_bytes() == b"previous accepted document"
    _result(state)
    assert state.capture("session", document, b"repair", document.read_bytes()).baseline == BASELINE


def test_distinct_repairs_are_bounded_beyond_baseline(state: GateState) -> None:
    _capture(state)
    assert _result(state).repairs == 0
    for ordinal in range(1, MAX_REPAIRS + 1):
        candidate = f"repair {ordinal}".encode()
        _capture(state, candidate)
        assert _result(state, candidate).repairs == ordinal
        assert _result(state, candidate).repairs == ordinal
        assert _result(state, candidate, identity=OTHER_IDENTITY).repairs == ordinal
    with pytest.raises(AttemptLimit):
        _capture(state, b"fourth repair")
    for candidate in (BASELINE, b"repair 1"):
        _capture(state, candidate)
        assert _result(state, candidate).repairs == MAX_REPAIRS
    assert state.pending("session")[0].baseline == BASELINE


def test_record_result_also_enforces_repair_limit(state: GateState) -> None:
    _capture(state)
    for ordinal in range(3):
        candidate = f"repair {ordinal}".encode()
        _capture(state, candidate)
        _result(state, candidate)
    # An independently delayed evaluator must not count a different active candidate.
    with pytest.raises(StateConflict, match="superseded candidate"):
        _result(state, b"fourth repair")
    assert state.pending("session")[0].repairs == 3


def test_cache_binds_bytes_baseline_epoch_and_external_identity(state: GateState) -> None:
    _capture(state)
    _result(state)
    assert state.cached("session", "doc.md", BASELINE, IDENTITY) == REJECT
    assert state.cached("session", "doc.md", BASELINE, OTHER_IDENTITY) is None
    assert state.cached("session", "doc.md", b"other", IDENTITY) is None
    state.begin_request("session", "101")
    _capture(state)
    assert state.cached("session", "doc.md", BASELINE, IDENTITY) is None
    assert state.pending("session")[0].repairs == 0


def test_cache_cannot_be_rewritten_and_returns_detached_values(state: GateState) -> None:
    _capture(state)
    _result(state)
    cached = state.cached("session", "doc.md", BASELINE, IDENTITY)
    assert cached is not None
    cached["accepted"] = True
    assert state.cached("session", "doc.md", BASELINE, IDENTITY) == REJECT
    with pytest.raises(StateConflict, match="different results"):
        _result(state, result=PASS)
    assert state.pending("session")[0].status == "repair_required"


@pytest.mark.parametrize("accepted", [None, 1, "true", "false", []])
def test_result_acceptance_must_be_a_boolean(state: GateState, accepted: JsonValue) -> None:
    _capture(state)
    with pytest.raises(GateStateError, match="boolean accepted"):
        _result(state, result={**PASS, "accepted": accepted})
    assert state.cached("session", "doc.md", BASELINE, IDENTITY) is None


def test_result_content_identities_cannot_cross_requests(state: GateState) -> None:
    _capture(state)
    _capture(state, b"candidate")
    delayed: dict[str, JsonValue] = {
        **PASS, "candidate_sha256": content_hash(b"candidate"),
    }
    state.begin_request("session", "101")
    _capture(state, b"new authorized baseline")
    _capture(state, b"candidate")
    with pytest.raises(StateConflict, match="different immutable baseline"):
        state.record_result("session", "doc.md", b"candidate", delayed, IDENTITY)
    assert state.cached("session", "doc.md", b"candidate", IDENTITY) is None
    with pytest.raises(StateConflict, match="candidate identity"):
        state.record_result("session", "doc.md", b"candidate", PASS, IDENTITY)


def test_only_first_draft_can_have_an_uncompared_result(state: GateState) -> None:
    _capture(state)
    first: dict[str, JsonValue] = {**PASS, "baseline_sha256": None}
    _result(state, result=first)
    assert state.approve("session", "doc.md", BASELINE, IDENTITY).status == "approved"
    state.failed("session", "doc.md")
    _capture(state, b"repair")
    with pytest.raises(StateConflict, match="different immutable baseline"):
        _result(state, b"repair", first)


@pytest.mark.parametrize("identity", ["", "policy-v1", "a" * 63, "A" * 64, "../" * 22])
def test_invalid_identity_digests_are_rejected(state: GateState, identity: str) -> None:
    _capture(state)
    with pytest.raises(GateStateError, match="SHA-256"):
        _result(state, identity=identity)
    with pytest.raises(GateStateError, match="SHA-256"):
        state.cached("session", "doc.md", BASELINE, identity)


def test_old_and_out_of_order_events_cannot_reset_baselines(state: GateState) -> None:
    _capture(state)
    assert state.begin_request("session", "101") == 2
    new = _capture(state, b"authorized new content")
    assert new.baseline == b"authorized new content"
    with pytest.raises(StateConflict, match="Stale"):
        state.begin_request("session", "100")
    with pytest.raises(StateConflict, match="Out-of-order"):
        state.begin_request("session", "99")
    assert state.pending("session")[0].baseline == b"authorized new content"


def test_new_request_does_not_discard_untouched_rejected_documents(state: GateState) -> None:
    _capture(state)
    _result(state)
    state.begin_request("session", "101")
    assert state.pending("session")[0].baseline == BASELINE
    with pytest.raises(StateConflict, match="previous user-request"):
        state.approve("session", "doc.md", BASELINE, IDENTITY)


def test_full_write_lifecycle_and_following_edit_keep_baseline(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    approved = _approve(state)
    assert approved.status == "approved"
    assert not (tmp_path / "doc.md").exists()
    with pytest.raises(StateConflict, match="Written bytes"):
        state.verify_written("session", "doc.md")
    (tmp_path / "doc.md").write_bytes(BASELINE)
    verified = state.verify_written("session", "doc.md", BASELINE)
    assert verified.status == "verified"
    assert state.pending("session") == []
    assert verified.expected_hash == content_hash(BASELINE)
    assert state.snapshots("session") == {canonical_path(tmp_path / "doc.md"): content_hash(BASELINE)}
    assert state.verify_written("session", "doc.md").status == "verified"
    edited = state.capture("session", "doc.md", b"next repair", BASELINE)
    assert edited.baseline == BASELINE
    assert edited.expected_hash == content_hash(BASELINE)


def test_no_write_can_be_verified_without_approval(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _result(state, result=PASS)
    (tmp_path / "doc.md").write_bytes(BASELINE)
    with pytest.raises(StateConflict, match="prior approval"):
        state.verify_written("session", "doc.md")
    assert len(state.pending("session")) == 1


def test_approval_requires_matching_pass_result(state: GateState) -> None:
    _capture(state)
    with pytest.raises(StateConflict, match="No passing"):
        state.approve("session", "doc.md", BASELINE, IDENTITY)
    _result(state)
    with pytest.raises(StateConflict, match="No passing"):
        state.approve("session", "doc.md", BASELINE, IDENTITY)
    _result(state, result=PASS, identity=OTHER_IDENTITY)
    with pytest.raises(StateConflict, match="No passing"):
        state.approve("session", "doc.md", BASELINE, IDENTITY)
    assert state.approve("session", "doc.md", BASELINE, OTHER_IDENTITY).status == "approved"


def test_failed_write_preserves_baseline_expected_bytes_cache_and_attempts(state: GateState) -> None:
    _capture(state)
    _result(state)
    _capture(state, b"repair")
    _approve(state, b"repair")
    state.failed("session", "doc.md")
    draft = state.pending("session")[0]
    assert draft.status == "failed"
    assert draft.baseline == BASELINE
    assert draft.repairs == 1
    assert draft.expected_hash is None
    assert state.cached("session", "doc.md", b"repair", IDENTITY) == {
        **PASS, "candidate_sha256": content_hash(b"repair"),
    }
    assert state.approve("session", "doc.md", b"repair", IDENTITY).status == "approved"


def test_failed_tool_cannot_verify_partial_write(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _approve(state)
    (tmp_path / "doc.md").write_bytes(b"partial write")
    state.failed("session", "doc.md")
    with pytest.raises(StateConflict, match="expected prior"):
        state.approve("session", "doc.md", BASELINE, IDENTITY)
    assert state.pending("session")[0].baseline == BASELINE
    assert (tmp_path / "doc.md").read_bytes() == b"partial write"


def test_capture_rejects_stale_observation(state: GateState, tmp_path: Path) -> None:
    (tmp_path / "doc.md").write_bytes(b"human change")
    with pytest.raises(StateConflict, match="stale"):
        _capture(state)
    assert state.pending("session") == []
    assert (tmp_path / "doc.md").read_bytes() == b"human change"


@pytest.mark.parametrize("change", [b"human change", None])
def test_approval_rechecks_expected_destination(
    state: GateState, tmp_path: Path, change: bytes | None,
) -> None:
    document = tmp_path / "doc.md"
    document.write_bytes(b"original")
    state.capture("session", document, BASELINE, b"original")
    _result(state, result=PASS)
    if change is None:
        document.unlink()
    else:
        document.write_bytes(change)
    with pytest.raises(StateConflict, match="expected prior"):
        state.approve("session", document, BASELINE, IDENTITY)
    with pytest.raises(StateConflict, match="expected prior"):
        state.capture("session", document, b"repair", change)
    assert state.pending("session")[0].baseline == BASELINE


def test_pending_approved_write_cannot_be_replaced_or_superseded(state: GateState) -> None:
    _capture(state)
    _approve(state)
    with pytest.raises(StateConflict, match="pending verification"):
        _capture(state, b"replacement")
    state.begin_request("session", "101")
    with pytest.raises(StateConflict, match="in flight"):
        _capture(state, b"replacement")
    assert state.pending("session")[0].baseline == BASELINE


def test_rechecking_verified_content_does_not_reuse_old_policy_status(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _approve(state)
    (tmp_path / "doc.md").write_bytes(BASELINE)
    state.verify_written("session", "doc.md")
    state.capture("session", "doc.md", BASELINE, BASELINE)
    _result(state, result=REJECT, identity=OTHER_IDENTITY)
    assert state.pending("session")[0].status == "repair_required"


def test_deletion_does_not_clear_rejected_record(state: GateState, tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    document.write_bytes(b"existing")
    state.capture("session", document, BASELINE, b"existing")
    _result(state)
    document.unlink()
    state.update_snapshot("session", document, None)
    with pytest.raises(StateConflict):
        state.verify_written("session", document)
    assert state.pending("session")[0].baseline == BASELINE
    assert state.pending("session")[0].status == "repair_required"


def test_observe_new_shell_document_captures_first_complete_bytes(state: GateState, tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    document.write_bytes(BASELINE)
    draft = state.observe("session", document, BASELINE, None)
    assert draft.baseline == BASELINE
    assert draft.expected_hash == content_hash(BASELINE)
    assert draft.status == "captured"
    assert state.snapshots("session")[canonical_path(document)] == content_hash(BASELINE)
    _approve(state)
    assert state.verify_written("session", document).status == "verified"


def test_observe_rejected_editor_draft_materialized_by_shell_preserves_baseline(
    state: GateState, tmp_path: Path,
) -> None:
    _capture(state)
    _result(state)
    document = tmp_path / "doc.md"
    document.write_bytes(BASELINE)
    observed = state.observe("session", document, BASELINE, None)
    assert observed.baseline == BASELINE
    assert observed.status == "repair_required"
    assert observed.expected_hash == content_hash(BASELINE)
    assert state.observe("session", document, BASELINE, None) == observed
    repaired = state.capture("session", document, b"native repair", BASELINE)
    assert repaired.baseline == BASELINE
    assert repaired.expected_hash == content_hash(BASELINE)


def test_shell_repairs_preserve_baseline_and_distinct_attempt_limit(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _result(state)
    document = tmp_path / "doc.md"
    previous: str | None = None
    for number in range(3):
        current = f"shell repair {number}".encode()
        document.write_bytes(current)
        observed = state.observe("session", document, current, previous)
        assert observed.baseline == BASELINE
        assert _result(state, current).repairs == number + 1
        previous = content_hash(current)
    document.write_bytes(b"fourth shell repair")
    with pytest.raises(AttemptLimit):
        state.observe("session", document, document.read_bytes(), previous)
    assert state.pending("session")[0].repairs == 3
    assert document.read_bytes() == b"fourth shell repair"


def test_observe_cannot_adopt_stale_snapshot_or_unexpected_prior_bytes(state: GateState, tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    document.write_bytes(b"original")
    state.capture("session", document, BASELINE, b"original")
    state.update_snapshot("session", document, content_hash(b"original"))
    document.write_bytes(b"shell change")
    with pytest.raises(StateConflict, match="Pre-shell snapshot"):
        state.observe("session", document, document.read_bytes(), None)
    state.update_snapshot("session", document, content_hash(b"unrelated human change"))
    with pytest.raises(StateConflict, match="tracked expected"):
        state.observe("session", document, document.read_bytes(), content_hash(b"unrelated human change"))
    assert state.pending("session")[0].expected_hash == content_hash(b"original")
    assert document.read_bytes() == b"shell change"


def test_observe_checks_current_bytes_and_foreign_ownership(state: GateState, tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    _capture(state)
    document.write_bytes(BASELINE)
    with pytest.raises(StateConflict, match="no longer match"):
        state.observe("session", document, b"outdated observation", None)
    state.start_session("other", tmp_path)
    state.begin_request("other", "100")
    with pytest.raises(StateConflict, match="another session"):
        state.observe("other", document, BASELINE, None)
    assert state.pending("session")[0].baseline == BASELINE


def test_observe_matching_approved_bytes_verifies_instead_of_resetting(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _approve(state)
    document = tmp_path / "doc.md"
    document.write_bytes(BASELINE)
    observed = state.observe("session", document, BASELINE, None)
    assert observed.status == "verified"
    assert observed.baseline == BASELINE
    assert state.pending("session") == []


def test_observe_mismatched_approved_bytes_is_a_conflict(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _approve(state)
    document = tmp_path / "doc.md"
    document.write_bytes(b"unexpected shell content")
    with pytest.raises(StateConflict, match="previously approved"):
        state.observe("session", document, document.read_bytes(), None)
    assert state.pending("session")[0].status == "approved"
    assert state.pending("session")[0].expected_hash is None


def test_shell_observation_can_start_a_genuine_new_owned_revision(state: GateState, tmp_path: Path) -> None:
    document = tmp_path / "doc.md"
    _capture(state)
    _result(state)
    state.bind_prompt("session", "101", content_hash(b"genuine new request"), tmp_path)
    document.write_bytes(b"new authorized first complete draft")
    observed = state.observe("session", document, document.read_bytes(), None)
    assert observed.epoch == 2
    assert observed.baseline == b"new authorized first complete draft"
    assert observed.repairs == 0


def test_tracked_includes_current_verified_and_unresolved_previous_request_documents(
    state: GateState, tmp_path: Path,
) -> None:
    assert state.draft("session", "unknown.md") is None
    _capture(state)
    _approve(state)
    (tmp_path / "doc.md").write_bytes(BASELINE)
    state.verify_written("session", "doc.md")
    verified = state.tracked("session")[0]
    assert verified.status == "verified"
    _capture(state, path="unresolved.md")
    _result(state, path="unresolved.md")
    state.begin_request("session", "101")
    assert len(state.pending("session")) == 1
    tracked = state.tracked("session")
    assert len(tracked) == 1
    assert tracked[0].status == "repair_required"
    assert tracked[0].epoch == 1
    assert state.draft("session", "doc.md") == verified
    _capture(state, path="second.md")
    with pytest.raises(StateConflict, match="enumeration limit"):
        state.tracked("session", limit=1)


def test_operation_manifest_persists_and_verifies_only_matching_paths(state: GateState, tmp_path: Path) -> None:
    for path in ("one.md", "two.md"):
        _capture(state, path=path)
        _approve(state, path=path)
    state.stage_operation("session", "operation-one", ["one.md"])
    state.stage_operation("session", "operation-two", ["two.md"])
    assert state.operation_paths("session", "unknown-tool-event") == []
    with GateState(tmp_path / "state") as reopened:
        assert reopened.operation_paths("session", "operation-one") == [canonical_path(tmp_path / "one.md")]
        (tmp_path / "one.md").write_bytes(BASELINE)
        completed = reopened.complete_operation("session", "operation-one")
        assert len(completed) == 1
        assert completed[0].status == "verified"
        assert reopened.operation_paths("session", "operation-one") == []
        assert reopened.complete_operation("session", "operation-one") == []
        pending = reopened.pending("session")
        assert len(pending) == 1
        assert pending[0].path == canonical_path(tmp_path / "two.md")
        assert pending[0].status == "approved"


def test_operation_multi_file_verification_is_transactional(state: GateState, tmp_path: Path) -> None:
    for path in ("one.md", "two.md"):
        _capture(state, path=path)
        _approve(state, path=path)
    state.stage_operation("session", "operation", ["one.md", "two.md"])
    (tmp_path / "one.md").write_bytes(BASELINE)
    (tmp_path / "two.md").write_bytes(b"unexpected")
    with pytest.raises(StateConflict, match="Written bytes"):
        state.complete_operation("session", "operation")
    assert all(draft.status == "approved" for draft in state.pending("session"))
    assert state.snapshots("session") == {}
    assert len(state.operation_paths("session", "operation")) == 2


def test_failed_operation_retains_baselines_and_can_retry_same_token(state: GateState) -> None:
    _capture(state)
    _approve(state)
    state.stage_operation("session", "operation", ["doc.md"])
    state.fail_operation("session", "operation")
    failed = state.pending("session")[0]
    assert failed.status == "failed"
    assert failed.baseline == BASELINE
    assert state.operation_paths("session", "operation") == []
    _approve(state)
    state.stage_operation("session", "operation", ["doc.md"])
    assert len(state.operation_paths("session", "operation")) == 1


def test_operation_requires_approved_unique_paths_and_rejects_overlapping_writes(state: GateState) -> None:
    _capture(state)
    with pytest.raises(StateConflict, match="approved"):
        state.stage_operation("session", "operation", ["doc.md"])
    _approve(state)
    with pytest.raises(StateConflict, match="same canonical"):
        state.stage_operation("session", "operation", ["doc.md", "doc.md"])
    state.stage_operation("session", "operation", ["doc.md"])
    state.stage_operation("session", "operation", ["doc.md"])
    with pytest.raises(StateConflict, match="Another pending operation"):
        state.stage_operation("session", "overlapping-operation", ["doc.md"])


def test_operation_manifest_cannot_follow_superseded_candidate_or_epoch(state: GateState) -> None:
    _capture(state)
    _approve(state)
    state.stage_operation("session", "operation", ["doc.md"])
    state.failed("session", "doc.md")
    _capture(state, b"different candidate")
    with pytest.raises(StateConflict, match="superseded"):
        state.operation_paths("session", "operation")
    with pytest.raises(StateConflict, match="superseded"):
        state.complete_operation("session", "operation")
    state.begin_request("session", "101")
    with pytest.raises(StateConflict, match="previous request"):
        state.operation_paths("session", "operation")
    state.finish_operation("session", "operation")
    assert state.operation_paths("session", "operation") == []
    assert state.pending("session")[0].baseline == BASELINE


def test_finish_operation_only_retires_manifest_and_never_clears_pending(state: GateState) -> None:
    _capture(state)
    _approve(state)
    state.stage_operation("session", "operation", ["doc.md"])
    state.finish_operation("session", "operation")
    state.finish_operation("session", "non-writing-tool-event")
    assert state.operation_paths("session", "operation") == []
    assert state.pending("session")[0].status == "approved"


def test_rename_retains_draft_attempts_cache_and_old_alias(state: GateState) -> None:
    _capture(state)
    _result(state)
    _capture(state, b"repair")
    _result(state, b"repair")
    moved = state.move("session", "doc.md", "renamed.markdown")
    assert moved.baseline == BASELINE
    assert moved.repairs == 1
    assert moved.path.endswith("renamed.markdown")
    assert state.cached("session", "renamed.markdown", b"repair", IDENTITY) == {
        **REJECT, "candidate_sha256": content_hash(b"repair"),
    }
    with pytest.raises(StateConflict, match="old path alias"):
        _capture(state, path="doc.md")
    assert len(state.pending("session")) == 1
    assert state.move("session", "doc.md", "renamed.markdown") == moved


def test_existing_document_rename_checks_both_paths(state: GateState, tmp_path: Path) -> None:
    source, destination = tmp_path / "doc.md", tmp_path / "renamed.md"
    source.write_bytes(BASELINE)
    state.capture("session", source, BASELINE, BASELINE)
    _result(state, result=PASS)
    moved = state.move("session", source, destination)
    assert moved.expected_hash is None
    state.approve("session", destination, BASELINE, IDENTITY)
    destination.write_bytes(BASELINE)
    with pytest.raises(StateConflict, match="source still exists"):
        state.verify_written("session", destination)
    source.unlink()
    assert state.verify_written("session", destination).status == "verified"


def test_rename_never_overwrites_an_existing_or_tracked_destination(
    state: GateState, tmp_path: Path,
) -> None:
    _capture(state)
    (tmp_path / "occupied.md").write_bytes(b"human")
    with pytest.raises(StateConflict, match="already exists"):
        state.move("session", "doc.md", "occupied.md")
    _capture(state, path="tracked.md")
    with pytest.raises(StateConflict, match="tracked"):
        state.move("session", "doc.md", "tracked.md")
    assert len(state.pending("session")) == 2
    assert (tmp_path / "occupied.md").read_bytes() == b"human"


def test_rename_source_mutation_blocks_approval(state: GateState, tmp_path: Path) -> None:
    source = tmp_path / "doc.md"
    source.write_bytes(b"original")
    state.capture("session", source, BASELINE, b"original")
    _result(state, result=PASS)
    state.move("session", source, "renamed.md")
    source.write_bytes(b"human")
    with pytest.raises(StateConflict, match="Rename source"):
        state.approve("session", "renamed.md", BASELINE, IDENTITY)


def test_failed_rename_restores_only_metadata_and_preserves_target_bound_result(
    state: GateState, tmp_path: Path,
) -> None:
    source, destination = tmp_path / "doc.md", tmp_path / "renamed.md"
    original, repair = b"existing source bytes", b"passing repair bytes"
    source.write_bytes(original)
    state.capture("session", source, BASELINE, original)
    _result(state)
    state.capture("session", source, repair, original)
    target_identity = content_hash((IDENTITY + canonical_path(destination)).encode())
    report: dict[str, JsonValue] = {**PASS, "candidate_sha256": content_hash(repair)}
    state.record_result("session", source, repair, report, target_identity)
    state.move("session", source, destination)
    state.approve("session", destination, repair, target_identity)
    state.stage_operation("session", "rename-operation", [destination])
    assert state.operation_paths("session", "rename-operation") == [canonical_path(destination)]
    state.fail_operation("session", "rename-operation")
    restored = state.draft("session", source)
    assert restored is not None
    assert restored.path == canonical_path(source)
    assert restored.baseline == BASELINE
    assert restored.candidate_hash == content_hash(repair)
    assert restored.expected_hash == content_hash(original)
    assert restored.repairs == 1
    assert restored.status == "failed"
    assert state.draft("session", destination) is None
    assert state.operation_paths("session", "rename-operation") == []
    assert state.cached("session", source, repair, target_identity) == report
    assert source.read_bytes() == original
    assert not destination.exists()
    state.move("session", source, destination)
    assert state.approve("session", destination, repair, target_identity).baseline == BASELINE


@pytest.mark.parametrize("changed_path", ["source", "destination", "source-deleted"])
def test_failed_rename_does_not_undo_reservation_after_filesystem_change(
    state: GateState, tmp_path: Path, changed_path: str,
) -> None:
    source, destination = tmp_path / "doc.md", tmp_path / "renamed.md"
    original = b"existing source bytes"
    source.write_bytes(original)
    state.capture("session", source, BASELINE, original)
    _result(state, result=PASS)
    state.move("session", source, destination)
    state.approve("session", destination, BASELINE, IDENTITY)
    if changed_path == "source":
        source.write_bytes(b"human change")
    elif changed_path == "destination":
        destination.write_bytes(BASELINE)
    else:
        source.unlink()
    with pytest.raises(StateConflict, match="reservation cannot be undone"):
        state.failed("session", destination)
    reserved = state.draft("session", destination)
    assert reserved is not None
    assert reserved.path == canonical_path(destination)
    assert reserved.status == "approved"
    assert reserved.baseline == BASELINE
    if changed_path == "source":
        assert source.read_bytes() == b"human change"
    elif changed_path == "destination":
        assert destination.read_bytes() == BASELINE
    else:
        assert not source.exists()


def test_failed_unexecuted_rename_can_restore_a_draft_with_no_source_file(state: GateState) -> None:
    _capture(state)
    _result(state)
    state.move("session", "doc.md", "renamed.md")
    state.failed("session", "renamed.md")
    restored = state.draft("session", "doc.md")
    assert restored is not None
    assert restored.baseline == BASELINE
    assert restored.expected_hash is None
    assert state.draft("session", "renamed.md") is None
    assert state.pending("session") == [restored]


def test_concurrent_session_cannot_release_rejected_record_or_alias(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _result(state)
    state.move("session", "doc.md", "renamed.md")
    state.start_session("other", tmp_path)
    state.begin_request("other", "200")
    for name in ("doc.md", "renamed.md"):
        with pytest.raises(StateConflict):
            state.capture("other", name, b"unrelated baseline", None)
    assert state.pending("session")[0].baseline == BASELINE
    assert state.pending("other") == []


def test_verified_document_can_have_new_genuine_session_revision(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _approve(state)
    (tmp_path / "doc.md").write_bytes(BASELINE)
    state.verify_written("session", "doc.md")
    state.start_session("other", tmp_path)
    state.begin_request("other", "200")
    new = state.capture("other", "doc.md", b"authorized revision", BASELINE)
    assert new.baseline == b"authorized revision"
    assert new.expected_hash == content_hash(BASELINE)
    with pytest.raises(StateConflict, match="another session"):
        state.cached("session", "doc.md", BASELINE, IDENTITY)


def test_child_shares_epoch_baseline_attempts_roots_and_stop_bound(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _result(state)
    state.start_session("child", tmp_path, "child")
    state.bind_child("child", "session", tmp_path)
    assert state.capture("child", "doc.md", b"repair", None).baseline == BASELINE
    state.record_result(
        "child", "doc.md", b"repair", {**REJECT, "candidate_sha256": content_hash(b"repair")}, IDENTITY
    )
    assert state.pending("session")[0].repairs == 1
    assert state.pending("child") == state.pending("session")
    assert state.session_roots("child") == state.session_roots("session")
    with pytest.raises(StateConflict, match="child event"):
        state.begin_request("child", "1000")
    for ordinal in range(1, MAX_STOPS + 1):
        owner = "session" if ordinal % 2 else "child"
        state.start_session(owner, tmp_path, "resume")
        assert state.next_stop(owner) == ordinal
    with pytest.raises(StopLimit):
        state.next_stop("session")
    with pytest.raises(StopLimit):
        state.next_stop("child")
    state.begin_request("session", "101")
    with pytest.raises(StateConflict, match="previous user-request"):
        state.next_stop("child")
    with pytest.raises(StateConflict, match="previous user-request"):
        state.capture("child", "doc.md", b"stale child edit", None)
    assert state.next_stop("session") == 1
    assert state.pending("session")[0].baseline == BASELINE


def test_child_with_its_own_epoch_cannot_be_rebound(state: GateState, tmp_path: Path) -> None:
    state.start_session("other", tmp_path)
    state.begin_request("other", "200")
    with pytest.raises(StateConflict, match="different request owner"):
        state.bind_child("other", "session", tmp_path)


def test_unknown_prompt_is_staged_until_main_session_start(tmp_path: Path) -> None:
    digest = content_hash(b"synthetic genuine user instruction")
    with GateState(tmp_path / "state") as value:
        assert value.bind_prompt("session", "100", digest, tmp_path) == "staged"
        assert value.bind_prompt("session", "100", digest, tmp_path) == "staged"
        with pytest.raises(StateConflict, match="session-start proof"):
            value.begin_request("session", "100")
        with pytest.raises(StateConflict, match="genuine"):
            _capture(value)
        value.start_session("session", tmp_path)
        assert _capture(value).epoch == 1
        assert value.bind_prompt("session", "100", digest, tmp_path) == "main"
        value.start_session("session", tmp_path, "resume")
        assert value.pending("session")[0].epoch == 1
        assert value.bind_prompt("session", "101", digest, tmp_path) == "main"
        assert _capture(value, b"authorized revision").epoch == 2
        with pytest.raises(StateConflict, match="Stale"):
            value.bind_prompt("session", "100", digest, tmp_path)


def test_staged_prompt_does_not_gain_epoch_from_child_start(tmp_path: Path) -> None:
    with GateState(tmp_path / "state") as value:
        value.bind_prompt("session", "100", content_hash(b"unknown"), tmp_path)
        value.start_session("session", tmp_path, "child")
        with pytest.raises(StateConflict, match="genuine"):
            _capture(value)
        with pytest.raises(StateConflict, match="Multiple unproven"):
            value.bind_prompt("session", "101", content_hash(b"another unknown"), tmp_path)


def test_staged_prompt_start_requires_same_directory(tmp_path: Path) -> None:
    with GateState(tmp_path / "state") as value:
        value.bind_prompt("session", "100", content_hash(b"unknown"), tmp_path)
        with pytest.raises(StateConflict, match="staged prompt directory"):
            value.start_session("session", tmp_path / "other")
        with pytest.raises(StateConflict, match="genuine"):
            _capture(value)
        value.start_session("session", tmp_path)
        assert _capture(value).epoch == 1


def test_delegated_child_prompt_binds_without_session_start_and_never_resets(
    state: GateState, tmp_path: Path,
) -> None:
    _capture(state)
    _result(state)
    digest = content_hash(b"synthetic child instruction")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    assert state.bind_prompt("child", "200", digest, tmp_path) == "child"
    child = state.capture("child", "doc.md", b"repair", None)
    assert child.baseline == BASELINE
    assert child.epoch == 1
    assert child.session_id == "session"
    assert state.bind_prompt("child", "200", digest, tmp_path) == "child"
    assert state.next_stop("child") == 1
    state.finish_delegation("session", "operation-1")
    state.finish_delegation("session", "operation-1")
    assert state.bind_prompt("child", "201", content_hash(b"follow-up"), tmp_path) == "child"
    assert state.next_stop("session") == 2
    assert state.pending("child")[0].baseline == BASELINE
    with pytest.raises(StateConflict, match="child event"):
        state.begin_request("child", "202")


def test_ambiguous_delegation_digest_cannot_authorize_child_edits(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"identical child instruction")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    state.register_delegation("session", "operation-2", digest, tmp_path)
    with pytest.raises(StateConflict, match="multiple outstanding delegations"):
        state.bind_prompt("child", "200", digest, tmp_path)
    with pytest.raises(StateConflict, match="Unknown session"):
        state.capture("child", "doc.md", BASELINE, None)
    state.finish_delegation("session", "operation-2", failed=True)
    assert state.bind_prompt("child", "200", digest, tmp_path) == "child"


def test_matching_prompt_across_concurrent_parents_is_ambiguous(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"identical child instruction")
    state.start_session("other", tmp_path)
    state.begin_request("other", "100")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    state.register_delegation("other", "operation-1", digest, tmp_path)
    with pytest.raises(StateConflict, match="multiple outstanding"):
        state.bind_prompt("child", "200", digest, tmp_path)


def test_delegation_match_requires_exact_digest_and_cwd(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"child instruction")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    assert state.bind_prompt("different-prompt", "200", content_hash(b"other"), tmp_path) == "staged"
    assert state.bind_prompt("different-cwd", "200", digest, tmp_path / "other") == "staged"
    for child in ("different-prompt", "different-cwd"):
        with pytest.raises(StateConflict, match="genuine"):
            state.capture(child, tmp_path / "doc.md", BASELINE, None)
    assert state.bind_prompt("correct-child", "200", digest, tmp_path) == "child"


def test_one_delegation_cannot_claim_two_child_sessions(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"child instruction")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    assert state.bind_prompt("child", "200", digest, tmp_path) == "child"
    with pytest.raises(StateConflict, match="different child session"):
        state.bind_prompt("another-child", "200", digest, tmp_path)


def test_child_and_outstanding_delegation_are_pinned_to_parent_epoch(
    state: GateState, tmp_path: Path,
) -> None:
    digest = content_hash(b"child instruction")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    state.bind_prompt("child", "200", digest, tmp_path)
    state.register_delegation("session", "operation-2", content_hash(b"another task"), tmp_path)
    state.bind_prompt("session", "101", content_hash(b"genuine new request"), tmp_path)
    with pytest.raises(StateConflict, match="previous user-request"):
        state.bind_prompt("child", "201", digest, tmp_path)
    with pytest.raises(StateConflict, match="previous user-request"):
        state.bind_prompt("another-child", "300", content_hash(b"another task"), tmp_path)
    with pytest.raises(StateConflict, match="owner or epoch"):
        state.bind_child("child", "session", tmp_path)
    state.finish_delegation("session", "operation-1")
    state.finish_delegation("session", "operation-2")


def test_prompt_metadata_replay_mismatch_is_a_conflict(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"user instruction")
    assert state.bind_prompt("session", "101", digest, tmp_path) == "main"
    with pytest.raises(StateConflict, match="different correlation metadata"):
        state.bind_prompt("session", "101", content_hash(b"altered instruction"), tmp_path)
    with pytest.raises(StateConflict, match="different correlation metadata"):
        state.bind_prompt("session", "101", digest, tmp_path / "different")


def test_known_main_prompt_is_not_mistaken_for_matching_child_task(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"same words")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    assert state.bind_prompt("session", "101", digest, tmp_path) == "main"
    assert _capture(state).epoch == 2


def test_finished_delegation_is_not_reopened_by_duplicate_registration(
    state: GateState, tmp_path: Path,
) -> None:
    digest = content_hash(b"child instruction")
    state.register_delegation("session", "operation-1", digest, tmp_path)
    state.register_delegation("session", "operation-1", digest, tmp_path)
    state.finish_delegation("session", "operation-1", failed=True)
    state.register_delegation("session", "operation-1", digest, tmp_path)
    assert state.bind_prompt("unknown", "200", digest, tmp_path) == "staged"
    with pytest.raises(StateConflict, match="different operation"):
        state.register_delegation("session", "operation-1", content_hash(b"different task"), tmp_path)
    with pytest.raises(StateConflict, match="Unknown delegation"):
        state.finish_delegation("session", "unknown-operation")


def test_nested_delegations_share_one_root_request_and_budget(state: GateState, tmp_path: Path) -> None:
    child_prompt, grandchild_prompt = content_hash(b"child"), content_hash(b"grandchild")
    state.register_delegation("session", "operation-1", child_prompt, tmp_path)
    state.bind_prompt("child", "200", child_prompt, tmp_path)
    state.register_delegation("child", "operation-2", grandchild_prompt, tmp_path)
    assert state.bind_prompt("grandchild", "300", grandchild_prompt, tmp_path) == "child"
    assert state.capture("grandchild", "doc.md", BASELINE, None).session_id == "session"
    assert state.next_stop("grandchild") == 1
    assert state.next_stop("child") == 2
    assert state.next_stop("session") == 3
    state.finish_delegation("session", "operation-1")
    assert state.pending("grandchild")[0].baseline == BASELINE


def test_delegation_enumeration_is_bounded(state: GateState, tmp_path: Path) -> None:
    for number in range(MAX_DELEGATIONS):
        state.register_delegation("session", str(number), content_hash(str(number).encode()), tmp_path)
    with pytest.raises(StateConflict, match="delegation limit"):
        state.register_delegation("session", "overflow", content_hash(b"overflow"), tmp_path)
    state.finish_delegation("session", "0", failed=True)
    state.register_delegation("session", "overflow", content_hash(b"overflow"), tmp_path)


def test_successful_background_launch_can_bind_its_child_after_parent_post_tool(
    state: GateState, tmp_path: Path,
) -> None:
    _capture(state)
    _result(state)
    digest = content_hash(b"background task")
    state.register_delegation("session", "background-operation", digest, tmp_path)
    state.finish_delegation("session", "background-operation")
    state.finish_delegation("session", "background-operation")
    assert state.bind_prompt("child", "200", digest, tmp_path) == "child"
    assert state.capture("child", "doc.md", b"child repair", None).baseline == BASELINE
    assert state.bind_prompt("another-session", "300", digest, tmp_path) == "staged"
    assert state.next_stop("child") == 1
    assert state.next_stop("session") == 2


def test_failed_background_launch_does_not_leave_a_claim(state: GateState, tmp_path: Path) -> None:
    digest = content_hash(b"failed background task")
    state.register_delegation("session", "background-operation", digest, tmp_path)
    state.finish_delegation("session", "background-operation", failed=True)
    assert state.bind_prompt("unknown-session", "200", digest, tmp_path) == "staged"
    with pytest.raises(StateConflict, match="genuine"):
        state.capture("unknown-session", "doc.md", BASELINE, None)


def test_child_correlation_survives_database_reopen_without_prompt_text(
    state: GateState, tmp_path: Path,
) -> None:
    secret = b"Synthetic prompt text that must never be persisted."
    digest = content_hash(secret)
    state.register_delegation("session", "operation-1", digest, tmp_path)
    state.bind_prompt("child", "200", digest, tmp_path)
    with GateState(tmp_path / "state") as reopened:
        assert reopened.bind_prompt("child", "200", digest, tmp_path) == "child"
        assert reopened.capture("child", "doc.md", BASELINE, None).session_id == "session"
    assert secret not in (tmp_path / "state" / "state.sqlite3").read_bytes()


def test_stop_echo_consumes_expected_prompt_without_resetting_request(
    state: GateState, tmp_path: Path,
) -> None:
    _capture(state)
    _result(state)
    reason = content_hash(b"Repair the draft. [lingity-continuation:synthetic-unique-nonce]")
    assert state.next_stop("session") == 1
    state.expect_continuation("session", reason)
    state.expect_continuation("session", reason)
    assert state.bind_prompt("session", "200", reason, tmp_path) == "continuation"
    assert state.bind_prompt("session", "200", reason, tmp_path) == "continuation"
    assert state.begin_request("session", "200") == 1
    state.start_session("session", tmp_path, "resume")
    draft = _capture(state, b"repair")
    assert draft.baseline == BASELINE
    assert draft.epoch == 1
    assert state.next_stop("session") == 2


def test_stop_echoes_cannot_reset_stop_or_distinct_repair_bounds(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _result(state)
    for number in range(3):
        candidate = f"repair {number}".encode()
        _capture(state, candidate)
        _result(state, candidate)
    for number in range(1, MAX_STOPS + 1):
        reason = content_hash(f"Unique stop reason nonce {number}".encode())
        assert state.next_stop("session", reason) == number
        assert state.bind_prompt("session", str(200 + number), reason, tmp_path) == "continuation"
    with pytest.raises(StopLimit):
        state.next_stop("session", content_hash(b"seventh nonce"))
    with pytest.raises(AttemptLimit):
        _capture(state, b"fourth distinct repair")
    assert state.pending("session")[0].epoch == 1
    assert state.pending("session")[0].repairs == 3
    assert state.bind_prompt("session", "300", content_hash(b"genuine user revision"), tmp_path) == "main"
    state.start_session("session", tmp_path, "resume")
    assert _capture(state, b"authorized new baseline").epoch == 2
    assert state.next_stop("session") == 1


def test_child_stop_echo_shares_parent_budget_without_new_epoch(state: GateState, tmp_path: Path) -> None:
    task = content_hash(b"child task")
    state.register_delegation("session", "operation-1", task, tmp_path)
    state.bind_prompt("child", "200", task, tmp_path)
    _capture(state)
    reason = content_hash(b"child continuation nonce")
    assert state.next_stop("child", reason) == 1
    assert state.bind_prompt("child", "201", reason, tmp_path) == "continuation"
    assert state.capture("child", "doc.md", b"child repair", None).baseline == BASELINE
    assert state.next_stop("session") == 2
    assert state.pending("child")[0].epoch == 1


def test_consumed_or_stale_reason_cannot_become_a_new_user_request(state: GateState, tmp_path: Path) -> None:
    reason = content_hash(b"single-use continuation nonce")
    state.next_stop("session", reason)
    state.bind_prompt("session", "200", reason, tmp_path)
    with pytest.raises(StateConflict, match="already consumed"):
        state.bind_prompt("session", "201", reason, tmp_path)
    with pytest.raises(StateConflict, match="reused"):
        state.expect_continuation("session", reason)
    assert _capture(state).epoch == 1
    state.bind_prompt("session", "300", content_hash(b"genuine new request"), tmp_path)
    with pytest.raises(StateConflict, match="previous user-request"):
        state.bind_prompt("session", "200", reason, tmp_path)
    assert _capture(state, b"new baseline").epoch == 2


def test_pending_stale_reason_cannot_reset_a_new_request(state: GateState, tmp_path: Path) -> None:
    reason = content_hash(b"delayed continuation nonce")
    state.next_stop("session", reason)
    state.bind_prompt("session", "300", content_hash(b"genuine new request"), tmp_path)
    with pytest.raises(StateConflict, match="previous user-request"):
        state.bind_prompt("session", "400", reason, tmp_path)
    assert _capture(state).epoch == 2
    assert state.next_stop("session") == 1


def test_continuation_is_bound_to_session_and_directory(state: GateState, tmp_path: Path) -> None:
    reason = content_hash(b"scoped continuation nonce")
    state.next_stop("session", reason)
    state.start_session("other", tmp_path)
    state.begin_request("other", "100")
    with pytest.raises(StateConflict, match="different session"):
        state.bind_prompt("other", "200", reason, tmp_path)
    with pytest.raises(StateConflict, match="session directory"):
        state.bind_prompt("session", "200", reason, tmp_path / "other")
    assert state.bind_prompt("session", "200", reason, tmp_path) == "continuation"


def test_continuation_registration_requires_own_counted_stop(state: GateState, tmp_path: Path) -> None:
    reason = content_hash(b"counted continuation nonce")
    with pytest.raises(StateConflict, match="reserved next_stop"):
        state.expect_continuation("session", reason)
    task = content_hash(b"child task")
    state.register_delegation("session", "operation-1", task, tmp_path)
    state.bind_prompt("child", "200", task, tmp_path)
    assert state.next_stop("child") == 1
    with pytest.raises(StateConflict, match="reserved next_stop"):
        state.expect_continuation("session", reason)
    assert state.next_stop("session") == 2
    state.expect_continuation("session", reason)
    state.expect_continuation("child", content_hash(b"child counted nonce"))


def test_reason_registration_and_consumption_survive_reopen_without_reason_text(
    state: GateState, tmp_path: Path,
) -> None:
    reason_text = b"Synthetic private feedback [lingity-continuation:random-test-nonce]"
    reason = content_hash(reason_text)
    _capture(state)
    state.next_stop("session", reason)
    with GateState(tmp_path / "state") as reopened:
        assert reopened.bind_prompt("session", "200", reason, tmp_path) == "continuation"
        assert reopened.next_stop("session") == 2
        assert reopened.pending("session")[0].baseline == BASELINE
    assert reason_text not in (tmp_path / "state" / "state.sqlite3").read_bytes()


def test_atomic_stop_registration_rolls_back_on_reused_reason(state: GateState, tmp_path: Path) -> None:
    reason = content_hash(b"unique continuation nonce")
    assert state.next_stop("session", reason) == 1
    state.bind_prompt("session", "200", reason, tmp_path)
    with pytest.raises(StateConflict, match="reused"):
        state.next_stop("session", reason)
    assert state.next_stop("session", content_hash(b"new unique nonce")) == 2


def test_snapshot_and_pending_enumerations_are_bounded_without_omission(state: GateState, tmp_path: Path) -> None:
    for name in ("one.md", "two.md"):
        _capture(state, path=name)
        state.update_snapshot("session", name, content_hash(name.encode()))
    with pytest.raises(StateConflict, match="enumeration limit"):
        state.pending("session", limit=1)
    with pytest.raises(StateConflict, match="enumeration limit"):
        state.snapshots("session", limit=1)
    assert len(state.pending("session", limit=2)) == 2
    assert len(state.snapshots("session", limit=2)) == 2
    state.update_snapshot("session", "one.md", None)
    assert state.snapshots("session")[canonical_path(tmp_path / "one.md")] is None
    assert len(state.pending("session")) == 2
    for bound in (0, -1, 10001):
        with pytest.raises(GateStateError, match="bound"):
            state.pending("session", limit=bound)
        with pytest.raises(GateStateError, match="bound"):
            state.snapshots("session", limit=bound)


def test_root_registration_is_deduplicated_shared_and_bounded(state: GateState, tmp_path: Path) -> None:
    state.register_root("session", tmp_path)
    assert state.session_roots("session") == [canonical_path(tmp_path)]
    for ordinal in range(MAX_ROOTS - 1):
        state.register_root("session", tmp_path / str(ordinal))
    with pytest.raises(StateConflict, match="Known-root limit"):
        state.register_root("session", tmp_path / "one-too-many")
    assert len(state.session_roots("session")) == MAX_ROOTS


@pytest.mark.parametrize(
    "name",
    [
        "doc.md:payload", "doc.md::$DATA", "doc.md.", "doc.md ", "NUL.md", "con",
        "aux.markdown", "COM0.md", "COM1.md", "LPT9", "CONIN$.md", "COM\u00b9.md",
        "CON .md", "LONGFI~1.md", "short~1/doc.md",
        "name?.md", "name*.md", "name|.md", "a//b.md", "a/../b.md", "a/./b.md",
        "", "a\x00.md", "a\n.md", r"C:relative.md", r"\root-relative.md",
        r"\\?\C:\doc.md", r"\\.\C:\doc.md", r"\\server\share\doc.md",
        r"\??\C:\doc.md", r"C:\\doc.md",
    ],
)
def test_ambiguous_windows_paths_rejected_portably(tmp_path: Path, name: str) -> None:
    with pytest.raises(UnsafePath):
        canonical_path(name, tmp_path)


def test_native_paths_unicode_spaces_and_relative_cwd(state: GateState, tmp_path: Path) -> None:
    name = "document \u00e9.md"
    draft = _capture(state, path=name)
    assert draft.path == canonical_path(tmp_path / name)
    assert canonical_path(tmp_path / name) == canonical_path(name, tmp_path)
    with pytest.raises(UnsafePath, match="known session"):
        canonical_path("relative.md")


def test_resume_and_new_request_preserve_scan_metadata(state: GateState, tmp_path: Path) -> None:
    outside = tmp_path / "external"
    state.register_root("session", outside)
    state.update_snapshot("session", outside / "doc.md", content_hash(BASELINE))
    roots, snapshots = state.session_roots("session"), state.snapshots("session")
    state.start_session("session", tmp_path, "resume")
    state.begin_request("session", "101")
    assert state.session_roots("session") == roots
    assert state.snapshots("session") == snapshots


@pytest.mark.skipif(os.name != "nt", reason="Windows path identity")
def test_windows_casing_and_separator_aliases_share_identity(state: GateState, tmp_path: Path) -> None:
    first = state.capture("session", str(tmp_path / "Document.MD"), BASELINE, None)
    second = state.capture(
        "session", str(tmp_path / "DOCUMENT.md").replace("\\", "/"), b"repair", None
    )
    assert second.document_id == first.document_id
    assert second.baseline == first.baseline


def test_symlink_file_and_ancestor_are_rejected(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    (actual / "doc.md").write_bytes(BASELINE)
    link = tmp_path / "link"
    try:
        link.symlink_to(actual, target_is_directory=True)
    except OSError as exc:
        if os.name == "nt" and exc.winerror == 1314:
            pytest.skip("Windows symlink privilege unavailable")
        raise
    with pytest.raises(UnsafePath, match="links and junctions"):
        canonical_path(link / "doc.md")
    with pytest.raises(UnsafePath, match="links and junctions"):
        GateState(link / "state")


def test_hard_links_are_rejected(tmp_path: Path) -> None:
    actual, link = tmp_path / "actual.md", tmp_path / "link.md"
    actual.write_bytes(BASELINE)
    os.link(actual, link)
    with pytest.raises(UnsafePath, match="Hard-linked"):
        canonical_path(actual)
    with pytest.raises(UnsafePath, match="Hard-linked"):
        canonical_path(link)


@pytest.mark.skipif(os.name != "nt", reason="Windows junction")
def test_junction_ancestor_is_rejected(tmp_path: Path) -> None:
    actual, junction = tmp_path / "actual", tmp_path / "junction"
    actual.mkdir()
    subprocess.run(
        ["cmd.exe", "/c", "mklink", "/J", str(junction), str(actual)],
        check=True, capture_output=True,
    )
    try:
        with pytest.raises(UnsafePath, match="links and junctions"):
            canonical_path(junction / "doc.md")
    finally:
        os.rmdir(junction)


def test_corrupted_artifact_is_not_replaced_or_treated_as_fresh_draft(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    artifact = tmp_path / "state" / "content" / content_hash(BASELINE)
    artifact.write_bytes(b"corrupt")
    with pytest.raises(GateStateError, match="corrupt"):
        state.pending("session")
    with pytest.raises(GateStateError, match="corrupt"):
        _capture(state)
    assert artifact.read_bytes() == b"corrupt"


def test_baseline_artifact_path_is_existing_exact_content_without_a_copy(
    state: GateState, tmp_path: Path,
) -> None:
    baseline = BASELINE + b"\xff\x00"
    draft = _capture(state, baseline)
    path = state.artifact_path(draft.baseline_hash)
    assert path == Path(canonical_path(tmp_path / "state")) / "content" / draft.baseline_hash
    assert path.read_bytes() == baseline
    assert path.name == content_hash(baseline)
    _capture(state, b"later repair")
    assert state.artifact_path(draft.baseline_hash) == path
    assert path.read_bytes() == baseline
    assert sorted(item.name for item in path.parent.iterdir()) == sorted([
        content_hash(baseline), content_hash(b"later repair"),
    ])


def test_artifact_path_rejects_unknown_corrupt_and_unsafe_objects(state: GateState, tmp_path: Path) -> None:
    with pytest.raises(GateStateError, match="SHA-256"):
        state.artifact_path("..\\state.sqlite3")
    with pytest.raises(GateStateError, match="Missing or corrupt"):
        state.artifact_path(content_hash(b"unknown content"))
    draft = _capture(state)
    path = state.artifact_path(draft.baseline_hash)
    path.write_bytes(b"corrupt content")
    with pytest.raises(GateStateError, match="Missing or corrupt"):
        state.artifact_path(draft.baseline_hash)
    path.write_bytes(BASELINE)
    link = tmp_path / "artifact-alias"
    os.link(path, link)
    try:
        with pytest.raises(UnsafePath, match="Hard-linked"):
            state.artifact_path(draft.baseline_hash)
    finally:
        link.unlink()


def test_baseline_artifact_recovery_survives_state_reopen(state: GateState, tmp_path: Path) -> None:
    draft = _capture(state)
    with GateState(tmp_path / "state") as reopened:
        assert reopened.artifact_path(draft.baseline_hash).read_bytes() == BASELINE


def test_failed_capture_rolls_back_document_registration(state: GateState) -> None:
    with pytest.raises(GateStateError, match="content limit"):
        _capture(state, b"x" * (MAX_CONTENT_BYTES + 1))
    assert state.pending("session") == []
    assert _capture(state).baseline == BASELINE


def test_failed_artifact_publication_rolls_back_and_cleans_temporary_content(
    state: GateState, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    def cannot_publish(source: Path, destination: Path) -> None:
        raise OSError("Synthetic publication failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "link", cannot_publish)
        with pytest.raises(OSError, match="publication failure"):
            _capture(state)
    assert state.pending("session") == []
    assert list((tmp_path / "state" / "content").iterdir()) == []
    assert _capture(state).baseline == BASELINE


def test_snapshot_registration_limit_is_explicit_and_existing_records_remain(
    state: GateState, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(gate_state_module, "MAX_SNAPSHOTS", 2)
    state.update_snapshot("session", "one.md", content_hash(BASELINE))
    state.update_snapshot("session", "two.md", None)
    with pytest.raises(StateConflict, match="record limit"):
        state.update_snapshot("session", "three.md", None)
    state.update_snapshot("session", "one.md", None)
    assert len(state.snapshots("session", limit=2)) == 2

def test_unknown_schema_version_is_rejected(tmp_path: Path) -> None:
    with GateState(tmp_path / "state"):
        pass
    with sqlite3.connect(tmp_path / "state" / "state.sqlite3") as database:
        database.execute("PRAGMA user_version=999")
    with pytest.raises(GateStateError, match="schema version"):
        GateState(tmp_path / "state")


def test_schema_upgrade_preserves_drafts_without_inventing_legacy_child_epoch(tmp_path: Path) -> None:
    root = tmp_path / "state"
    with GateState(root) as value:
        value.start_session("session", tmp_path)
        value.begin_request("session", "100")
        _capture(value)
        value.bind_child("child", "session", tmp_path)
    with sqlite3.connect(root / "state.sqlite3") as database:
        database.execute("UPDATE sessions SET epoch=0 WHERE id='child'")
        database.execute("DROP TABLE prompt_events")
        database.execute("DROP TABLE delegations")
        database.execute("DROP TABLE main_sessions")
        database.execute("DROP TABLE continuations")
        database.execute("PRAGMA user_version=1")
    with GateState(root) as upgraded:
        assert upgraded.pending("session")[0].baseline == BASELINE
        with pytest.raises(StateConflict, match="previous user-request"):
            upgraded.capture("child", "doc.md", b"new baseline", None)
        upgraded.start_session("session", tmp_path, "resume")
        assert upgraded.pending("session")[0].baseline == BASELINE


def test_state_stores_no_prompt_transcript_or_event_payload(state: GateState, tmp_path: Path) -> None:
    _capture(state)
    _result(state)
    with sqlite3.connect(tmp_path / "state" / "state.sqlite3") as database:
        tables = database.execute("SELECT name,sql FROM sqlite_master WHERE type='table'").fetchall()
        schema = json.dumps(tables).lower()
        assert "prompt text" not in schema
        assert "transcript" not in schema
        assert "payload" not in schema
        assert database.execute("SELECT event FROM requests").fetchall() == [("100",)]


def test_concurrent_sessions_have_one_owner_and_no_last_writer_wins(tmp_path: Path) -> None:
    root = tmp_path / "state"
    with GateState(root) as value:
        for name in ("one", "two"):
            value.start_session(name, tmp_path)
            value.begin_request(name, "100")
    barrier = Barrier(2)

    def capture(name: str) -> str:
        with GateState(root) as value:
            barrier.wait(timeout=10)
            try:
                value.capture(name, "doc.md", name.encode(), None)
            except StateConflict:
                return "conflict"
            return name

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(capture, ("one", "two")))
    assert outcomes.count("conflict") == 1
    winner = next(name for name in outcomes if name != "conflict")
    with GateState(root) as value:
        assert value.pending(winner)[0].baseline == winner.encode()
    assert not (tmp_path / "doc.md").exists()


def test_concurrent_capture_in_same_request_has_one_immutable_first_draft(tmp_path: Path) -> None:
    root = tmp_path / "state"
    with GateState(root) as value:
        value.start_session("session", tmp_path)
        value.begin_request("session", "100")
    barrier = Barrier(2)

    def capture(content: bytes) -> Draft:
        with GateState(root) as value:
            barrier.wait(timeout=10)
            return _capture(value, content)

    with ThreadPoolExecutor(max_workers=2) as pool:
        drafts = list(pool.map(capture, (b"one", b"two")))
    assert drafts[0].baseline == drafts[1].baseline
    assert drafts[0].document_id == drafts[1].document_id
    with GateState(root) as value:
        assert value.pending("session")[0].baseline == drafts[0].baseline


def test_concurrent_stop_budget_is_shared_and_transactional(tmp_path: Path) -> None:
    root = tmp_path / "state"
    with GateState(root) as value:
        value.start_session("session", tmp_path)
        value.begin_request("session", "100")
    barrier = Barrier(8)

    def stop(_: int) -> int:
        with GateState(root) as value:
            barrier.wait(timeout=10)
            try:
                return value.next_stop("session")
            except StopLimit:
                return 0

    with ThreadPoolExecutor(max_workers=8) as pool:
        counts = sorted(pool.map(stop, range(8)))
    assert counts == [0, 0, 1, 2, 3, 4, 5, 6]


def test_concurrent_child_binding_claims_exactly_one_session(tmp_path: Path) -> None:
    root = tmp_path / "state"
    digest = content_hash(b"synthetic child task")
    with GateState(root) as value:
        value.start_session("session", tmp_path)
        value.begin_request("session", "100")
        value.register_delegation("session", "operation-1", digest, tmp_path)
    barrier = Barrier(2)

    def bind(session_id: str) -> str:
        with GateState(root) as value:
            barrier.wait(timeout=10)
            try:
                return value.bind_prompt(session_id, "200", digest, tmp_path)
            except StateConflict:
                return "conflict"

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(bind, ("child-one", "child-two"))) == ["child", "conflict"]


@pytest.mark.parametrize(
    ("question_session", "consumer"),
    [("session", "session"), ("answering-child", "session"), ("answering-child", "answering-child")],
)
def test_inline_answer_is_scoped_to_document_not_root_or_other_children(
    state: GateState, tmp_path: Path, question_session: str, consumer: str,
) -> None:
    state.bind_child("answering-child", "session", tmp_path)
    state.bind_child("other-child", "session", tmp_path)
    a = state.capture("session", "a.md", BASELINE, None)
    b_baseline = b"The client must send exactly two messages."
    b = state.capture("session", "b.md", b_baseline, None)
    for path, baseline, count in (("a.md", a, 3), ("b.md", b, 2)):
        for number in range(count):
            candidate = f"{path} repair {number}".encode()
            draft = state.capture("session", path, candidate, None)
            state.record_result("session", path, candidate, _evaluation_result(baseline, candidate), IDENTITY)
            assert draft.baseline == baseline.baseline
    assert state.next_stop("session") == 1
    assert state.next_stop("other-child") == 2
    _answer(state, session_id=question_session)
    pending_a = state.draft("session", "a.md")
    assert pending_a is not None
    assert (pending_a.epoch, pending_a.revision_id, pending_a.repairs) == (1, a.revision_id, 3)
    assert pending_a.status == "revision_requested"
    assert state.bind_prompt("other-child", "2500", content_hash(b"child follow-up"), tmp_path) == "child"
    assert state.next_stop("other-child") == 3
    with pytest.raises(StateConflict, match="root or answering session"):
        state.capture("other-child", "a.md", b"unselected first draft", None, event_time=3000)

    unrelated = state.capture(question_session, "b.md", b"unrelated replacement", None, event_time=3000)
    assert (unrelated.baseline, unrelated.revision_id, unrelated.epoch, unrelated.repairs) == (
        b_baseline, b.revision_id, 1, 2,
    )
    state.record_result(
        question_session, "b.md", b"unrelated replacement",
        _evaluation_result(unrelated, b"unrelated replacement"), IDENTITY,
    )
    with pytest.raises(AttemptLimit):
        state.capture("other-child", "b.md", b"fourth unrelated repair", None, event_time=3001)

    chosen_bytes = b"The reviewer must approve the selected release."
    chosen = state.capture(consumer, "a.md", chosen_bytes, None, event_time=3001)
    assert chosen.revision_id != a.revision_id
    assert (chosen.epoch, chosen.baseline, chosen.repairs) == (1, chosen_bytes, 0)
    assert state.next_stop("session") == 4
    assert state.capture("other-child", "a.md", b"repair chosen content", None).baseline == chosen_bytes
    for number in range(3):
        candidate = f"new chosen repair {number}".encode()
        state.capture(consumer, "a.md", candidate, None)
        result = state.record_result(consumer, "a.md", candidate, _evaluation_result(chosen, candidate), IDENTITY)
        assert result.repairs == number + 1
    with pytest.raises(AttemptLimit):
        state.capture(consumer, "a.md", b"fourth chosen repair", None)
    assert state.artifact_path(a.baseline_hash).read_bytes() == BASELINE


@pytest.mark.parametrize("event_time", [None, 0, False, 1999, 2000, 9223372036854775808])
def test_chosen_draft_requires_actual_pre_tool_timestamp_after_answer(
    state: GateState, event_time: int | None,
) -> None:
    original = _capture(state, path="a.md")
    _answer(state)
    with pytest.raises(StateConflict, match="timestamp|after the wording answer"):
        state.capture("session", "a.md", b"queued pre-answer proposal", None, event_time=event_time)
    unchanged = state.draft("session", "a.md")
    assert unchanged is not None
    assert (unchanged.revision_id, unchanged.baseline, unchanged.status) == (
        original.revision_id, BASELINE, "revision_requested",
    )
    assert state.capture("session", "a.md", b"actual chosen draft", None, event_time=2001).epoch == 1


def test_answer_requires_actual_timestamp_and_cancellation_grants_no_revision(state: GateState) -> None:
    draft = _capture(state, path="a.md")
    token = content_hash(b"question")
    state.stage_decision("session", token, "a.md", draft.baseline_hash)
    with pytest.raises(StateConflict, match="timestamp"):
        state.resolve_decision("session", token, content_hash(b"answer"), "event")
    with pytest.raises(StateConflict, match="still pending"):
        state.capture("session", "a.md", b"queued draft", None, event_time=3000)
    assert not state.resolve_decision("session", token, None, "cancel")
    assert not state.resolve_decision("session", token, content_hash(b"late answer"), "late", event_time=3000)
    repaired = state.capture("session", "a.md", b"ordinary repair", None, event_time=4000)
    assert repaired.revision_id == draft.revision_id
    assert repaired.baseline == BASELINE
    assert state.next_stop("session") == 1


def test_queued_old_results_approvals_and_renames_cannot_use_inline_authorization(state: GateState) -> None:
    draft = _capture(state, path="a.md")
    passing = _evaluation_result(draft, BASELINE, accepted=True)
    state.record_result("session", "a.md", BASELINE, passing, IDENTITY)
    _answer(state)
    with pytest.raises(StateConflict, match="chosen first draft"):
        state.record_result("session", "a.md", BASELINE, passing, IDENTITY)
    with pytest.raises(StateConflict, match="chosen first draft"):
        state.approve("session", "a.md", BASELINE, IDENTITY)
    with pytest.raises(StateConflict, match="chosen first draft"):
        state.cached("session", "a.md", BASELINE, IDENTITY)
    with pytest.raises(StateConflict, match="chosen first draft"):
        state.move("session", "a.md", "renamed.md")
    with pytest.raises(StateConflict, match="chosen first draft"):
        state.verify_written("session", "a.md", BASELINE)
    assert state.draft("session", "renamed.md") is None


@pytest.mark.parametrize("question_session", ["session", "answering-child"])
def test_shell_after_answer_cannot_choose_first_draft_or_reset_another_document(
    state: GateState, tmp_path: Path, question_session: str,
) -> None:
    state.bind_child("answering-child", "session", tmp_path)
    state.bind_child("other-child", "session", tmp_path)
    a = _capture(state, path="a.md")
    b = state.capture("session", "b.md", b"Unrelated baseline.", None)
    state.update_snapshot("session", "a.md", None)
    state.update_snapshot("session", "b.md", None)
    _answer(state, session_id=question_session)

    unselected = b"Async shell output that was proposed before the answer."
    (tmp_path / "a.md").write_bytes(unselected)
    observed = state.observe("other-child", "a.md", unselected, None)
    assert (observed.revision_id, observed.baseline, observed.candidate_hash, observed.status) == (
        a.revision_id, BASELINE, a.candidate_hash, "revision_requested",
    )
    assert observed.expected_hash == content_hash(unselected)
    assert observed.repairs == a.repairs
    with pytest.raises(StateConflict, match="chosen first draft"):
        state.record_result("session", "a.md", unselected, _evaluation_result(a, unselected), IDENTITY)
    with pytest.raises(StateConflict, match="root or answering session"):
        state.capture("other-child", "a.md", unselected, unselected, event_time=3000)
    with pytest.raises(StateConflict, match="after the wording answer"):
        state.capture(question_session, "a.md", unselected, unselected, event_time=1999)

    changed_b = b"Unrelated replacement via shell."
    (tmp_path / "b.md").write_bytes(changed_b)
    observed_b = state.observe(question_session, "b.md", changed_b, None)
    assert (observed_b.revision_id, observed_b.baseline, observed_b.epoch) == (
        b.revision_id, b.baseline, 1,
    )

    chosen = state.capture(question_session, "a.md", unselected, unselected, event_time=3001)
    assert chosen.baseline == unselected
    assert chosen.revision_id != a.revision_id
    state.record_result(
        question_session, "a.md", unselected, _evaluation_result(chosen, unselected, accepted=True), IDENTITY,
    )
    state.approve(question_session, "a.md", unselected, IDENTITY)
    assert state.verify_written(question_session, "a.md", unselected).status == "verified"
    state.failed(question_session, "a.md")
    assert state.draft("session", "a.md") == state.draft(question_session, "a.md")
    assert (tmp_path / "a.md").read_bytes() == unselected


def test_shell_choice_reconciliation_requires_matching_existing_snapshot(state: GateState, tmp_path: Path) -> None:
    draft = _capture(state, path="a.md")
    _answer(state)
    assert state.snapshots("session")[canonical_path(tmp_path / "a.md")] is None
    with sqlite3.connect(tmp_path / "state" / "state.sqlite3") as database:
        database.execute("DELETE FROM snapshots WHERE owner='session'")
    current = b"changed asynchronously"
    (tmp_path / "a.md").write_bytes(current)
    with pytest.raises(StateConflict, match="pre-shell snapshot record"):
        state.observe("session", "a.md", current, None)
    state.update_snapshot("session", "a.md", content_hash(b"different prior bytes"))
    with pytest.raises(StateConflict, match="snapshot is stale"):
        state.observe("session", "a.md", current, None)
    state.update_snapshot("session", "a.md", None)
    observed = state.observe("session", "a.md", current, None)
    assert observed.expected_hash == content_hash(current)
    assert (observed.baseline_hash, observed.revision_id) == (draft.baseline_hash, draft.revision_id)
    assert observed.status == "revision_requested"


def test_inline_answer_is_one_shot_and_root_stop_limit_does_not_reset(state: GateState, tmp_path: Path) -> None:
    draft = _capture(state, path="a.md")
    for number in range(1, MAX_STOPS + 1):
        assert state.next_stop("session") == number
    token = _answer(state)
    assert not state.resolve_decision(
        "session", token, content_hash(b"different duplicate answer"), "duplicate", event_time=3000,
    )
    chosen = state.capture("session", "a.md", b"chosen first draft", None, event_time=2001)
    ordinary = state.capture("session", "a.md", b"later repair", None, event_time=4000)
    assert ordinary.revision_id == chosen.revision_id != draft.revision_id
    assert ordinary.baseline == b"chosen first draft"
    with pytest.raises(StopLimit):
        state.next_stop("session")
    _answer(state, event_time=5000)
    second = state.capture("session", "a.md", b"second chosen first draft", None, event_time=5001)
    assert second.revision_id not in {draft.revision_id, chosen.revision_id}
    assert (second.epoch, second.repairs) == (1, 0)
    with sqlite3.connect(tmp_path / "state" / "state.sqlite3") as database:
        assert database.execute("SELECT count(*) FROM requests WHERE owner='session'").fetchone() == (1,)
        assert database.execute("SELECT count(*) FROM revisions WHERE document=?", (draft.document_id,)).fetchone() == (3,)
        grants = database.execute(
            "SELECT revision,document,owner,epoch,question_session,answer_hash,event_id,event_time,consumed_revision "
            "FROM revision_authorizations ORDER BY event_time"
        ).fetchall()
        assert grants[0] == (
            draft.revision_id, draft.document_id, "session", 1, "session",
            content_hash(b"selected wording"), "answer-2000", 2000, chosen.revision_id,
        )
        assert grants[1][-1] == second.revision_id
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []


def test_question_stale_path_candidate_bytes_and_cancel_guards_are_preserved(state: GateState, tmp_path: Path) -> None:
    draft = _capture(state, path="a.md")
    _capture(state, path="b.md")
    token = content_hash(b"bound question")
    with pytest.raises(StateConflict, match="different frozen draft"):
        state.stage_decision("session", token, "a.md", content_hash(b"wrong baseline"))
    state.stage_decision("session", token, "a.md", draft.baseline_hash)
    state.stage_decision("session", token, "a.md", draft.baseline_hash)
    with pytest.raises(StateConflict, match="stale"):
        state.stage_decision("session", token, "b.md", draft.baseline_hash)
    with pytest.raises(StateConflict, match="still pending"):
        state.move("session", "a.md", "renamed.md")
    (tmp_path / "a.md").write_bytes(b"unexpected human change")
    with pytest.raises(StateConflict, match="expected prior bytes"):
        state.resolve_decision("session", token, content_hash(b"answer"), "event", event_time=2000)
    assert not state.resolve_decision("session", token, None, "cancel")
    assert (tmp_path / "a.md").read_bytes() == b"unexpected human change"
    state.begin_request("session", "101")
    new = state.capture("session", "a.md", b"genuine new request", b"unexpected human change")
    assert (new.epoch, new.baseline) == (2, b"genuine new request")


def test_new_genuine_root_request_expires_pending_inline_authorization(state: GateState, tmp_path: Path) -> None:
    state.bind_child("answering-child", "session", tmp_path)
    a = _capture(state, path="a.md")
    _answer(state, session_id="answering-child")
    assert state.bind_prompt("session", "101", content_hash(b"new real user request"), tmp_path) == "main"
    with pytest.raises(StateConflict, match="previous user-request"):
        state.capture("answering-child", "a.md", b"stale child", None, event_time=3000)
    new = state.capture("session", "a.md", b"genuine new first draft", None)
    assert new.epoch == 2
    assert new.revision_id != a.revision_id
    assert state.next_stop("session") == 1


def test_concurrent_authorized_captures_consume_exactly_one_document_revision(tmp_path: Path) -> None:
    root = tmp_path / "state"
    with GateState(root) as state:
        state.start_session("session", tmp_path)
        state.begin_request("session", "100")
        state.bind_child("answering-child", "session", tmp_path)
        first = _capture(state, path="a.md")
        _answer(state, session_id="answering-child")
    barrier = Barrier(2)

    def capture(session_id: str) -> Draft:
        with GateState(root) as state:
            barrier.wait(timeout=10)
            return state.capture(session_id, "a.md", session_id.encode(), None, event_time=2001)

    with ThreadPoolExecutor(max_workers=2) as pool:
        drafts = list(pool.map(capture, ("session", "answering-child")))
    assert drafts[0].revision_id == drafts[1].revision_id != first.revision_id
    assert drafts[0].baseline == drafts[1].baseline
    assert drafts[0].epoch == drafts[1].epoch == 1
    with sqlite3.connect(root / "state.sqlite3") as database:
        assert database.execute("SELECT count(*) FROM revisions").fetchone() == (2,)
        assert database.execute("SELECT consumed_revision FROM revision_authorizations").fetchone() == (
            drafts[0].revision_id,
        )


def _make_v4_state(tmp_path: Path) -> tuple[Path, Draft, Draft]:
    root = tmp_path / "state"
    with GateState(root) as state:
        state.start_session("session", tmp_path)
        state.begin_request("session", "100")
        _capture(state, path="a.md")
        _result(state, path="a.md")
        state.begin_request("session", "101")
        a = state.capture("session", "a.md", b"Second root request A.", None)
        state.record_result("session", "a.md", a.baseline, _evaluation_result(a, a.baseline), IDENTITY)
        b = state.capture("session", "b.md", b"Second root request B.", None)
        state.record_result("session", "b.md", b.baseline, _evaluation_result(b, b.baseline, accepted=True), IDENTITY)
        state.approve("session", "b.md", b.baseline, IDENTITY)
        state.stage_operation("session", "pending-write", ["b.md"])
        state.stage_decision("session", content_hash(b"legacy question"), "a.md", a.baseline_hash)
        state.update_snapshot("session", "a.md", None)
        state.update_snapshot("session", "b.md", None)
        state.mark_snapshots_ready("session")
        state.bind_child("child", "session", tmp_path)
        state.next_stop("child")
    with sqlite3.connect(root / "state.sqlite3") as database:
        database.execute("PRAGMA foreign_keys=OFF")
        database.execute("BEGIN IMMEDIATE")
        database.execute("DROP TABLE revision_authorizations")
        database.execute(
            "CREATE TABLE revisions_v4 ("
            "id INTEGER PRIMARY KEY, document INTEGER NOT NULL REFERENCES documents(id),"
            "owner TEXT NOT NULL, epoch INTEGER NOT NULL, baseline TEXT NOT NULL,"
            "candidate TEXT NOT NULL, expected TEXT, status TEXT NOT NULL,"
            "move_source TEXT, move_expected TEXT, approved_identity TEXT,"
            "UNIQUE(document, owner, epoch))"
        )
        database.execute("INSERT INTO revisions_v4 SELECT * FROM revisions")
        database.execute("DROP TABLE revisions")
        database.execute("ALTER TABLE revisions_v4 RENAME TO revisions")
        database.execute("CREATE INDEX revisions_owner ON revisions(owner,status)")
        database.execute(
            "CREATE TABLE decisions_v4 (session TEXT NOT NULL, token TEXT NOT NULL, owner TEXT NOT NULL,"
            "epoch INTEGER NOT NULL, revision INTEGER NOT NULL, baseline TEXT NOT NULL,"
            "candidate TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(session,token))"
        )
        database.execute(
            "INSERT INTO decisions_v4 SELECT session,token,owner,epoch,revision,baseline,candidate,resolved FROM decisions"
        )
        database.execute("DROP TABLE decisions")
        database.execute("ALTER TABLE decisions_v4 RENAME TO decisions")
        database.execute("PRAGMA user_version=4")
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
    return root, a, b


def test_v4_migration_preserves_revision_ids_results_operations_and_foreign_keys(tmp_path: Path) -> None:
    root, a, b = _make_v4_state(tmp_path)
    tables = (
        "sessions", "requests", "documents", "aliases", "revisions", "attempts", "results",
        "operations", "operation_documents", "snapshots", "snapshot_epochs",
    )
    before: dict[str, list[tuple[object, ...]]] = {}
    with sqlite3.connect(root / "state.sqlite3") as database:
        for table in tables:
            before[table] = database.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall()
        decisions = database.execute("SELECT * FROM decisions ORDER BY rowid").fetchall()
        assert any(row[2] for row in database.execute("PRAGMA index_list(revisions)"))
    with GateState(root) as state:
        with sqlite3.connect(root / "state.sqlite3") as database:
            assert database.execute("PRAGMA user_version").fetchone() == (6,)
            assert database.execute("PRAGMA foreign_key_check").fetchall() == []
            for table in tables:
                assert database.execute(f"SELECT * FROM {table} ORDER BY rowid").fetchall() == before[table], table
            assert database.execute(
                "SELECT session,token,owner,epoch,revision,baseline,candidate,resolved FROM decisions ORDER BY rowid"
            ).fetchall() == decisions
            assert not any(row[2] for row in database.execute("PRAGMA index_list(revisions)"))
            for table in ("attempts", "results", "operation_documents"):
                assert "revisions" in {row[2] for row in database.execute(f"PRAGMA foreign_key_list({table})")}
            assert database.execute(
                "SELECT d.id FROM documents d LEFT JOIN revisions r ON r.id=d.current_revision WHERE r.id IS NULL"
            ).fetchall() == []
        assert state._db.execute("PRAGMA foreign_keys").fetchone()[0] == 1
        with pytest.raises(sqlite3.IntegrityError):
            state._db.execute(
                "INSERT INTO attempts(revision,candidate) VALUES(?,?)", (999999, content_hash(b"invalid reference"))
            )
        assert state.artifact_path(content_hash(BASELINE)).read_bytes() == BASELINE
        assert state.artifact_path(a.baseline_hash).read_bytes() == a.baseline
        with pytest.raises(StateConflict, match="still pending"):
            state.cached("session", "a.md", a.baseline, IDENTITY)
        assert state.operation_paths("session", "pending-write") == [canonical_path(tmp_path / "b.md")]
        assert state.snapshots_ready("session")
        assert state.next_stop("child") == 2
        with pytest.raises(StateConflict, match="document changed"):
            state.resolve_decision(
                "session", content_hash(b"legacy question"), content_hash(b"answer"), "legacy-answer", event_time=2000,
            )
        assert not state.resolve_decision("session", content_hash(b"legacy question"), None, "cancel-legacy")
        assert state.cached("session", "a.md", a.baseline, IDENTITY) == _evaluation_result(a, a.baseline)
        _answer(state, event_time=2000)
        chosen = state.capture("session", "a.md", b"Document-scoped chosen revision.", None, event_time=2001)
        assert chosen.epoch == a.epoch == 2
        assert chosen.revision_id not in {a.revision_id, b.revision_id}
        (tmp_path / "b.md").write_bytes(b.baseline)
        assert state.complete_operation("session", "pending-write")[0].revision_id == b.revision_id
    with GateState(root) as reopened:
        current = reopened.draft("session", "a.md")
        assert current is not None
        assert (current.baseline, current.revision_id) == (chosen.baseline, chosen.revision_id)
        assert reopened.artifact_path(a.baseline_hash).read_bytes() == a.baseline
        assert reopened.next_stop("session") == 3


def test_failed_v4_integrity_migration_rolls_back_schema_and_data(tmp_path: Path) -> None:
    root, a, _ = _make_v4_state(tmp_path)
    with sqlite3.connect(root / "state.sqlite3") as database:
        database.execute(
            "INSERT INTO attempts(revision,candidate) VALUES(?,?)", (999999, content_hash(b"orphan"))
        )
        before = database.execute("SELECT * FROM revisions ORDER BY id").fetchall()
    with pytest.raises(GateStateError, match="foreign-key integrity"):
        GateState(root)
    with sqlite3.connect(root / "state.sqlite3") as database:
        assert database.execute("PRAGMA user_version").fetchone() == (4,)
        assert database.execute("SELECT * FROM revisions ORDER BY id").fetchall() == before
        assert any(row[2] for row in database.execute("PRAGMA index_list(revisions)"))
        assert database.execute(
            "SELECT name FROM sqlite_master WHERE name IN ('revisions_v5','revision_authorizations')"
        ).fetchall() == []
    assert (root / "content" / a.baseline_hash).read_bytes() == a.baseline


def test_pending_document_authorization_survives_reopen_without_exposing_answer_text(
    state: GateState, tmp_path: Path,
) -> None:
    draft = _capture(state, path="a.md")
    answer = b"Private synthetic answer content must not be persisted."
    token = content_hash(b"question")
    state.stage_decision("session", token, "a.md", draft.baseline_hash)
    assert state.resolve_decision("session", token, content_hash(answer), "event-2000", event_time=2000)
    with GateState(tmp_path / "state") as reopened:
        pending = reopened.draft("session", "a.md")
        assert pending is not None
        assert pending.status == "revision_requested"
        with pytest.raises(StateConflict, match="timestamp"):
            reopened.capture("session", "a.md", b"missing genuine pre-event timestamp", None)
        chosen = reopened.capture("session", "a.md", b"chosen complete draft", None, event_time=2001)
        assert chosen.epoch == 1
        assert chosen.revision_id != draft.revision_id
    assert answer not in (tmp_path / "state" / "state.sqlite3").read_bytes()


@pytest.mark.parametrize("migrate_v5", [False, True])
def test_new_root_request_can_authorize_same_unconsumed_target_without_reusing_old_grant(
    tmp_path: Path, migrate_v5: bool,
) -> None:
    root = tmp_path / "state"
    with GateState(root) as state:
        state.start_session("session", tmp_path)
        state.begin_request("session", "100")
        original = _capture(state, path="a.md")
        _answer(state)
    if migrate_v5:
        with sqlite3.connect(root / "state.sqlite3") as database:
            database.execute("PRAGMA foreign_keys=OFF")
            database.execute("BEGIN IMMEDIATE")
            database.execute(
                "CREATE TABLE revision_authorizations_v5 ("
                "revision INTEGER PRIMARY KEY REFERENCES revisions(id),"
                "document INTEGER NOT NULL REFERENCES documents(id), owner TEXT NOT NULL,"
                "epoch INTEGER NOT NULL, question_session TEXT NOT NULL REFERENCES sessions(id),"
                "question_token TEXT NOT NULL, answer_hash TEXT NOT NULL, event_id TEXT NOT NULL,"
                "event_time INTEGER NOT NULL, consumed_revision INTEGER REFERENCES revisions(id),"
                "UNIQUE(question_session,question_token),"
                "FOREIGN KEY(question_session,question_token) REFERENCES decisions(session,token))"
            )
            database.execute("INSERT INTO revision_authorizations_v5 SELECT * FROM revision_authorizations")
            database.execute("DROP TABLE revision_authorizations")
            database.execute("ALTER TABLE revision_authorizations_v5 RENAME TO revision_authorizations")
            database.execute("PRAGMA user_version=5")
    with GateState(root) as state:
        assert state.begin_request("session", "101") == 2
        _answer(state, event_time=3000)
        chosen = state.capture("session", "a.md", b"Chosen under a new genuine request.", None, event_time=3001)
        assert chosen.epoch == 2
        assert chosen.revision_id != original.revision_id
        assert state.next_stop("session") == 1
    with sqlite3.connect(root / "state.sqlite3") as database:
        assert database.execute("PRAGMA user_version").fetchone() == (6,)
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute(
            "SELECT revision,epoch,consumed_revision FROM revision_authorizations ORDER BY epoch"
        ).fetchall() == [
            (original.revision_id, 1, None), (original.revision_id, 2, chosen.revision_id),
        ]
