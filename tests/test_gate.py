"""Absolute quality and protected repair tests, using the pinned local model."""

from __future__ import annotations

import copy
import hashlib
import json
import socket
from pathlib import Path
from typing import cast

import pytest
from jsonschema import Draft202012Validator

from lingity import gate
from lingity.analyzer import analyze_text
from lingity.gate import GatePolicy, GateResult, cache_identity, evaluate_document
from lingity.markdown import parser_fingerprint
from lingity.models import JsonValue
from lingity.nlp import model_fingerprint
from lingity.profiles import Profile, load_profile, sha256_json

GOOD = b"The reviewer must close the finding."
SCHEMAS = Path(__file__).resolve().parents[1] / "lingity" / "schemas" / "v1"


def _codes(result: GateResult) -> set[str]:
    return {cast(str, violation["code"]) for violation in result.violations}


def _validate(result: GateResult) -> None:
    schema = json.loads((SCHEMAS / "gate-result.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(result.to_dict())
    json.dumps(result.to_dict(), allow_nan=False)


def _score_seam(
    monkeypatch: pytest.MonkeyPatch, document: float, block: float | None = None,
    source: tuple[str, float] | None = None,
) -> None:
    def analyzed(text: str, profile: Profile | None = None) -> dict[str, JsonValue]:
        artifact = analyze_text(text, profile)
        score = cast(dict[str, JsonValue], artifact["score"])
        score["value"] = document if block is None or "\n\n" in text else block
        if source is not None and text == source[0]:
            score["value"] = source[1]
        artifact.pop("analysis_sha256")
        artifact["analysis_sha256"] = sha256_json(artifact)
        schema = json.loads((SCHEMAS / "analysis.schema.json").read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(artifact)
        return artifact

    monkeypatch.setattr(gate, "analyze_text", analyzed)


@pytest.mark.parametrize(("score", "accepted"), [(84.99, False), (85.0, True), (85.01, True)])
def test_exact_published_document_boundary(monkeypatch: pytest.MonkeyPatch, score: float, accepted: bool) -> None:
    _score_seam(monkeypatch, score, 100.0)
    result = evaluate_document(GOOD + b"\n\nThe owner must act.")
    assert result.accepted is accepted
    assert ("quality.document_hri" in _codes(result)) is (not accepted)
    assert "quality.block_hri" not in _codes(result)
    _validate(result)


@pytest.mark.parametrize(("score", "accepted"), [(84.99, False), (85.0, True), (85.01, True)])
def test_exact_published_block_boundary(monkeypatch: pytest.MonkeyPatch, score: float, accepted: bool) -> None:
    _score_seam(monkeypatch, 100.0, score)
    result = evaluate_document(GOOD + b"\n\nThe owner must act.")
    assert result.accepted is accepted
    assert ("quality.block_hri" in _codes(result)) is (not accepted)
    assert "quality.document_hri" not in _codes(result)
    _validate(result)


def test_profile_digest_is_exact() -> None:
    profile = load_profile("architecture-review")
    assert (profile.version, profile.digest) == ("1.3.0", gate.PROFILE_DIGEST)


def test_unchanged_compliant_draft_does_not_require_relative_improvement() -> None:
    result = evaluate_document(GOOD, GOOD)
    assert result.accepted
    assert result.protected_delta["disposition"] == "unchanged"
    _validate(result)


@pytest.mark.parametrize("newline", [b"\r\n", b"\r"])
def test_newline_equivalent_content_is_unchanged_but_bytes_are_not(newline: bytes) -> None:
    baseline = b"# Rules\n\nThe reviewer must act.\n\n| Key | Rule |\n|---|---|\n| Owner | The owner must act. |\n\n```python\nvalue = 1\n```\n"
    candidate = baseline.replace(b"\n", newline)
    result = evaluate_document(candidate, baseline)
    assert result.accepted, result.to_dict()
    assert result.protected_delta["disposition"] == "unchanged"
    assert result.candidate_sha256 != result.baseline_sha256
    assert result.projected_sha256 == result.baseline_projected_sha256
    assert result.scores["document"] == result.scores["baseline_document"]
    _validate(result)


def test_newline_normalization_cannot_clear_an_absolute_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    _score_seam(monkeypatch, 84.99)
    result = evaluate_document(GOOD + b"\r\n", GOOD + b"\n")
    assert not result.accepted
    assert result.protected_delta["disposition"] == "unchanged"
    assert "quality.document_hri" in _codes(result)
    assert "repair.judge" not in _codes(result)


def test_wording_repair_can_keep_literal_content_with_host_newline_normalization() -> None:
    baseline = b"The release must be approved by the reviewer.\n\n```python\nvalue = 1\n```\n"
    candidate = b"The reviewer must approve the release.\r\n\r\n```python\r\nvalue = 1\r\n```\r\n"
    assert evaluate_document(candidate, baseline).accepted


def test_actual_supported_improving_repair_passes() -> None:
    baseline = b"The release must be approved by the reviewer."
    candidate = b"The reviewer must approve the release."
    result = evaluate_document(candidate, baseline)
    assert result.accepted, result.to_dict()


def test_relative_improvement_cannot_buy_a_subthreshold_absolute_score(monkeypatch: pytest.MonkeyPatch) -> None:
    _score_seam(monkeypatch, 84.99, source=("The release must be approved by the reviewer.", 80))
    result = evaluate_document(b"The reviewer must approve the release.", b"The release must be approved by the reviewer.")
    assert not result.accepted
    assert {"quality.document_hri", "quality.block_hri"} <= _codes(result)
    assert "repair.judge" not in _codes(result)


def test_unresolved_changed_content_is_not_certified() -> None:
    result = evaluate_document(b"A calm office.", b"A quiet office.")
    assert not result.accepted
    assert result.protected_delta["unresolved"]


def test_actual_table_repair_keeps_header_and_row_binding() -> None:
    baseline = b"| Owner | Rule |\n|---|---|\n| Reviewer | The release must be approved by the reviewer. |\n"
    candidate = b"| Owner | Rule |\n|---|---|\n| Reviewer | The reviewer must approve the release. |\n"
    result = evaluate_document(candidate, baseline)
    assert result.accepted, result.to_dict()


def test_changed_compliant_tie_still_requires_improvement() -> None:
    result = evaluate_document(GOOD + b"\n", GOOD)
    assert not result.accepted
    assert "repair.judge" in _codes(result)
    assert any("did not change" in str(violation["message"]) for violation in result.violations)


def test_specifying_a_previously_unnamed_owner_is_rejected() -> None:
    result = evaluate_document(b"The reviewer must review the request.", b"The request must be reviewed.")
    assert not result.accepted
    assert result.protected_delta["specified"]
    assert "repair.specified_owner" in _codes(result)


@pytest.mark.parametrize(("baseline", "candidate"), [
    (b"The board must use the framework in order to verify the report.",
     b"The board must use the database to verify the report."),
    (b"The reviewer must close the finding in order to approve the release.",
     b"The owner must close the finding to approve the release."),
    (b"The reviewer must not approve the release.", b"The reviewer must approve the release."),
])
def test_actual_target_actor_and_polarity_changes_fail(baseline: bytes, candidate: bytes) -> None:
    result = evaluate_document(candidate, baseline)
    assert not result.accepted
    assert "repair.judge" in _codes(result)
    assert result.protected_delta["missing"] or result.protected_delta["added"] or result.protected_delta["unresolved"]


def test_table_requirements_are_scored_even_though_native_analyzer_excludes_them() -> None:
    bad = "The reviewer must ensure operational readiness review governance approval compliance verification certification audit readiness."
    candidate = f"| Requirement |\n|---|\n| {bad} |\n".encode()
    result = evaluate_document(candidate)
    assert not result.accepted
    assert any(violation["code"] == "quality.high_severity" for violation in result.violations)
    assert any(cast(dict[str, JsonValue], violation["location"]).get("row") == 2 for violation in result.violations)
    native = analyze_text(candidate.decode())
    assert not native["findings"]


def test_table_row_swap_cannot_pass_a_global_bag_of_protected_words() -> None:
    baseline = b"| Key | Requirement |\n|---|---|\n| First | The reviewer must close the finding in order to approve the release. |\n| Second | The owner must record the decision. |\n"
    candidate = b"| Key | Requirement |\n|---|---|\n| First | The owner must record the decision. |\n| Second | The reviewer must close the finding to approve the release. |\n"
    result = evaluate_document(candidate, baseline)
    assert not result.accepted
    assert "repair.table_meaning" in _codes(result)
    assert result.protected_delta["tables"]


@pytest.mark.parametrize("replacement", ["Permission", "Requirement | Extra"])
def test_table_header_and_column_changes_are_not_wording_repair(replacement: str) -> None:
    baseline = b"| Requirement |\n|---|\n| The owner must act. |\n"
    candidate = baseline.replace(b"Requirement", replacement.encode())
    result = evaluate_document(candidate, baseline)
    assert not result.accepted
    assert "repair.table_structure" in _codes(result)


@pytest.mark.parametrize("hidden", [
    b"`The reviewer must close the finding.`",
    b"```\nThe reviewer must close the finding.\n```",
    b"    The reviewer must close the finding.",
    b"<!-- The reviewer must close the finding. -->",
])
def test_prose_cannot_be_hidden_as_code_or_html(hidden: bytes) -> None:
    baseline = b"# Rules\n\n" + GOOD
    result = evaluate_document(b"# Rules\n\n" + hidden, baseline)
    assert not result.accepted
    assert _codes(result) & {"repair.literals", "coverage.html", "repair.judge"}


@pytest.mark.parametrize(("baseline", "candidate", "code"), [
    (b"The owner must read `rule_id`.", b"The owner must read `other_id`.", "repair.literals"),
    (b"Read [the report](https://first.test).", b"Read [the report](https://second.test).", "repair.links"),
    (b"The owner must act.\n\n```python\nx = 1\n```", b"The owner must act.\n\n```python\nx = 2\n```", "repair.literals"),
])
def test_protected_literals_code_and_links_are_preserved(baseline: bytes, candidate: bytes, code: str) -> None:
    result = evaluate_document(candidate, baseline)
    assert not result.accepted
    assert code in _codes(result)


@pytest.mark.parametrize("candidate", [b"", b" \r\n", b"---", b"```\nprose\n```", b"    prose", b"`identifier`", b"<!-- hidden -->"])
def test_empty_and_excluded_only_documents_never_score_one_hundred(candidate: bytes) -> None:
    result = evaluate_document(candidate)
    assert not result.accepted
    assert result.scores["document"] is None
    assert "coverage.unscorable" in _codes(result)
    _validate(result)


def test_repeated_high_occurrences_fail_even_when_rule_id_already_existed(monkeypatch: pytest.MonkeyPatch) -> None:
    original_analyze = analyze_text

    def analyzed(text: str, profile: Profile | None = None) -> dict[str, JsonValue]:
        artifact = original_analyze(text, profile)
        cast(dict[str, JsonValue], artifact["score"])["value"] = 100.0
        occurrences: list[JsonValue] = []
        cursor = 0
        while (start := text.find("reviewer", cursor)) >= 0:
            occurrences.append({
                "rule_id": "TEST-HIGH-001", "dimension": "lexical_clarity", "severity": "high",
                "location": {"start": start, "end": start + 8, "line": 1, "column": start + 1},
                "observed_value": "reviewer", "threshold": 0, "remediation": "Replace the synthetic defect.",
                "penalty": 0,
            })
            cursor = start + 8
        artifact["findings"] = occurrences
        return artifact

    monkeypatch.setattr(gate, "analyze_text", analyzed)
    candidate = GOOD + b"\n\nThe reviewer must record the decision."
    result = evaluate_document(candidate, candidate)
    high = [violation for violation in result.violations if violation["code"] == "quality.high_severity"]
    assert len(high) == 2
    assert result.scores["document"] == 100.0
    assert not result.accepted


@pytest.mark.parametrize("changes", [
    {"minimum_document_hri": 84.99}, {"minimum_block_hri": 0}, {"profile": "web-copy"},
    {"profile_version": "1.2.0"}, {"profile_digest": "0" * 64},
    {"reject_high_severity": False}, {"reject_specified_owners": False},
    {"require_relative_improvement": False}, {"max_input_bytes": 32769}, {"max_units": 257},
    {"minimum_document_hri": float("nan")}, {"minimum_block_hri": float("inf")},
    {"max_input_bytes": True}, {"untrusted_extra": True},
])
def test_policy_cannot_weaken_or_mutate_the_approved_contract(changes: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        GatePolicy.from_dict(changes)


def test_policy_can_only_tighten_limits_and_thresholds() -> None:
    policy = GatePolicy.from_dict({"minimum_document_hri": 90, "max_input_bytes": 4096})
    assert policy.minimum_document_hri == 90
    assert policy.max_input_bytes == 4096
    schema = json.loads((SCHEMAS / "gate-policy.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(policy.to_dict())


def test_profile_tampering_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = load_profile()
    monkeypatch.setattr(gate, "load_profile", lambda name: Profile(profile.data, "0" * 64))
    with pytest.raises(ValueError, match="pinned identity"):
        evaluate_document(GOOD)


@pytest.mark.parametrize("value", [b"\xff", b"\x00", b"\x1b[0m"])
def test_invalid_utf8_and_controls_are_input_errors(value: bytes) -> None:
    with pytest.raises(ValueError):
        evaluate_document(value)


def test_input_limit_is_measured_in_actual_bytes_for_both_inputs() -> None:
    policy = GatePolicy(max_input_bytes=len(GOOD))
    assert evaluate_document(GOOD, policy=policy).accepted
    for candidate, baseline in ((GOOD + b" ", None), (GOOD, GOOD + b" ")):
        with pytest.raises(ValueError, match="byte gate limit"):
            evaluate_document(candidate, baseline, policy)
    with pytest.raises(ValueError, match="byte gate limit"):
        evaluate_document(b" " * 32769)


def test_exact_default_input_byte_limit_can_be_evaluated() -> None:
    candidate = GOOD + b" " * (32768 - len(GOOD))
    result = evaluate_document(candidate)
    assert result.accepted
    assert result.candidate_sha256 == hashlib.sha256(candidate).hexdigest()


def test_multibyte_input_cannot_exceed_byte_limit_using_character_count() -> None:
    with pytest.raises(ValueError, match="byte gate limit"):
        evaluate_document(("\u00e9" * 21).encode(), policy=GatePolicy(max_input_bytes=36))


def test_limit_cannot_return_a_partial_success_or_unbounded_coverage() -> None:
    result = evaluate_document(GOOD + b"\n\n" + GOOD, policy=GatePolicy(max_units=1))
    assert not result.accepted
    assert "coverage.unit_limit" in _codes(result)
    assert result.coverage["units_count"] == 2
    assert result.coverage["units_truncated"] is True
    assert len(cast(list[JsonValue], result.coverage["units"])) == 1


@pytest.mark.parametrize("units", [256, 257])
def test_default_unit_limit_scores_all_units_or_rejects_the_document(units: int) -> None:
    candidate = b"\n\n".join(f"Entry {index}.".encode() for index in range(units))
    result = evaluate_document(candidate)
    assert result.coverage["units_count"] == units
    if units == 256:
        assert "coverage.unit_limit" not in _codes(result)
        assert len(cast(list[JsonValue], result.scores["blocks"])) == 256
    else:
        assert not result.accepted
        assert "coverage.unit_limit" in _codes(result)
        assert result.scores["document"] is None
        assert result.coverage["units_truncated"] is True
    _validate(result)


def test_byte_hashes_differ_from_projection_and_include_crlf_and_bom() -> None:
    candidate = b"\xef\xbb\xbf# Rules\r\n\r\n" + GOOD + b"\r\n"
    result = evaluate_document(candidate, candidate)
    assert result.accepted
    assert result.candidate_sha256 == hashlib.sha256(candidate).hexdigest()
    assert result.baseline_sha256 == result.candidate_sha256
    assert result.projected_sha256 != result.candidate_sha256
    assert result.baseline_projected_sha256 == result.projected_sha256


def test_cache_identity_binds_policy_profile_model_parser_and_code(monkeypatch: pytest.MonkeyPatch) -> None:
    identity = cache_identity()
    assert cache_identity() == identity
    assert cache_identity(GatePolicy(minimum_document_hri=90)) != identity
    fingerprint = model_fingerprint()
    monkeypatch.setattr(gate, "model_fingerprint", lambda: {**fingerprint, "digest": "0" * 64})
    assert cache_identity() != identity
    monkeypatch.undo()
    parser = parser_fingerprint()
    monkeypatch.setattr(gate, "parser_fingerprint", lambda: {**parser, "version": "3.99.0"})
    assert cache_identity() != identity
    monkeypatch.undo()
    original_read = Path.read_bytes

    def changed(path: Path) -> bytes:
        return original_read(path) + (b"\n# changed gate implementation" if path.name == "gate.py" else b"")

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert cache_identity() != identity


def test_dependency_failure_never_becomes_a_passing_result(monkeypatch: pytest.MonkeyPatch) -> None:
    def unavailable() -> dict[str, str]:
        raise RuntimeError("Pinned model is unavailable")

    monkeypatch.setattr(gate, "model_fingerprint", unavailable)
    with pytest.raises(RuntimeError, match="unavailable"):
        evaluate_document(GOOD)


def test_gate_makes_no_network_or_remote_provider_call(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        raise AssertionError("network access is forbidden")

    monkeypatch.setattr(socket, "create_connection", forbidden)
    assert evaluate_document(GOOD).accepted


def test_serialized_result_is_detached_from_mutable_callers() -> None:
    result = evaluate_document(GOOD)
    serialized = result.to_dict()
    before = copy.deepcopy(result.to_dict())
    cast(dict[str, JsonValue], serialized["scores"])["document"] = 0
    assert result.to_dict() == before


def test_feedback_is_bounded_and_reports_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    _score_seam(monkeypatch, 80)
    result = evaluate_document(GOOD + b"\n\n" + GOOD, policy=GatePolicy(max_feedback_items=1))
    assert not result.accepted
    assert result.violation_count > len(result.violations) == 1
    assert result.to_dict()["violations_truncated"] is True
    assert "source" not in result.critique
    _validate(result)
