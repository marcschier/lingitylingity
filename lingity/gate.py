"""Local absolute authoring policy and frozen-baseline repair evaluation.

No provider is invoked here. Configuration/dependency/input errors raise;
quality, coverage and protected-meaning failures return a rejected result.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import platform
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from functools import lru_cache
from importlib.metadata import version
from pathlib import Path
from typing import cast

from jsonschema import Draft202012Validator

from lingity.analyzer import ANALYZER_VERSION, analyze_text
from lingity.critique import build_critique
from lingity.gate_markdown import (
    PROJECTION_VERSION,
    MarkdownProjection,
    ProseUnit,
    project_markdown,
    source_location,
)
from lingity.invariants import compare_protected, extract_protected
from lingity.markdown import parser_fingerprint
from lingity.models import JsonValue
from lingity.nlp import model_fingerprint
from lingity.profiles import Profile, load_profile, sha256_json

GATE_VERSION = "1.0.0"
PROFILE_DIGEST = "92b2032db19672b09990484750bcc03e07d5b8ef9b8cecfaee59de2be912f9a9"
_PACKAGE = Path(__file__).resolve().parent


@dataclass(frozen=True)
class GatePolicy:
    """Trusted policy; callers may tighten, but cannot weaken the agreed floor.

    Evaluation supports at most 32 KiB per input and 256 projection units.
    Oversize bytes raise an input error; excess units produce a located
    coverage rejection. Neither limit permits a partial-document pass.
    """

    schema_version: str = "1.0.0"
    profile: str = "architecture-review"
    profile_version: str = "1.3.0"
    profile_digest: str = PROFILE_DIGEST
    minimum_document_hri: float = 85.0
    minimum_block_hri: float = 85.0
    reject_high_severity: bool = True
    reject_specified_owners: bool = True
    require_relative_improvement: bool = True
    max_input_bytes: int = 32768
    max_units: int = 256
    max_feedback_items: int = 64
    max_feedback_chars: int = 240

    def __post_init__(self) -> None:
        schema = json.loads((_PACKAGE / "schemas" / "v1" / "gate-policy.schema.json").read_text(encoding="utf-8"))
        data = asdict(self)
        try:
            json.dumps(data, allow_nan=False)
        except (TypeError, ValueError) as error:
            raise ValueError(f"Invalid gate policy: {error}") from error
        errors = sorted(Draft202012Validator(schema).iter_errors(data), key=lambda error: str(error.path))
        if errors:
            details = "; ".join(error.message for error in errors[:5])
            raise ValueError(f"Invalid gate policy: {details}")

    @classmethod
    def from_dict(cls, value: Mapping[str, object]) -> GatePolicy:
        if not isinstance(value, Mapping):
            raise ValueError("Gate policy must be a JSON object")
        defaults = asdict(cls())
        unknown = set(value) - set(defaults)
        if unknown:
            raise ValueError(f"Unknown gate policy fields: {sorted(unknown, key=str)}")
        # Runtime schema validation in __post_init__ is authoritative, including
        # types: dataclass annotations alone do not reject booleans as numbers.
        defaults.update(value)
        return cls(**defaults)

    def to_dict(self) -> dict[str, JsonValue]:
        return cast(dict[str, JsonValue], asdict(self))


@dataclass(frozen=True)
class GateResult:
    accepted: bool
    violations: tuple[dict[str, JsonValue], ...]
    violation_count: int
    scores: dict[str, JsonValue]
    coverage: dict[str, JsonValue]
    identities: dict[str, JsonValue]
    candidate_sha256: str
    baseline_sha256: str | None
    projected_sha256: str
    baseline_projected_sha256: str | None
    protected_delta: dict[str, JsonValue]
    critique: dict[str, JsonValue]

    def to_dict(self) -> dict[str, JsonValue]:
        return copy.deepcopy({
            "schema_version": "1.0.0",
            "kind": "lingity.gate-result.v1",
            "accepted": self.accepted,
            "violations": list(self.violations),
            "violation_count": self.violation_count,
            "violations_truncated": self.violation_count > len(self.violations),
            "scores": self.scores,
            "coverage": self.coverage,
            "identities": self.identities,
            "candidate_sha256": self.candidate_sha256,
            "baseline_sha256": self.baseline_sha256,
            "projected_sha256": self.projected_sha256,
            "baseline_projected_sha256": self.baseline_projected_sha256,
            "protected_delta": self.protected_delta,
            "critique": self.critique,
        })


def _profile(policy: GatePolicy) -> Profile:
    profile = load_profile(policy.profile)
    if (profile.name, profile.version, profile.digest) != (
        policy.profile, policy.profile_version, policy.profile_digest
    ):
        raise ValueError("Installed architecture-review profile does not match the gate's pinned identity")
    return profile


@lru_cache(maxsize=1)
def _wordnet_identity() -> str:
    from lingity.morphology import _load_wordnet

    try:
        corpus = _load_wordnet()
    except LookupError as error:
        raise RuntimeError("WordNet corpus data is unavailable; install it with python -m nltk.downloader wordnet") from error
    digest = hashlib.sha256()
    for name in sorted(corpus.fileids()):
        digest.update(name.encode("utf-8"))
        with corpus.root.join(name).open() as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
    return digest.hexdigest()


def _identities(policy: GatePolicy, profile: Profile) -> dict[str, JsonValue]:
    code: dict[str, JsonValue] = {}
    for name in (
        "gate.py", "gate_markdown.py", "analyzer.py", "markdown.py", "invariants.py",
        "nlp.py", "morphology.py", "profiles.py", "scoring.py", "critique.py",
        "improve.py", "text.py", "models.py", "lexicon.py",
        "schemas/v1/gate-policy.schema.json", "schemas/v1/gate-result.schema.json",
    ):
        code[name] = hashlib.sha256((_PACKAGE / name).read_bytes()).hexdigest()
    identity: dict[str, JsonValue] = {
        "gate_version": GATE_VERSION,
        "projection_version": PROJECTION_VERSION,
        "text_normalization": "universal-newlines",
        "analyzer_version": ANALYZER_VERSION,
        "profile": profile.reference(),
        "policy": policy.to_dict(),
        "policy_sha256": sha256_json(policy.to_dict()),
        "linguistic_model": cast(dict[str, JsonValue], model_fingerprint()),
        "parser": cast(dict[str, JsonValue], parser_fingerprint()),
        "python": platform.python_version(),
        "runtime": {name: version(name) for name in ("lingity", "nltk", "spacy", "thinc", "numpy", "jsonschema", "mdurl")},
        "wordnet_sha256": _wordnet_identity(),
        "code_sha256": sha256_json(code),
    }
    identity["cache_identity"] = sha256_json(identity)
    return identity


def cache_identity(policy: GatePolicy | None = None) -> str:
    """Identity of the local contract; model/corpus loads are reused in-process.

    Code is rehashed on each call so edits under an unchanged version cannot
    reuse a stale acceptance. Original-byte identities belong to each result.
    """
    selected = policy or GatePolicy()
    return cast(str, _identities(selected, _profile(selected))["cache_identity"])


def _decode(value: bytes, label: str, policy: GatePolicy) -> str:
    if not isinstance(value, bytes):
        raise ValueError(f"{label} must be bytes")
    if len(value) > policy.max_input_bytes:
        raise ValueError(f"{label} exceeds the {policy.max_input_bytes}-byte gate limit")
    try:
        text = value.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} must be valid UTF-8") from error
    if any(ord(character) < 32 and character not in "\t\r\n" for character in text):
        raise ValueError(f"{label} contains unsupported control characters")
    return text


def _normalized_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _literal_text(projection: MarkdownProjection | ProseUnit) -> tuple[str, ...]:
    return tuple(_normalized_newlines(text) for text in projection.literals)


def _object(value: JsonValue, label: str) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise RuntimeError(f"Invalid analysis artifact: {label} must be an object")
    return value


def _score(analysis: dict[str, JsonValue]) -> float:
    value = _object(analysis.get("score"), "score").get("value")
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or not 0 <= value <= 100:
        raise RuntimeError("Invalid analysis artifact: HRI must be finite and between 0 and 100")
    return float(value)


def _bounded(value: JsonValue, policy: GatePolicy) -> JsonValue:
    if isinstance(value, str):
        return value if len(value) <= policy.max_feedback_chars else value[:policy.max_feedback_chars - 3] + "..."
    if isinstance(value, list):
        return [_bounded(item, policy) for item in value[:policy.max_feedback_items]]
    if isinstance(value, dict):
        return {key: item if key.endswith("_sha256") else _bounded(item, policy)
                for key, item in value.items()}
    return value


def _shape(projection: MarkdownProjection) -> list[dict[str, JsonValue]]:
    return [{key: value for key, value in table.items() if key != "location"} for table in projection.tables]


def _coverage_result(projection: MarkdownProjection, policy: GatePolicy) -> dict[str, JsonValue]:
    result = projection.coverage()
    for key in ("units", "exclusions", "tables"):
        items = cast(list[JsonValue], result[key])
        result[f"{key}_count"] = len(items)
        result[f"{key}_truncated"] = len(items) > policy.max_units
        # Coverage locations are evidence, not prose excerpts: only their
        # human-readable strings are bounded, and numeric offsets stay intact.
        result[key] = [_bounded(item, policy) for item in items[:policy.max_units]]
        if key == "tables":
            for raw, reported in zip(items, cast(list[JsonValue], result[key])):
                table = _object(raw, "table coverage")
                report = _object(reported, "table coverage")
                report["structure_sha256"] = sha256_json({name: value for name, value in table.items() if name != "location"})
                for field in ("headers", "row_widths", "alignments"):
                    values = cast(list[JsonValue], table[field])
                    report[f"{field}_count"] = len(values)
                    report[f"{field}_truncated"] = len(values) > policy.max_feedback_items
    return result


def evaluate_document(
    candidate: bytes,
    baseline: bytes | None = None,
    policy: GatePolicy | None = None,
) -> GateResult:
    """Apply absolute quality first, then wording-only repair constraints.

    Scores are the analyzer's published HRI, not rounded again here. A baseline
    is supplied by the state owner; this function never captures or replaces it.
    Host newline normalization is content identity, not a wording repair. Byte
    hashes and source locations nevertheless retain the exact supplied bytes.
    """
    selected = policy or GatePolicy()
    text = _decode(candidate, "Candidate", selected)
    baseline_text = _decode(baseline, "Baseline", selected) if baseline is not None else None
    profile = _profile(selected)
    identities = _identities(selected, profile)
    projected = project_markdown(text)
    original = project_markdown(baseline_text) if baseline_text is not None else None
    violations: list[dict[str, JsonValue]] = []

    def reject(code: str, message: str, location: dict[str, JsonValue], **details: JsonValue) -> None:
        violations.append({"code": code, "message": message, "location": location, **details})

    def coverage(projection: MarkdownProjection, label: str) -> bool:
        for issue in projection.issues:
            reject(issue.code, issue.message, source_location(projection.source, issue.start, issue.end), source=label)
        if not any(unit.substantive for unit in projection.units):
            reject("coverage.unscorable", "No substantive prose is available to score.",
                   source_location(projection.source, 0, len(projection.source)), source=label)
        if len(projection.units) > selected.max_units:
            reject("coverage.unit_limit", f"Document exceeds the {selected.max_units}-unit evaluation limit.",
                   source_location(projection.source, 0, len(projection.source)), source=label)
        return not projection.issues and bool(projection.text) and len(projection.units) <= selected.max_units

    scorable = coverage(projected, "candidate")
    baseline_scorable = coverage(original, "baseline") if original is not None else False
    analyses: dict[str, dict[str, JsonValue]] = {}

    def analyze(content: str) -> dict[str, JsonValue]:
        if content not in analyses:
            analyses[content] = analyze_text(content, profile=profile)
        return analyses[content]

    def manifest(projection: MarkdownProjection) -> dict[str, JsonValue]:
        # Extraction parses its input as plain text. Pool independently
        # extracted units so a header or row label cannot become the actor of
        # the following requirement. Comparison still belongs to the existing
        # comparator, including its fail-closed uncovered-content handling.
        items: list[JsonValue] = []
        signatures: list[JsonValue] = []
        uncovered: list[JsonValue] = []
        sentences = 0
        for unit in projection.units:
            if not unit.substantive:
                continue
            protected = _object(analyze(unit.text).get("protected"), "protected")
            items.extend(cast(list[JsonValue], protected["items"]))
            signatures.extend(cast(list[JsonValue], protected["semantic_signature"]))
            unit_coverage = _object(protected["coverage"], "protected.coverage")
            for raw in cast(list[JsonValue], unit_coverage["uncovered"]):
                entry = dict(_object(raw, "protected.coverage.uncovered"))
                entry["sentence_index"] = cast(int, entry["sentence_index"]) + sentences
                uncovered.append(entry)
            sentences += cast(int, unit_coverage["sentences"])
        pooled: dict[str, JsonValue] = {
            "items": items, "semantic_signature": signatures,
            "coverage": {"sentences": sentences, "uncovered": uncovered},
            "source_sha256": projection.sha256,
        }
        pooled["sha256"] = sha256_json(pooled)
        return pooled

    def analyzed_coverage(analysis: dict[str, JsonValue], location: dict[str, JsonValue], label: str = "candidate") -> None:
        ingest = _object(analysis.get("ingest"), "ingest")
        blocks = _object(ingest.get("blocks"), "ingest.blocks")
        if ingest.get("unresolved_lines") != 0 or ingest.get("uncovered_lines") != 0:
            reject("coverage.analysis", "The analyzer could not cover the projected content.", location, source=label)
        if not isinstance(ingest.get("analyzed_characters"), int) or cast(int, ingest["analyzed_characters"]) <= 0:
            reject("coverage.analysis", "Projected content contains no analyzable characters.", location, source=label)
        if any(blocks.get(kind) for kind in ("code", "table", "html", "rule")):
            reject("coverage.reclassified", "Readable content became excluded Markdown during projection.", location, source=label)

    document_score: float | None = None
    baseline_score: float | None = None
    block_scores: list[JsonValue] = []
    critique: dict[str, JsonValue] = {"defects": [], "defect_count": 0, "truncated": False}
    delta: dict[str, JsonValue] = {"disposition": "not_compared", "missing": [], "added": [], "unresolved": [], "specified": [], "tables": []}
    seen_high: set[tuple[str, int, int, str]] = set()

    def findings(analysis: dict[str, JsonValue], unit: ProseUnit | None = None) -> None:
        raw = analysis.get("findings")
        if not isinstance(raw, list):
            raise RuntimeError("Invalid analysis artifact: findings must be an array")
        for value in raw:
            finding = _object(value, "finding")
            if finding.get("severity") != "high":
                continue
            at = _object(finding.get("location"), "finding.location")
            start, end = at.get("start"), at.get("end")
            content = projected.text if unit is None else unit.text
            if not isinstance(start, int) or not isinstance(end, int) or not 0 <= start < end <= len(content):
                raise RuntimeError("Invalid analysis artifact: finding location is outside projected text")
            location = projected.location(start, end) if unit is None else unit.location(text, start, end)
            key = (str(finding.get("rule_id")), cast(int, location["start"]), cast(int, location["end"]),
                   sha256_json([finding.get("observed_value"), finding.get("threshold")]))
            if key in seen_high:
                continue
            seen_high.add(key)
            reject("quality.high_severity", str(finding.get("remediation")), location,
                   rule_id=finding.get("rule_id"), severity="high")

    if scorable:
        document = analyze(projected.text)
        analyzed_coverage(document, projected.location())
        document_score = _score(document)
        if document_score < selected.minimum_document_hri:
            reject("quality.document_hri", "Document HRI is below the absolute minimum.",
                   projected.location(), observed=document_score, required=selected.minimum_document_hri)
        findings(document)
        for unit in projected.units:
            if not unit.substantive:
                continue
            analysis = analyze(unit.text)
            location = unit.location(text)
            analyzed_coverage(analysis, location)
            score = _score(analysis)
            block_scores.append({"unit": unit.id, "value": score, "location": location})
            if score < selected.minimum_block_hri:
                reject("quality.block_hri", "Substantive block HRI is below the absolute minimum.",
                       location, observed=score, required=selected.minimum_block_hri)
            findings(analysis, unit)
        brief = build_critique({**document, "protected": manifest(projected)})
        defects = cast(list[JsonValue], brief["defects"])
        located_defects: list[JsonValue] = []
        for raw in defects[:selected.max_feedback_items]:
            defect = dict(_object(raw, "critique.defect"))
            at = _object(defect["location"], "critique.location")
            defect["location"] = projected.location(cast(int, at["start"]), cast(int, at["end"]))
            located_defects.append(defect)
        critique.update({"defects": _bounded(located_defects, selected), "defect_count": len(defects),
                         "truncated": len(defects) > selected.max_feedback_items,
                         "analysis_sha256": document["analysis_sha256"],
                         "must_preserve": _bounded(brief["must_preserve"], selected)})
        preserve_count = len(cast(list[JsonValue], brief["must_preserve"]))
        critique["must_preserve_count"] = preserve_count
        critique["must_preserve_truncated"] = preserve_count > selected.max_feedback_items
        critique["truncated"] = bool(critique["truncated"]) or preserve_count > selected.max_feedback_items

    if original is not None:
        if _literal_text(original) != _literal_text(projected):
            reject("repair.literals", "Wording repair must preserve literal/code spans and link definitions.",
                   projected.location())
        if original.links != projected.links:
            reject("repair.links", "Wording repair must preserve ordered link destinations and titles.",
                   projected.location())
        if _shape(original) != _shape(projected):
            reject("repair.table_structure", "Wording repair must preserve table headers, rows, columns and alignment.",
                   projected.location())
        if baseline_text is not None and _normalized_newlines(baseline_text) == _normalized_newlines(text):
            delta["disposition"] = "unchanged"
            baseline_score = document_score
        elif scorable and baseline_scorable:
            source_analysis = analyze(original.text)
            baseline_score = _score(source_analysis)
            analyzed_coverage(source_analysis, original.location(), "baseline")
            for baseline_unit in original.units:
                if baseline_unit.substantive:
                    analyzed_coverage(analyze(baseline_unit.text), baseline_unit.location(original.source), "baseline")
            comparison = compare_protected(manifest(original), manifest(projected))
            delta = {key: comparison[key] for key in ("missing", "added", "unresolved", "specified")}
            delta["disposition"] = comparison["disposition"]
            delta["tables"] = []
            if comparison["disposition"] != "equivalent":
                reject("repair.judge", f"Protected meaning is {comparison['disposition']}; restore the located protected deltas.",
                       projected.location())
            if document_score is None or document_score <= baseline_score:
                verb = "did not change" if document_score == baseline_score else "regressed"
                reject("repair.judge", f"Readability {verb}; a changed candidate must strictly improve the published document HRI.",
                       projected.location(), observed=document_score, baseline=baseline_score)
            if delta.get("specified"):
                reject("repair.specified_owner", "Naming a previously unspecified owner requires source authority.",
                       projected.location(), specified=delta["specified"])
            before = {(unit.table, unit.row, unit.cell): unit for unit in original.units if unit.table is not None}
            table_deltas: list[JsonValue] = []
            for unit in projected.units:
                if unit.table is None:
                    continue
                previous = before.get((unit.table, unit.row, unit.cell))
                if previous is None or previous.text == unit.text:
                    continue
                comparison = compare_protected(extract_protected(previous.text, profile),
                                               extract_protected(unit.text, profile))
                if _literal_text(previous) != _literal_text(unit) or previous.links != unit.links:
                    reject("repair.table_literals", "Literal spans and links must stay in their original table cell.",
                           unit.location(text))
                if comparison["disposition"] != "equivalent" or comparison.get("specified"):
                    table_deltas.append({"unit": unit.id, "location": unit.location(text), "comparison": comparison})
                    reject("repair.table_meaning", "Protected meaning must remain in its original row/header association.",
                           unit.location(text))
            delta["tables"] = table_deltas

    bounded_violations = tuple(cast(dict[str, JsonValue], _bounded(item, selected))
                               for item in violations[:selected.max_feedback_items])
    critique["absolute_policy"] = {
        "minimum_document_hri": selected.minimum_document_hri,
        "minimum_block_hri": selected.minimum_block_hri,
        "maximum_high_severity_findings": 0,
        "violations": list(bounded_violations),
        "violation_count": len(violations),
    }
    critique["untrusted_document_data"] = True
    delta["counts"] = {key: len(cast(list[JsonValue], delta[key]))
                       for key in ("missing", "added", "unresolved", "specified", "tables")}
    delta["truncated"] = any(cast(int, count) > selected.max_feedback_items
                             for count in cast(dict[str, JsonValue], delta["counts"]).values())
    return GateResult(
        not violations, bounded_violations, len(violations),
        {"document": document_score, "baseline_document": baseline_score, "blocks": block_scores,
         "minimum_document_hri": selected.minimum_document_hri, "minimum_block_hri": selected.minimum_block_hri},
        _coverage_result(projected, selected), identities, hashlib.sha256(candidate).hexdigest(),
        hashlib.sha256(baseline).hexdigest() if baseline is not None else None,
        projected.sha256, original.sha256 if original is not None else None,
        cast(dict[str, JsonValue], _bounded(delta, selected)), critique,
    )
