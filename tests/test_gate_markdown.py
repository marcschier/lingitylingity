"""Gate projection covers tables without changing the native ingest contract."""

from __future__ import annotations

from typing import cast

import pytest
from markdown_it.token import Token

from lingity import gate_markdown
from lingity.gate import evaluate_document
from lingity.gate_markdown import project_markdown
from lingity.markdown import segment_source


@pytest.mark.parametrize("underline", ["---", "==="])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
@pytest.mark.parametrize(("prefix", "continuation"), [("", ""), ("> ", "> "), ("- ", "  ")])
def test_setext_heading_maps_include_structure_but_score_only_prose(
    underline: str, newline: str, prefix: str, continuation: str,
) -> None:
    source = newline.join([
        prefix + "The reviewer must",
        continuation + "approve the release.",
        continuation + underline,
        "",
        "The owner must record the decision.",
        "",
    ])
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.uncovered_lines == projection.unresolved_lines == 0
    heading = projection.units[0]
    assert heading.kind == "heading" and heading.substantive
    assert heading.text == "The reviewer must\napprove the release."
    start = heading.text.index("approve")
    location = heading.location(source, start, start + len("approve"))
    assert location["line"] == 2
    assert location["column"] == len(continuation) + 1
    assert source[cast(int, location["start"]):cast(int, location["end"])] == "approve"
    marker = next(item for item in projection.exclusions if item["kind"] == "heading_marker")
    assert cast(dict[str, object], marker["location"])["line"] == 3
    assert underline not in projection.text
    assert projection.units[-1].text == "The owner must record the decision."


def test_leading_separator_and_metadata_like_setext_heading_are_fully_scored() -> None:
    source = '---\napplyTo: "**"\n---\n\nThe reviewer must approve the release.\n'
    native_before = segment_source(source)
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.units[0].text == 'applyTo: "**"'
    assert projection.units[0].substantive
    assert projection.literals == ('applyTo: "**"',)
    assert [unit.kind for unit in projection.units] == ["heading", "prose"]
    assert projection.text == 'applyTo: "**"\n\nThe reviewer must approve the release.'
    result = evaluate_document(source.encode())
    assert result.accepted, result.to_dict()
    assert result.scores["document"] is not None
    assert len(cast(list[object], result.scores["blocks"])) == 2
    assert result.coverage["uncovered_lines"] == 0
    assert segment_source(source) == native_before


def test_prose_in_a_metadata_like_heading_has_no_quality_exemption() -> None:
    prose = "The reviewer must ensure operational readiness review governance approval compliance verification certification audit readiness."
    source = f'---\napplyTo: "**"\ndescription: {prose}\n---\n\nThe reviewer must approve the release.\n'
    projection = project_markdown(source)
    assert not projection.issues
    assert prose in projection.text
    assert projection.units[0].substantive
    result = evaluate_document(source.encode())
    assert not result.accepted
    assert result.scores["document"] is not None
    assert any(violation["code"] == "quality.high_severity" for violation in result.violations)
    assert result.coverage["uncovered_lines"] == 0


@pytest.mark.parametrize("replacement", ['"*"','"**/*.md"', "'**'"])
def test_metadata_like_quoted_glob_spelling_cannot_change_during_repair(replacement: str) -> None:
    baseline = b'---\napplyTo: "**"\n---\n\nThe release must be approved by the reviewer.\n'
    candidate = f'---\napplyTo: {replacement}\n---\n\nThe reviewer must approve the release.\n'.encode()
    result = evaluate_document(candidate, baseline)
    assert not result.accepted
    assert any(violation["code"] == "repair.literals" for violation in result.violations)


def test_metadata_like_heading_can_remain_unchanged_during_body_repair() -> None:
    baseline = b'---\napplyTo: "**"\n---\n\nThe release must be approved by the reviewer.\n'
    candidate = b'---\r\napplyTo: "**"\r\n---\r\n\r\nThe reviewer must approve the release.\r\n'
    result = evaluate_document(candidate, baseline)
    assert result.accepted, result.to_dict()


def test_prose_and_table_projection_retains_original_cell_locations() -> None:
    source = "# Rules\r\n\r\nThe reviewer must act.\r\n\r\n| Owner | Rule |\r\n| --- | --- |\r\n| Team | The owner must close the finding. |\r\n"
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.uncovered_lines == projection.unresolved_lines == 0
    assert [unit.kind for unit in projection.units] == [
        "heading", "prose", "table_header", "table_header", "table_cell", "table_cell"
    ]
    cell = projection.units[-1]
    at = cell.location(source)
    assert at["line"] == 7
    assert at["table"] == 1 and at["row"] == 2 and at["cell"] == 2
    assert at["header"] == "Rule"
    assert source[cast(int, at["start"]):cast(int, at["end"])] == cell.text
    assert projection.tables[0]["row_widths"] == [2, 2]


@pytest.mark.parametrize("prefix", ["", "> ", "- "])
def test_table_parser_supplies_container_aware_source_rows(prefix: str) -> None:
    continuation = "  " if prefix == "- " else prefix
    source = f"{prefix}| Owner | Rule |\n{continuation}| --- | --- |\n{continuation}| Team | The reviewer must act. |\n"
    projection = project_markdown(source)
    assert not projection.issues
    assert len(projection.tables) == 1
    assert projection.units[-1].text == "The reviewer must act."
    assert projection.units[-1].location(source)["line"] == 3


@pytest.mark.parametrize("cell", [r"a\|b", r"a\\|b", r"`a\|b`", r"[a\|b](https://example.test)"])
def test_escaped_pipes_follow_the_parser_splitter(cell: str) -> None:
    source = f"| Key | Value |\n| --- | --- |\n| {cell} | The owner must act. |\n"
    projection = project_markdown(source)
    assert not projection.issues
    assert len(projection.units) == 4
    unit = projection.units[2]
    assert unit.text.replace("|", r"\|") == cell
    assert source[unit.start:unit.end] == cell
    assert projection.units[-1].text == "The owner must act."


def test_empty_and_padded_cells_are_explicit_not_prose() -> None:
    projection = project_markdown("| A | B |\n|---|---|\n| | |\n| value |\n")
    assert not projection.issues
    assert len(projection.units) == 6
    assert [unit.substantive for unit in projection.units] == [True, True, False, False, True, False]
    assert projection.tables[0]["row_widths"] == [2, 2, 1]


def test_table_overflow_is_rejected_instead_of_discarded() -> None:
    source = "| A | B |\n|---|---|\n| x | y | The owner must delete the archive. |\n"
    projection = project_markdown(source)
    issue = next(issue for issue in projection.issues if issue.code == "coverage.table_overflow")
    assert "delete the archive" in source[issue.start:issue.end]


def test_duplicate_cells_are_located_in_source_order() -> None:
    source = "| Name | Name |\n|---|---|\n| value | value |\n"
    units = project_markdown(source).units
    assert units[0].end < units[1].start
    assert units[2].end < units[3].start


def test_unicode_crlf_wrapped_list_and_literal_spans() -> None:
    source = "- The reviewer must inspect the caf\u00e9\r\n  before approving `rule_id`.\r\n"
    projection = project_markdown(source)
    assert not projection.issues
    unit, = projection.units
    assert unit.kind == "list_item"
    assert "caf\u00e9\nbefore" in unit.text
    assert unit.literals == ("`rule_id`",)
    start = unit.text.index("before")
    at = unit.location(source, start, start + len("before"))
    assert at["line"] == 2 and at["column"] == 3
    assert source[cast(int, at["start"]):cast(int, at["end"])] == "before"


def test_multiline_code_span_preserves_literal_source_bytes_as_text() -> None:
    source = "> Read `first\r\n> second` before approval.\r\n"
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.literals == ("`first\r\n> second`",)


@pytest.mark.parametrize("source", [
    "<div>The owner must act.</div>\n",
    "The owner <em>must</em> act.\n",
    "<!-- The owner must act. -->\n",
    "| Rule |\n|---|\n| The owner <b>must</b> act. |\n",
])
def test_raw_html_is_explicitly_unsupported(source: str) -> None:
    assert any(issue.code == "coverage.html" for issue in project_markdown(source).issues)


@pytest.mark.parametrize("source", [
    "&#84;he reviewer must act.",
    "The&nbsp;reviewer must act.",
    "| Rule |\n|---|\n| &#84;he reviewer must act. |\n",
    "[&#84;he](The) reviewer must act.",
])
def test_decoded_entity_spelling_cannot_hide_prose(source: str) -> None:
    assert any(issue.code == "coverage.inline_normalization" for issue in project_markdown(source).issues)


def test_entities_inside_literal_code_remain_literal() -> None:
    projection = project_markdown("The reviewer must read `&amp;`.")
    assert not projection.issues
    assert projection.literals == ("`&amp;`",)


def test_links_images_and_reference_definitions_remain_bound() -> None:
    source = "Read [the report][report] and ![the diagram](diagram.svg).\n\n[report]: https://example.test \"Report\"\n"
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.uncovered_lines == 0
    assert len(projection.links) == 2
    assert any("https://example.test" in link for link in projection.links)
    assert projection.literals == ('[report]: https://example.test "Report"',)
    assert any(item["kind"] == "link_definition" for item in projection.exclusions)


def test_explicit_uncovered_line_for_duplicate_reference_definition() -> None:
    source = "The owner must act.\n\n[r]: https://a.test\n[r]: https://b.test\n"
    projection = project_markdown(source)
    assert projection.uncovered_lines == 1
    assert any(issue.code == "coverage.uncovered" for issue in projection.issues)


def test_unresolved_prose_mapping_is_not_silently_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    def unresolved(source: str, token: Token, bounds: list[tuple[int, int]]) -> tuple[list[tuple[int, int]], int]:
        return [], 1

    monkeypatch.setattr(gate_markdown, "_content_spans", unresolved)
    projection = project_markdown("The owner must act.\n")
    assert projection.unresolved_lines == 1
    assert any(issue.code == "coverage.unresolved" for issue in projection.issues)


def test_bom_keeps_original_character_offsets() -> None:
    source = "\ufeff# Rules\n\nThe owner must act.\n"
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.units[0].text == "Rules"
    assert projection.units[0].location(source)["start"] == 3


def test_cr_only_lines_keep_original_line_and_column_locations() -> None:
    source = "# Rules\r\rThe owner must act.\r"
    projection = project_markdown(source)
    assert not projection.issues
    assert projection.units[-1].location(source)["line"] == 3
    assert projection.units[-1].location(source)["column"] == 1


def test_native_table_exclusion_is_unchanged_by_gate_parser() -> None:
    source = "The owner must act.\n\n| Rule |\n|---|\n| The reviewer must act. |\n"
    before = segment_source(source)
    projection = project_markdown(source)
    after = segment_source(source)
    assert before == after
    assert [block.kind for block in after.blocks] == ["prose", "table"]
    assert any(unit.kind == "table_cell" for unit in projection.units)


def test_projection_is_deterministic() -> None:
    source = "| A | B |\n|:---|---:|\n| The owner must act. | `rule_id` |\n"
    assert project_markdown(source) == project_markdown(source)
    assert project_markdown(source).sha256 == project_markdown(source).sha256
