"""Fail-closed Markdown projection for the authoring gate, not native analysis.

The existing parser owns the grammar. A wrapper around its table rule records
the exact row slices while container offsets are still available. Source maps
then follow the parser's own splitter, including its escaped-pipe semantics.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, cast

from markdown_it import MarkdownIt
from markdown_it.common.utils import UNESCAPE_ALL_RE, unescapeAll
from markdown_it.rules_block import StateBlock
from markdown_it.rules_block.table import escapedSplit, getLine, table
from markdown_it.token import Token

from lingity.markdown import (
    _content_spans,
    _line_bounds,
    inline_code_spans,
    parser_fingerprint,
)
from lingity.models import JsonValue
from lingity.profiles import canonical_json

PROJECTION_VERSION = "1.0.0"


@dataclass(frozen=True)
class ProjectionIssue:
    code: str
    message: str
    start: int
    end: int


@dataclass(frozen=True)
class ProseUnit:
    id: str
    kind: str
    text: str
    offsets: tuple[int, ...]
    start: int
    end: int
    substantive: bool
    table: int | None = None
    row: int | None = None
    cell: int | None = None
    header: str | None = None
    literals: tuple[str, ...] = ()
    links: tuple[str, ...] = ()

    def location(self, source: str, start: int = 0, end: int | None = None) -> dict[str, JsonValue]:
        stop = len(self.offsets) if end is None else end
        left = self.offsets[start] if 0 <= start < len(self.offsets) else self.start
        right = self.offsets[stop - 1] + 1 if 0 < stop <= len(self.offsets) else self.end
        result = source_location(source, left, max(left, right))
        result["unit"] = self.id
        if self.table is not None:
            result.update({"table": self.table, "row": self.row, "cell": self.cell,
                           "header": self.header[:240] if self.header is not None else None})
        return result


@dataclass(frozen=True)
class MarkdownProjection:
    source: str
    units: tuple[ProseUnit, ...]
    text: str
    offsets: tuple[int, ...]
    issues: tuple[ProjectionIssue, ...]
    exclusions: tuple[dict[str, JsonValue], ...]
    tables: tuple[dict[str, JsonValue], ...]
    literals: tuple[str, ...]
    links: tuple[str, ...]
    unresolved_lines: int
    uncovered_lines: int

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.text.encode("utf-8")).hexdigest()

    def location(self, start: int = 0, end: int | None = None) -> dict[str, JsonValue]:
        stop = len(self.offsets) if end is None else end
        left = self.offsets[start] if 0 <= start < len(self.offsets) else 0
        right = self.offsets[stop - 1] + 1 if 0 < stop <= len(self.offsets) else left
        for unit in self.units:
            if unit.start <= left < unit.end:
                result = source_location(self.source, left, max(left, right))
                result.update({key: value for key, value in unit.location(self.source).items()
                               if key not in {"start", "end", "line", "column"}})
                return result
        return source_location(self.source, left, max(left, right))

    def coverage(self) -> dict[str, JsonValue]:
        return {
            "projection_version": PROJECTION_VERSION,
            "unresolved_lines": self.unresolved_lines,
            "uncovered_lines": self.uncovered_lines,
            "substantive_units": sum(unit.substantive for unit in self.units),
            "projected_characters": len(self.text),
            "units": [
                {"id": unit.id, "kind": unit.kind, "substantive": unit.substantive,
                 "location": unit.location(self.source)}
                for unit in self.units
            ],
            "exclusions": list(self.exclusions),
            "tables": list(self.tables),
        }


def source_location(source: str, start: int, end: int) -> dict[str, JsonValue]:
    line = source.count("\n", 0, start) + source.count("\r", 0, start) - source.count("\r\n", 0, start) + 1
    previous = max(source.rfind("\n", 0, start), source.rfind("\r", 0, start))
    return {"start": start, "end": end, "line": line, "column": start - previous}


def _children(tokens: list[Token]) -> list[Token]:
    result: list[Token] = []
    for token in tokens:
        result.append(token)
        if token.children:
            result.extend(_children(token.children))
    return result


def _row_cells(raw: str, source_start: int) -> list[tuple[str, tuple[int, ...], int]]:
    """Align the parser's cell strings; do not decide whether this is a table."""
    parts = escapedSplit(raw)
    offsets = tuple(source_start + index for index, char in enumerate(raw)
                    if not (char == "\\" and raw[index + 1:index + 2] == "|"))
    normalized = "".join(raw[offset - source_start] for offset in offsets)
    if normalized != "|".join(parts):
        raise ValueError("Markdown table splitter and source alignment disagree")
    cells: list[tuple[str, tuple[int, ...], int]] = []
    cursor = 0
    for index, part in enumerate(parts):
        if not (part == "" and index in {0, len(parts) - 1}):
            left = len(part) - len(part.lstrip())
            right = len(part.rstrip())
            position = offsets[cursor] if cursor < len(offsets) else source_start + len(raw)
            cells.append((part.strip(), offsets[cursor + left:cursor + right], position))
        cursor += len(part) + 1
    return cells


def project_markdown(source: str) -> MarkdownProjection:
    """Project every readable block/cell, recording omissions as explicit issues."""
    parser_fingerprint()
    rows: dict[int, str] = {}

    def record_table(state: StateBlock, start: int, end: int, silent: bool) -> bool:
        matched = table(state, start, end, silent)
        if matched and not silent:
            for line in range(start, state.line):
                rows[line] = getLine(state, line).strip()
        return matched

    parser = MarkdownIt("commonmark").enable("table")
    parser.block.ruler.at("table", record_table, {"alt": ["paragraph", "reference"]})
    env: dict[str, Any] = {}
    tokens = parser.parse(source.removeprefix("\ufeff"), env)
    bounds = _line_bounds(source)
    claimed: set[int] = set()
    issues: list[ProjectionIssue] = []
    exclusions: list[dict[str, JsonValue]] = []
    units: list[ProseUnit] = []
    tables: list[dict[str, JsonValue]] = []
    literals: list[str] = []
    links: list[str] = []
    containers: list[str] = []
    in_heading = False
    literal_heading = False
    leading_separator = bool(
        tokens and tokens[0].type == "hr" and tokens[0].map == [0, 1] and bounds
        and source[bounds[0][0]:bounds[0][1]].removeprefix("\ufeff").strip() == "---"
    )
    table_number: int | None = None
    row_number = 0
    cell_number = 0
    header_names: list[str] = []
    row_cells: list[tuple[str, tuple[int, ...], int]] = []
    table_shape: list[JsonValue] = []
    alignments: list[JsonValue] = []
    unresolved: set[int] = set()

    def span(token: Token) -> tuple[int, int]:
        if token.map is None or not bounds:
            return 0, 0
        return bounds[token.map[0]][0], bounds[token.map[1] - 1][1]

    def claim(token: Token) -> None:
        if token.map is not None:
            claimed.update(range(*token.map))

    def issue(code: str, message: str, token: Token) -> None:
        left, right = span(token)
        issues.append(ProjectionIssue(code, message, left, right))

    for token in tokens:
        if token.type == "table_open":
            claim(token)
            table_number = len(tables) + 1
            row_number = 0
            header_names = []
            table_shape = []
            alignments = []
            tables.append({"table": table_number, "location": source_location(source, *span(token))})
        elif token.type == "table_close":
            tables[-1].update({"headers": list(header_names), "row_widths": table_shape,
                               "alignments": alignments})
            table_number = None
        elif token.type == "tr_open" and table_number is not None:
            row_number += 1
            cell_number = 0
            row_cells = []
            if token.map is None or token.map[0] not in rows:
                issue("coverage.unresolved", "Cannot locate the parsed table row.", token)
                continue
            line = token.map[0]
            left, right = bounds[line]
            raw = rows[line]
            located = source.find(raw, left, right)
            if located < 0:
                unresolved.add(line)
                issue("coverage.unresolved", "Cannot map the table row to original source.", token)
            else:
                row_cells = _row_cells(raw, located)
            table_shape.append(len(row_cells))
        elif token.type == "tr_close" and table_number is not None:
            if len(row_cells) > cell_number:
                issue("coverage.table_overflow", "The parser discarded extra table cells; make row widths explicit.", token)
                # Closing tokens have no line map; use the discarded source span.
                discarded = row_cells[cell_number]
                issues[-1] = ProjectionIssue(issues[-1].code, issues[-1].message,
                                             discarded[2], discarded[1][-1] + 1 if discarded[1] else discarded[2])
        elif token.type == "th_open":
            alignments.append(cast(JsonValue, token.attrs))
        elif token.type in {"fence", "code_block", "hr", "html_block"}:
            claim(token)
            left, right = span(token)
            if token.type == "html_block":
                issue("coverage.html", "Raw HTML is unsupported by the authoring gate.", token)
            else:
                kind = "rule" if token.type == "hr" else "code"
                exclusions.append({"kind": kind, "location": source_location(source, left, right)})
                if kind == "code":
                    literals.append(source[left:right])
        elif token.type in {"blockquote_open", "list_item_open"}:
            containers.append("blockquote" if token.type == "blockquote_open" else "list_item")
        elif token.type in {"blockquote_close", "list_item_close"}:
            if containers:
                containers.pop()
        elif token.type == "heading_open":
            in_heading = True
            claim(token)
            if token.markup in {"-", "="} and token.map is not None:
                # Setext's block map includes the underline; its inline map
                # deliberately contains only the readable heading lines.
                left, right = bounds[token.map[1] - 1]
                exclusions.append({"kind": "heading_marker", "location": source_location(source, left, right)})
                literal_heading = (
                    leading_separator and token.level == 0 and token.map[0] == 1
                    and source[left:right].strip() == "---"
                )
        elif token.type == "heading_close":
            in_heading = False
            literal_heading = False
        elif token.type == "inline":
            claim(token)
            left, right = span(token)
            if table_number is not None:
                cell_number += 1
                if cell_number <= len(row_cells):
                    content, offsets, empty_position = row_cells[cell_number - 1]
                    if content != token.content:
                        issue("coverage.unresolved", "Parsed table cell does not match its source.", token)
                        if token.map:
                            unresolved.add(token.map[0])
                    left = offsets[0] if offsets else empty_position
                    right = offsets[-1] + 1 if offsets else left
                else:
                    content, offsets = "", ()
                kind = "table_header" if row_number == 1 else "table_cell"
                if row_number == 1:
                    header_names.append(content)
                identity = f"table-{table_number}-row-{row_number}-cell-{cell_number}"
                header = header_names[cell_number - 1] if cell_number <= len(header_names) else None
            else:
                spans, missed = _content_spans(source, token, bounds)
                if missed:
                    if token.map:
                        unresolved.update(range(*token.map))
                    issue("coverage.unresolved", "Cannot confidently locate all prose lines.", token)
                pieces: list[str] = []
                positions: list[int] = []
                for start, stop in spans:
                    if pieces:
                        pieces.append("\n")
                        positions.append(start)
                    pieces.append(source[start:stop])
                    positions.extend(range(start, stop))
                content, offsets = "".join(pieces), tuple(positions)
                kind = "heading" if in_heading else (containers[-1] if containers else "prose")
                identity = f"block-{len(units) + 1}"
                header = None
            children = _children(token.children or [])
            if any(child.type == "html_inline" for child in children):
                issue("coverage.html", "Inline HTML is unsupported by the authoring gate.", token)
            visible = "".join(child.content for child in children if child.type == "text")
            substantive = any(character.isalnum() for character in visible)
            unit_literals: list[str] = []
            code_spans = inline_code_spans(content)
            for start, stop in code_spans:
                if start < len(offsets) and stop <= len(offsets):
                    unit_literals.append(source[offsets[start]:offsets[stop - 1] + 1])
            if literal_heading:
                # A leading separator/Setext pair can carry host metadata.
                # Keep its spelling (including quotes/globs) immutable during
                # repair, while still scoring every readable heading line.
                unit_literals.append(source[left:right])
            # Native analysis consumes source spelling, not rendered HTML.
            # Refuse decoded entities rather than score their entity names and
            # silently omit the words the reader actually sees.
            if any(match.group(2) and unescapeAll(match.group()) != match.group()
                   and not any(start <= match.start() < stop for start, stop in code_spans)
                   for match in UNESCAPE_ALL_RE.finditer(content)):
                issue("coverage.inline_normalization", "Decoded character entities outside code cannot be scored reliably; use their literal text.", token)
            destinations = tuple(canonical_json({"kind": child.type, "attrs": child.attrs})
                                 for child in children if child.type in {"link_open", "image"})
            units.append(ProseUnit(identity, kind, content, offsets, left, right, substantive,
                                   table_number, row_number if table_number else None,
                                   cell_number if table_number else None, header, tuple(unit_literals), destinations))
            literals.extend(unit_literals)
            links.extend(destinations)
            if not substantive:
                exclusions.append({"kind": "nonprose_inline", "location": source_location(source, left, right)})

    for definition in env.get("references", {}).values():
        first, last = definition["map"]
        claimed.update(range(first, last))
        left, right = bounds[first][0], bounds[last - 1][1]
        exclusions.append({"kind": "link_definition", "location": source_location(source, left, right)})
        literals.append(source[left:right])

    uncovered = [line for line, (left, right) in enumerate(bounds)
                 if source[left:right].strip() and line not in claimed]
    for line in uncovered:
        left, right = bounds[line]
        issues.append(ProjectionIssue("coverage.uncovered", "Nonblank source line was not classified.", left, right))
    pieces = []
    positions = []
    for unit in units:
        if not unit.substantive:
            continue
        if pieces:
            pieces.append("\n\n")
            positions.extend([unit.start, unit.start])
        pieces.append(unit.text)
        positions.extend(unit.offsets)
    return MarkdownProjection(source, tuple(units), "".join(pieces), tuple(positions),
                              tuple(issues), tuple(exclusions), tuple(tables), tuple(literals),
                              tuple(links), len(unresolved), len(uncovered))
