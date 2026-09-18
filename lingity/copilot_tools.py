"""Exact candidate reconstruction for the supported Copilot file tools."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lingity.gate_state import canonical_path

MAX_DOCUMENT_BYTES = 262_144
MAX_CHANGES = 32


@dataclass(frozen=True)
class Change:
    path: str
    original: bytes | None
    candidate: bytes | None
    source_path: str | None = None


def is_markdown(path: str) -> bool:
    name = path.replace("\\", "/").rsplit("/", 1)[-1].split(":", 1)[0]
    return name.rstrip(" .").lower().endswith((".md", ".markdown"))


def native_name(name: str) -> str:
    return name.removeprefix("functions.")


def arguments(value: object) -> dict[str, Any]:
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("tool arguments must be an object")
    if not all(isinstance(key, str) for key in value):
        raise ValueError("tool argument keys must be strings")
    return value


def _string(args: dict[str, Any], name: str) -> str:
    value = args.get(name)
    if not isinstance(value, str):
        raise ValueError(f"file tool requires a string {name}")
    return value


def _read(path: str) -> bytes | None:
    try:
        with Path(path).open("rb") as stream:
            value = stream.read(MAX_DOCUMENT_BYTES + 1)
    except FileNotFoundError:
        return None
    if len(value) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"Markdown exceeds the gate's {MAX_DOCUMENT_BYTES // 1024} KiB file limit")
    return value


def _text(value: bytes) -> str:
    text = value.decode("utf-8")
    if "\x00" in text or "\r" in text.replace("\r\n", ""):
        raise ValueError("unsupported NUL or bare-CR Markdown content")
    if "\r\n" in text and "\n" in text.replace("\r\n", ""):
        raise ValueError("mixed newlines cannot be reconstructed exactly; use uniform newlines")
    return text


def _eol(original: bytes | None) -> str:
    if original is not None and b"\n" in original:
        return "\r\n" if b"\r\n" in original else "\n"
    return os.linesep


def _encode(text: str, original: bytes | None) -> bytes:
    _text(text.encode("utf-8"))
    rendered = text.replace("\r\n", "\n").replace("\n", _eol(original)).encode("utf-8")
    if len(rendered) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"Markdown exceeds the gate's {MAX_DOCUMENT_BYTES // 1024} KiB file limit")
    return rendered


def _path(raw: str, cwd: str) -> str:
    return canonical_path(raw, cwd=cwd)


def _file_change(name: str, args: dict[str, Any], cwd: str) -> list[Change]:
    raw = _string(args, "path")
    if not is_markdown(raw):
        return []
    path = _path(raw, cwd)
    original = _read(path)
    if name == "create":
        if original is not None:
            raise ValueError("create target already exists; use an exact edit instead")
        candidate = _encode(_string(args, "file_text"), None)
    else:
        if original is None:
            raise ValueError("edit target is missing; submit the complete draft with create")
        text = _text(original).replace("\r\n", "\n")
        old = _string(args, "old_str").replace("\r\n", "\n")
        new = _string(args, "new_str").replace("\r\n", "\n")
        if not old or text.count(old) != 1:
            raise ValueError("edit must have exactly one exact old_str match; provide more context")
        if args.get("replace_all"):
            raise ValueError("replace_all is not supported; use separate exact edits")
        candidate = _encode(text.replace(old, new, 1), original)
    return [Change(path, original, candidate)]


def _update(lines: list[str], original: bytes) -> bytes:
    old_text = _text(original).replace("\r\n", "\n")
    old = old_text.split("\n")
    if old and old[-1] == "":
        old.pop()
    output: list[str] = []
    cursor = 0
    index = 0
    if not lines:
        raise ValueError("patch updates and moves need at least one exact context hunk")
    while index < len(lines):
        if lines[index] != "@@":
            raise ValueError("use plain @@ and unique exact context; labelled/fuzzy hunks are unsupported")
        index += 1
        before: list[str] = []
        after: list[str] = []
        eof = False
        while index < len(lines) and not lines[index].startswith("@@"):
            line = lines[index]
            index += 1
            if line == "*** End of File":
                if index != len(lines):
                    raise ValueError("End of File must end the final hunk")
                eof = True
                break
            if not line or line[0] not in " +-":
                raise ValueError("each patch context line needs its exact prefix")
            if line[0] in " -":
                before.append(line[1:])
            if line[0] in " +":
                after.append(line[1:])
        if not before and old:
            raise ValueError("insertion needs exact existing context, not an empty hunk")
        matches = [
            pos for pos in range(cursor, len(old) - len(before) + 1)
            if old[pos:pos + len(before)] == before
            and (not eof or pos + len(before) == len(old))
        ]
        if len(matches) != 1:
            raise ValueError("patch context must match exactly once; fuzzy patches are not checked")
        position = matches[0]
        output.extend(old[cursor:position])
        output.extend(after)
        cursor = position + len(before)
    output.extend(old[cursor:])
    return _encode("\n".join(output) + "\n", original)


def _patch(value: object, cwd: str) -> list[Change]:
    if not isinstance(value, str):
        raise ValueError("apply_patch requires the native raw patch string")
    lines = value.replace("\r\n", "\n").split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    headers = ("*** Add File: ", "*** Update File: ", "*** Delete File: ", "*** Move to: ")
    targets = [line.removeprefix(prefix) for line in lines for prefix in headers if line.startswith(prefix)]
    if not any(is_markdown(target) for target in targets):
        return []
    if len(lines) < 2 or lines[0] != "*** Begin Patch" or lines[-1] != "*** End Patch":
        raise ValueError("unsupported patch envelope")
    changes: list[Change] = []
    index = 1
    while index < len(lines) - 1:
        header = lines[index]
        operation = next((prefix for prefix in headers[:3] if header.startswith(prefix)), None)
        if operation is None:
            raise ValueError("unsupported patch operation")
        raw = header[len(operation):]
        index += 1
        moved: str | None = None
        if index < len(lines) - 1 and lines[index].startswith(headers[3]):
            if operation != headers[1]:
                raise ValueError("only Update File supports Move to")
            moved = lines[index][len(headers[3]):]
            index += 1
        body: list[str] = []
        while index < len(lines) - 1 and not lines[index].startswith(headers[:3]):
            body.append(lines[index])
            index += 1
        if not is_markdown(raw) and not (moved and is_markdown(moved)):
            continue
        if moved is not None and not is_markdown(moved):
            raise ValueError("renaming Markdown out of scope is not a readability repair")
        path = _path(raw, cwd)
        original = _read(path)
        if operation == headers[0]:
            if original is not None or not body or any(not line.startswith("+") for line in body):
                raise ValueError("Add File needs a missing target and literal added lines")
            changes.append(Change(path, None, _encode("\n".join(line[1:] for line in body) + "\n", None)))
        elif operation == headers[2]:
            if body or original is None:
                raise ValueError("Delete File needs an existing target and no hunks")
            changes.append(Change(path, original, None))
        else:
            if original is None:
                raise ValueError("Update File target is missing")
            destination = _path(moved, cwd) if moved is not None else path
            if destination != path and _read(destination) is not None:
                raise ValueError("Move to must not overwrite another file")
            changes.append(Change(destination, original, _update(body, original), path if moved else None))
    return changes


def reconstruct(tool_name: str, tool_args: object, cwd: str) -> list[Change]:
    """Read, but never execute, an operation and return its exact Markdown writes."""
    name = native_name(tool_name)
    if name == "apply_patch":
        changes = _patch(tool_args, cwd)
    elif name in {"create", "edit"}:
        changes = _file_change(name, arguments(tool_args), cwd)
    elif name in {"multi_tool_use.parallel", "parallel"}:
        entries = arguments(tool_args).get("tool_uses")
        if not isinstance(entries, list) or len(entries) > MAX_CHANGES:
            raise ValueError("parallel requires a bounded tool_uses list")
        changes = []
        for entry in entries:
            call = arguments(entry)
            nested = _string(call, "recipient_name")
            if native_name(nested) in {"parallel", "multi_tool_use.parallel"}:
                raise ValueError("nested parallel wrappers are unsupported")
            changes.extend(reconstruct(nested, call.get("parameters"), cwd))
    elif name == "str_replace_editor":
        args = arguments(tool_args)
        if args.get("command") == "view":
            return []
        if isinstance(args.get("path"), str) and is_markdown(args["path"]):
            raise ValueError("use native create/edit or an exact apply_patch for Markdown writes")
        return []
    else:
        return []
    paths = [path for change in changes for path in (change.path, change.source_path) if path]
    if len(changes) > MAX_CHANGES or len(paths) != len(set(paths)):
        raise ValueError("use at most 32 distinct Markdown targets per call; overlapping writes are ambiguous")
    return changes
