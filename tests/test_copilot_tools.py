from __future__ import annotations

import os
from pathlib import Path

import pytest

from lingity.copilot_tools import reconstruct


def test_native_create_matches_platform_bytes(tmp_path: Path) -> None:
    target = tmp_path / "A File.MD"
    changes = reconstruct("create", {"path": str(target), "file_text": "The server must retain the record.\n"}, str(tmp_path))
    assert len(changes) == 1
    assert changes[0].original is None
    assert changes[0].candidate == f"The server must retain the record.{os.linesep}".encode()
    assert not target.exists()


@pytest.mark.parametrize("newline", ["\r\n", "\n"])
def test_native_edit_preserves_existing_newlines(tmp_path: Path, newline: str) -> None:
    target = tmp_path / "spec.markdown"
    original = f"The server must retain the record.{newline}".encode()
    target.write_bytes(original)
    changes = reconstruct("functions.edit", {"path": str(target), "old_str": "record", "new_str": "message"}, str(tmp_path))
    assert changes[0].candidate == f"The server must retain the message.{newline}".encode()
    assert changes[0].original == target.read_bytes() == original


def test_duplicate_edit_is_rejected_without_mutation(tmp_path: Path) -> None:
    target = tmp_path / "spec.md"
    target.write_bytes(b"record record\n")
    with pytest.raises(ValueError, match="exactly one"):
        reconstruct("edit", {"path": str(target), "old_str": "record", "new_str": "message"}, str(tmp_path))
    assert target.read_bytes() == b"record record\n"


def test_patch_reconstructs_multiple_files_and_move(tmp_path: Path) -> None:
    source = tmp_path / "old.md"
    source.write_bytes(b"# Topic\n\nThe server must retain the record.\n")
    patch = """*** Begin Patch
*** Update File: old.md
*** Move to: new.md
@@
 # Topic
\x20
-The server must retain the record.
+The server must retain the message.
*** Add File: other.md
+The client must send the request.
*** End Patch
"""
    changes = reconstruct("apply_patch", patch, str(tmp_path))
    assert len(changes) == 2
    assert changes[0].candidate == b"# Topic\n\nThe server must retain the message.\n"
    assert changes[0].source_path == os.path.normcase(str(source))
    assert changes[0].path == os.path.normcase(str(tmp_path / "new.md"))
    assert changes[1].candidate == f"The client must send the request.{os.linesep}".encode()
    assert source.exists() and not (tmp_path / "new.md").exists()


@pytest.mark.parametrize("patch_body", [
    "@@\n-same\n+new",
    "@@ labelled context\n-same\n+new",
    "@@\n+new",
    "@@\n-not present\n+new",
])
def test_ambiguous_patch_refused(tmp_path: Path, patch_body: str) -> None:
    source = tmp_path / "old.md"
    source.write_bytes(b"same\nsame\n")
    with pytest.raises(ValueError):
        reconstruct("apply_patch", f"*** Begin Patch\n*** Update File: old.md\n{patch_body}\n*** End Patch\n", str(tmp_path))
    assert source.read_bytes() == b"same\nsame\n"


def test_overlapping_parallel_targets_refused(tmp_path: Path) -> None:
    call = {"recipient_name": "functions.create", "parameters": {"path": "same.md", "file_text": "A draft."}}
    with pytest.raises(ValueError, match="overlapping"):
        reconstruct("multi_tool_use.parallel", {"tool_uses": [call, call]}, str(tmp_path))
    assert not (tmp_path / "same.md").exists()


def test_non_markdown_and_unrelated_questions_untouched(tmp_path: Path) -> None:
    assert reconstruct("create", {"path": "code.py", "file_text": "print(1)"}, str(tmp_path)) == []
    assert reconstruct("ask_user", {"message": "Choose a database."}, str(tmp_path)) == []
    assert reconstruct("apply_patch", "*** Begin Patch\n*** Update File: a.py\n@@ complicated\n-x\n+y\n*** End Patch\n", str(tmp_path)) == []


def test_scope_cannot_be_escaped_through_move(tmp_path: Path) -> None:
    (tmp_path / "draft.md").write_bytes(b"A draft.\n")
    with pytest.raises(ValueError, match="out of scope"):
        reconstruct("apply_patch", "*** Begin Patch\n*** Update File: draft.md\n*** Move to: draft.txt\n@@\n A draft.\n*** End Patch\n", str(tmp_path))


def test_unicode_line_separator_is_not_a_patch_line_break(tmp_path: Path) -> None:
    (tmp_path / "draft.md").write_text("The server\u2028must retain the record.\n", encoding="utf-8", newline="\n")
    changes = reconstruct("apply_patch", "*** Begin Patch\n*** Update File: draft.md\n@@\n-The server\u2028must retain the record.\n+The server must retain the record.\n*** End Patch\n", str(tmp_path))
    assert changes[0].candidate == b"The server must retain the record.\n"
