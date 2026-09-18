"""Transactional authoring state; this module never writes an authored destination.

The caller supplies a trusted local state directory and an identity digest covering
the evaluator, policy, and runtime. Only genuine user-prompt events call
``begin_request``; session starts, continuations, and child binding cannot do so.
Approval is a state transition, not permission to execute a host tool. The host
must still use its normal permissions and verify the actual write afterward.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import ntpath
import os
from pathlib import Path
import re
import sqlite3
import stat
from typing import Iterator, Literal, Sequence, cast
import uuid

from .models import JsonValue


MAX_REPAIRS = 3
MAX_STOPS = 6
MAX_CONTENT_BYTES = 8 * 1024 * 1024
MAX_RESULT_BYTES = 1024 * 1024
MAX_SNAPSHOTS = 10000
MAX_ROOTS = 64
MAX_DELEGATIONS = 64
MAX_OPERATIONS = 64
MAX_OPERATION_PATHS = 1000
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_DEVICE = re.compile(
    r"(?:CON|PRN|AUX|NUL|CLOCK\$|CONIN\$|CONOUT\$|COM[0-9\u00b9\u00b2\u00b3]|LPT[0-9\u00b9\u00b2\u00b3])(?: *\.|$)",
    re.IGNORECASE,
)


class GateStateError(RuntimeError):
    """State cannot safely authorize the requested operation."""


class StateConflict(GateStateError):
    """The request, ownership, or expected destination is stale or ambiguous."""


class UnsafePath(StateConflict):
    """A path has an ambiguous identity or traverses a filesystem link."""


class AttemptLimit(StateConflict):
    """Three distinct repairs beyond the immutable first draft were exhausted."""


class StopLimit(StateConflict):
    """The shared request continuation bound was exhausted."""


def content_hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _digest(value: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise GateStateError("Expected a lowercase SHA-256 identity digest.")
    return value


def _identifier(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise StateConflict("Missing or invalid session/request identifier.")
    if any(ord(char) < 32 for char in value):
        raise StateConflict("Control characters in session/request identifier.")
    return value


def _event_timestamp(value: int | None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= 9223372036854775807:
        raise StateConflict("A positive actual hook event timestamp is required for the chosen revision.")
    return value


def _check_links(path: Path) -> None:
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or (
            getattr(info, "st_file_attributes", 0)
            & stat.FILE_ATTRIBUTE_REPARSE_POINT
        ):
            raise UnsafePath("Filesystem links and junctions are not supported.")
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise UnsafePath("Hard-linked files are not supported.")
        if not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
            raise UnsafePath("Only ordinary local files and directories are supported.")


def canonical_path(path: str | Path, cwd: str | Path | None = None) -> str:
    """Return a native absolute identity, rejecting Windows aliasing on all hosts.

    POSIX paths remain case-sensitive. Windows paths are case-normalized, but
    neither platform resolves symlinks: every existing ancestor is inspected.
    """
    raw = os.fspath(path)
    if not raw or "\x00" in raw or any(ord(char) < 32 for char in raw):
        raise UnsafePath("An ordinary nonempty filesystem path is required.")
    windows = raw.replace("/", "\\")
    if windows.startswith(("\\\\", "\\??\\")):
        raise UnsafePath("Network and device namespace paths are not supported.")
    drive, tail = ntpath.splitdrive(windows)
    if drive and (
        len(drive) != 2 or drive[1] != ":" or drive[0] not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    ):
        raise UnsafePath("Invalid drive prefix.")
    if drive and not tail.startswith("\\"):
        raise UnsafePath("Drive-relative paths are ambiguous.")
    if drive and tail.startswith("\\\\"):
        raise UnsafePath("Repeated root separators are ambiguous.")
    if os.name != "nt" and (drive or "\\" in raw):
        raise UnsafePath("Windows paths require a Windows host.")
    if os.name == "nt" and not drive and tail.startswith("\\"):
        raise UnsafePath("Root-relative paths require an explicit drive.")
    parts = tail.lstrip("\\").split("\\")
    if any(
        not part
        or part in {".", ".."}
        or part.endswith((" ", "."))
        or any(char in '<>:"|?*' for char in part)
        or "~" in part
        or _DEVICE.match(part)
        for part in parts
    ) and tail not in {"\\", ""}:
        raise UnsafePath("Ambiguous, reserved, or alternate-stream path component.")
    native = Path(raw)
    if not native.is_absolute():
        if cwd is None:
            raise UnsafePath("Relative paths require a known session directory.")
        native = Path(canonical_path(cwd)) / native
    normalized = os.path.normcase(os.path.abspath(native))
    _check_links(Path(normalized))
    return normalized


def _read_destination(path: str) -> bytes | None:
    canonical_path(path)
    try:
        with open(path, "rb") as handle:
            before = os.fstat(handle.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise UnsafePath("Destination is not an ordinary unlinked file.")
            content = handle.read(MAX_CONTENT_BYTES + 1)
            after = os.fstat(handle.fileno())
    except FileNotFoundError:
        return None
    if len(content) > MAX_CONTENT_BYTES:
        raise StateConflict("Document exceeds the state content limit.")
    canonical_path(path)
    current = os.stat(path, follow_symlinks=False)
    if (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    ) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) or (
        current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns
    ) != (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ):
        raise StateConflict("Destination changed while its bytes were being read.")
    return content


def _hash_optional(content: bytes | None) -> str | None:
    return None if content is None else content_hash(content)


@dataclass(frozen=True)
class Draft:
    document_id: int
    revision_id: int
    session_id: str
    epoch: int
    path: str
    baseline: bytes
    baseline_hash: str
    candidate_hash: str
    expected_hash: str | None
    status: str
    repairs: int


_REVISION_TABLE = """
CREATE TABLE IF NOT EXISTS revisions (
    id INTEGER PRIMARY KEY, document INTEGER NOT NULL REFERENCES documents(id),
    owner TEXT NOT NULL, epoch INTEGER NOT NULL, baseline TEXT NOT NULL,
    candidate TEXT NOT NULL, expected TEXT, status TEXT NOT NULL,
    move_source TEXT, move_expected TEXT, approved_identity TEXT
);
"""
_REVISION_COLUMNS = (
    "id,document,owner,epoch,baseline,candidate,expected,status,move_source,move_expected,approved_identity"
)
_AUTHORIZATION_TABLE = """
CREATE TABLE IF NOT EXISTS revision_authorizations (
    revision INTEGER NOT NULL REFERENCES revisions(id),
    document INTEGER NOT NULL REFERENCES documents(id), owner TEXT NOT NULL,
    epoch INTEGER NOT NULL, question_session TEXT NOT NULL REFERENCES sessions(id),
    question_token TEXT NOT NULL, answer_hash TEXT NOT NULL, event_id TEXT NOT NULL,
    event_time INTEGER NOT NULL, consumed_revision INTEGER REFERENCES revisions(id),
    PRIMARY KEY(revision, epoch), UNIQUE(question_session, question_token),
    FOREIGN KEY(question_session, question_token) REFERENCES decisions(session, token)
);
"""

_SCHEMA = f"""
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY, owner TEXT NOT NULL, cwd TEXT, epoch INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS requests (
    owner TEXT NOT NULL, event TEXT NOT NULL, epoch INTEGER NOT NULL,
    stops INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner, event), UNIQUE(owner, epoch)
);
CREATE TABLE IF NOT EXISTS main_sessions (
    session TEXT PRIMARY KEY REFERENCES sessions(id)
);
CREATE TABLE IF NOT EXISTS prompt_events (
    session TEXT NOT NULL REFERENCES sessions(id), event TEXT NOT NULL,
    digest TEXT NOT NULL, cwd TEXT NOT NULL, binding TEXT NOT NULL,
    epoch INTEGER NOT NULL, PRIMARY KEY(session, event)
);
CREATE TABLE IF NOT EXISTS delegations (
    parent TEXT NOT NULL REFERENCES sessions(id), token TEXT NOT NULL,
    owner TEXT NOT NULL, epoch INTEGER NOT NULL, digest TEXT NOT NULL,
    cwd TEXT NOT NULL, child TEXT, finished INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(parent, token)
);
CREATE TABLE IF NOT EXISTS continuations (
    owner TEXT NOT NULL, epoch INTEGER NOT NULL, stop INTEGER NOT NULL,
    session TEXT NOT NULL REFERENCES sessions(id), digest TEXT UNIQUE, event TEXT,
    PRIMARY KEY(owner, epoch, stop)
);
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY, path TEXT NOT NULL UNIQUE, current_revision INTEGER
);
CREATE TABLE IF NOT EXISTS aliases (
    path TEXT PRIMARY KEY, document INTEGER NOT NULL REFERENCES documents(id)
);
{_REVISION_TABLE}
CREATE TABLE IF NOT EXISTS attempts (
    revision INTEGER NOT NULL REFERENCES revisions(id), candidate TEXT NOT NULL,
    PRIMARY KEY(revision, candidate)
);
CREATE TABLE IF NOT EXISTS results (
    revision INTEGER NOT NULL REFERENCES revisions(id), candidate TEXT NOT NULL,
    identity TEXT NOT NULL, result TEXT NOT NULL,
    PRIMARY KEY(revision, candidate, identity)
);
CREATE TABLE IF NOT EXISTS roots (
    owner TEXT NOT NULL, path TEXT NOT NULL, PRIMARY KEY(owner, path)
);
CREATE TABLE IF NOT EXISTS snapshots (
    owner TEXT NOT NULL, path TEXT NOT NULL, digest TEXT, PRIMARY KEY(owner, path)
);
CREATE TABLE IF NOT EXISTS snapshot_epochs (
    owner TEXT PRIMARY KEY, epoch INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS decisions (
    session TEXT NOT NULL, token TEXT NOT NULL, owner TEXT NOT NULL,
    epoch INTEGER NOT NULL, revision INTEGER NOT NULL, baseline TEXT NOT NULL,
    candidate TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0,
    path TEXT, expected TEXT,
    PRIMARY KEY(session, token)
);
{_AUTHORIZATION_TABLE}
CREATE TABLE IF NOT EXISTS operations (
    session TEXT NOT NULL REFERENCES sessions(id), token TEXT NOT NULL,
    owner TEXT NOT NULL, epoch INTEGER NOT NULL, status TEXT NOT NULL,
    PRIMARY KEY(session, token)
);
CREATE TABLE IF NOT EXISTS operation_documents (
    session TEXT NOT NULL, token TEXT NOT NULL, position INTEGER NOT NULL,
    path TEXT NOT NULL, revision INTEGER NOT NULL REFERENCES revisions(id),
    candidate TEXT NOT NULL, identity TEXT NOT NULL,
    PRIMARY KEY(session, token, path),
    FOREIGN KEY(session, token) REFERENCES operations(session, token)
);
CREATE INDEX IF NOT EXISTS revisions_owner ON revisions(owner, status);
CREATE INDEX IF NOT EXISTS delegation_matches ON delegations(digest, cwd, finished);
"""


class GateState:
    """SQLite-serialized request ownership and immutable document artifacts.

    ``capture`` takes the exact bytes currently at the destination, or ``None``
    for absence. ``record_result`` counts distinct candidates, not calls or
    evaluator identities; results must include ``accepted``, ``candidate_sha256``,
    and ``baseline_sha256`` as emitted by the gate evaluator. ``approve`` rechecks
    the destination; ``verify_written`` checks the real post-tool bytes.
    ``failed`` never removes a draft.

    Roots and snapshots are bounded metadata for the caller's shell-write scan;
    this class never enumerates a task directory. A snapshot digest of ``None``
    records absence and does not resolve an owned pending document.

    Host adapters use ``bind_prompt`` rather than assuming a prompt proves a
    main session. Unknown prompts remain staged until ``start_session`` or an
    unambiguous pre-registered delegation establishes ownership. Prompt text is
    never stored: delegation and prompt correlation use only SHA-256 digests.
    Stop reasons must be registered with ``expect_continuation`` after reserving
    a ``next_stop`` count, or atomically via ``next_stop(session_id, prompt_hash)``.
    Their echo prompts never create a new request epoch.

    An inline wording answer authorizes only its document's next native first
    draft. It never changes the root request epoch or shared stop budget. The
    consuming capture must supply its actual pre-tool timestamp after the answer.
    """

    def __init__(self, root: str | Path, *, lock_timeout: float = 15.0) -> None:
        if isinstance(lock_timeout, bool) or not 0 < lock_timeout <= 15:
            raise GateStateError("State lock timeout must be positive and at most 15 seconds.")
        self.root = Path(canonical_path(root))
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        canonical_path(self.root)
        self.content = self.root / "content"
        self.content.mkdir(mode=0o700, exist_ok=True)
        canonical_path(self.content)
        database = self.root / "state.sqlite3"
        canonical_path(database)
        for suffix in ("-journal", "-wal", "-shm"):
            canonical_path(str(database) + suffix)
        self._db = sqlite3.connect(database, timeout=lock_timeout, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        # SQLite's referenced-table rebuild requires disabling FK enforcement
        # before BEGIN; the transaction checks all references before committing.
        self._db.execute("PRAGMA foreign_keys = OFF")
        self._db.execute("PRAGMA synchronous = FULL")
        try:
            with self._transaction():
                version = self._db.execute("PRAGMA user_version").fetchone()[0]
                if version not in (0, 1, 2, 3, 4, 5, 6):
                    raise GateStateError("Unsupported authoring-state schema version.")
                if version < 5 and self._db.execute(
                    "SELECT 1 FROM sqlite_master WHERE type='table' AND name='revisions'"
                ).fetchone() is not None:
                    self._db.execute(_REVISION_TABLE.replace("IF NOT EXISTS revisions", "revisions_v5"))
                    self._db.execute(
                        f"INSERT INTO revisions_v5({_REVISION_COLUMNS}) SELECT {_REVISION_COLUMNS} FROM revisions"
                    )
                    self._db.execute("DROP TABLE revisions")
                    self._db.execute("ALTER TABLE revisions_v5 RENAME TO revisions")
                if version == 5:
                    self._db.execute(
                        _AUTHORIZATION_TABLE.replace("IF NOT EXISTS revision_authorizations", "revision_authorizations_v6")
                    )
                    self._db.execute("INSERT INTO revision_authorizations_v6 SELECT * FROM revision_authorizations")
                    self._db.execute("DROP TABLE revision_authorizations")
                    self._db.execute("ALTER TABLE revision_authorizations_v6 RENAME TO revision_authorizations")
                for statement in _SCHEMA.split(";"):
                    if statement.strip():
                        self._db.execute(statement)
                decision_columns = {row["name"] for row in self._db.execute("PRAGMA table_info(decisions)")}
                for column in ("path", "expected"):
                    if column not in decision_columns:
                        self._db.execute(f"ALTER TABLE decisions ADD COLUMN {column} TEXT")
                if self._db.execute("PRAGMA foreign_key_check").fetchone() is not None:
                    raise GateStateError("Authoring-state foreign-key integrity check failed.")
                self._db.execute("PRAGMA user_version=6")
            self._db.execute("PRAGMA foreign_keys = ON")
        except (sqlite3.Error, GateStateError):
            self._db.close()
            raise

    def __enter__(self) -> GateState:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield
        except BaseException:
            self._db.rollback()
            raise
        else:
            self._db.commit()

    def _session(self, session_id: str, *, require_epoch: bool = True) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT owner, cwd, epoch, (SELECT epoch FROM sessions WHERE id=s.owner) AS owner_epoch "
            "FROM sessions s WHERE id=?", (_identifier(session_id),),
        ).fetchone()
        if row is None:
            raise StateConflict("Unknown session; a genuine request event is required.")
        if row["owner"] != session_id and row["epoch"] != row["owner_epoch"]:
            raise StateConflict("Child belongs to a previous user-request epoch.")
        if require_epoch and row["epoch"] == 0:
            raise StateConflict("Missing genuine user-request epoch.")
        return cast(sqlite3.Row, row)

    def start_session(self, session_id: str, cwd: str | Path, source: str = "new") -> None:
        session_id = _identifier(session_id)
        directory = canonical_path(cwd)
        if source not in {"new", "resume", "startup", "child"}:
            raise StateConflict("Unsupported session start source.")
        with self._transaction():
            self._db.execute(
                "INSERT OR IGNORE INTO sessions(id,owner,cwd) VALUES(?,?,?)",
                (session_id, session_id, directory),
            )
            self._db.execute("UPDATE sessions SET cwd=? WHERE id=?", (directory, session_id))
            session = self._session(session_id, require_epoch=False)
            if session["owner"] == session_id and source != "child":
                self._db.execute("INSERT OR IGNORE INTO main_sessions(session) VALUES(?)", (session_id,))
                staged = self._db.execute(
                    "SELECT * FROM prompt_events WHERE session=? AND binding='staged'", (session_id,)
                ).fetchone()
                if staged is not None:
                    if staged["cwd"] != directory:
                        raise StateConflict("Session start does not match the staged prompt directory.")
                    epoch = self._begin_request(session_id, staged["event"])
                    self._db.execute(
                        "UPDATE prompt_events SET binding='main',epoch=? WHERE session=? AND event=?",
                        (epoch, session_id, staged["event"]),
                    )
            self._register_root(session["owner"], directory)

    def bind_child(self, session_id: str, parent_session_id: str, cwd: str | Path) -> None:
        """Bind a host-proven child to its parent's request and continuation bound."""
        session_id = _identifier(session_id)
        directory = canonical_path(cwd)
        with self._transaction():
            self._bind_child(session_id, parent_session_id, directory)

    def _bind_child(self, session_id: str, parent_session_id: str, directory: str) -> None:
        parent = self._session(parent_session_id)
        current = self._db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
        main = self._db.execute("SELECT 1 FROM main_sessions WHERE session=?", (session_id,)).fetchone()
        if main is not None or (
            current is not None and not (
                (current["owner"] == session_id and current["epoch"] == 0)
                or (current["owner"] == parent["owner"] and current["epoch"] == parent["epoch"])
            )
        ):
            raise StateConflict("Child session already has a different request owner or epoch.")
        self._db.execute(
            "INSERT OR IGNORE INTO sessions(id,owner,cwd) VALUES(?,?,?)",
            (session_id, parent["owner"], directory),
        )
        self._db.execute(
            "UPDATE sessions SET owner=?,cwd=?,epoch=? WHERE id=?",
            (parent["owner"], directory, parent["epoch"], session_id),
        )
        self._register_root(parent["owner"], directory)

    def begin_request(self, session_id: str, event_id: str) -> int:
        """Begin an already-proven genuine request; hook adapters use bind_prompt."""
        session_id, event_id = _identifier(session_id), _identifier(event_id)
        with self._transaction():
            return self._begin_request(session_id, event_id)

    def _begin_request(self, session_id: str, event_id: str) -> int:
        self._db.execute(
            "INSERT OR IGNORE INTO sessions(id,owner) VALUES(?,?)", (session_id, session_id)
        )
        session = self._session(session_id, require_epoch=False)
        if session["owner"] != session_id:
            raise StateConflict("A child event cannot create a user-request epoch.")
        classified = self._db.execute(
            "SELECT binding,epoch FROM prompt_events WHERE session=? AND event=?", (session_id, event_id)
        ).fetchone()
        if classified is not None and classified["binding"] == "continuation":
            if classified["epoch"] != session["epoch"]:
                raise StateConflict("Stale continuation cannot reset the request epoch.")
            return cast(int, session["epoch"])
        if classified is not None and classified["binding"] == "staged" and self._db.execute(
            "SELECT 1 FROM main_sessions WHERE session=?", (session_id,)
        ).fetchone() is None:
            raise StateConflict("Staged prompt requires main session-start proof.")
        previous = self._db.execute(
            "SELECT epoch FROM requests WHERE owner=? AND event=?", (session_id, event_id)
        ).fetchone()
        if previous is not None:
            if previous["epoch"] != session["epoch"]:
                raise StateConflict("Stale user-request event cannot rewind the epoch.")
            return cast(int, previous["epoch"])
        latest = self._db.execute(
            "SELECT event FROM requests WHERE owner=? AND epoch=?", (session_id, session["epoch"])
        ).fetchone()
        if (
            latest is not None and event_id.isdecimal() and latest["event"].isdecimal()
            and int(event_id) <= int(latest["event"])
        ):
            raise StateConflict("Out-of-order user-request timestamp cannot reset the epoch.")
        epoch = cast(int, session["epoch"]) + 1
        self._db.execute(
            "INSERT INTO requests(owner,event,epoch) VALUES(?,?,?)", (session_id, event_id, epoch)
        )
        self._db.execute("UPDATE sessions SET epoch=? WHERE id=?", (epoch, session_id))
        return epoch

    def register_delegation(
        self, parent_session_id: str, token: str, prompt_hash: str, cwd: str | Path
    ) -> None:
        """Reserve a task operation before execution, using only prompt metadata.

        Tokens must identify an invocation, not just its arguments: include the
        parent pre-tool event ID when hashing an operation. A duplicate delivery
        is idempotent, but a completed token never opens another claim.
        """
        token, prompt_hash = _identifier(token), _digest(prompt_hash)
        directory = canonical_path(cwd)
        with self._transaction():
            parent = self._session(parent_session_id)
            existing = self._db.execute(
                "SELECT * FROM delegations WHERE parent=? AND token=?", (parent_session_id, token)
            ).fetchone()
            if existing is not None:
                if (
                    existing["owner"], existing["epoch"], existing["digest"], existing["cwd"]
                ) != (parent["owner"], parent["epoch"], prompt_hash, directory):
                    raise StateConflict("Delegation token was reused for a different operation.")
                return
            count = self._db.execute(
                "SELECT count(*) FROM delegations WHERE owner=? AND finished<>1", (parent["owner"],)
            ).fetchone()[0]
            if count >= MAX_DELEGATIONS:
                raise StateConflict("Outstanding delegation limit exceeded.")
            self._db.execute(
                "INSERT INTO delegations(parent,token,owner,epoch,digest,cwd) VALUES(?,?,?,?,?,?)",
                (parent_session_id, token, parent["owner"], parent["epoch"], prompt_hash, directory),
            )

    def bind_prompt(
        self, session_id: str, event_id: str, prompt_hash: str, cwd: str | Path,
        *, continuation_only: bool = False, host_continuation: bool = False,
    ) -> Literal["main", "staged", "continuation", "child"]:
        """Classify a prompt without confusing a task child's prompt with a user request."""
        session_id, event_id = _identifier(session_id), _identifier(event_id)
        prompt_hash, directory = _digest(prompt_hash), canonical_path(cwd)
        with self._transaction():
            recorded = self._db.execute(
                "SELECT * FROM prompt_events WHERE session=? AND event=?", (session_id, event_id)
            ).fetchone()
            if recorded is not None and (
                recorded["digest"] != prompt_hash or recorded["cwd"] != directory
            ):
                raise StateConflict("Prompt event was replayed with different correlation metadata.")
            existing = self._db.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            main = self._db.execute(
                "SELECT 1 FROM main_sessions WHERE session=?", (session_id,)
            ).fetchone()
            continuation = self._db.execute(
                "SELECT * FROM continuations WHERE digest=?", (prompt_hash,)
            ).fetchone()
            if continuation_only and continuation is None:
                raise StateConflict("An unregistered gate continuation cannot authorize a new revision.")
            binding: Literal["main", "staged", "continuation", "child"]
            if continuation is not None:
                if continuation["session"] != session_id:
                    raise StateConflict("Continuation belongs to a different session.")
                session = self._session(session_id)
                if (continuation["owner"], continuation["epoch"]) != (session["owner"], session["epoch"]):
                    raise StateConflict("Continuation belongs to a previous user-request epoch.")
                if session["cwd"] is not None and session["cwd"] != directory:
                    raise StateConflict("Continuation does not match the session directory.")
                if continuation["event"] is not None and continuation["event"] != event_id:
                    raise StateConflict("Continuation reason was already consumed; use a unique reason nonce.")
                self._db.execute(
                    "UPDATE continuations SET event=? WHERE digest=?", (event_id, prompt_hash)
                )
                binding, epoch = "continuation", cast(int, session["epoch"])
            elif host_continuation:
                session = self._session(session_id)
                if session["cwd"] != directory:
                    raise StateConflict("Host continuation does not match the session directory.")
                binding, epoch = "continuation", cast(int, session["epoch"])
            elif existing is not None and existing["owner"] != session_id:
                session = self._session(session_id)
                binding, epoch = "child", cast(int, session["epoch"])
            elif main is not None:
                binding, epoch = "main", self._begin_request(session_id, event_id)
            else:
                matches = self._db.execute(
                    "SELECT * FROM delegations WHERE digest=? AND cwd=? AND finished<>1 LIMIT 2",
                    (prompt_hash, directory),
                ).fetchall()
                if len(matches) > 1:
                    raise StateConflict("Ambiguous child prompt matches multiple outstanding delegations.")
                if matches:
                    match = matches[0]
                    if match["child"] is not None and match["child"] != session_id:
                        raise StateConflict("Delegation is already bound to a different child session.")
                    parent = self._session(match["parent"])
                    if parent["epoch"] != match["epoch"]:
                        raise StateConflict("Delegation belongs to a previous user-request epoch.")
                    self._bind_child(session_id, match["parent"], directory)
                    self._db.execute(
                        "UPDATE delegations SET child=?,finished=CASE WHEN finished=2 THEN 1 ELSE finished END "
                        "WHERE parent=? AND token=?",
                        (session_id, match["parent"], match["token"]),
                    )
                    binding, epoch = "child", cast(int, match["epoch"])
                else:
                    staged = self._db.execute(
                        "SELECT event FROM prompt_events WHERE session=? AND binding='staged'", (session_id,)
                    ).fetchone()
                    if staged is not None and staged["event"] != event_id:
                        raise StateConflict("Multiple unproven prompts cannot establish a request epoch.")
                    if existing is not None and existing["epoch"] != 0:
                        raise StateConflict("An existing request requires session-start proof before a new prompt.")
                    self._db.execute(
                        "INSERT OR IGNORE INTO sessions(id,owner,cwd) VALUES(?,?,?)",
                        (session_id, session_id, directory),
                    )
                    binding, epoch = "staged", 0
            self._db.execute(
                "INSERT INTO prompt_events(session,event,digest,cwd,binding,epoch) VALUES(?,?,?,?,?,?) "
                "ON CONFLICT(session,event) DO UPDATE SET binding=excluded.binding,epoch=excluded.epoch",
                (session_id, event_id, prompt_hash, directory, binding, epoch),
            )
            return binding

    def finish_delegation(
        self, parent_session_id: str, token: str, *, failed: bool = False
    ) -> None:
        """Close a claimed task, or retain an unclaimed successful background launch.

        A launch failure must pass ``failed=True`` to cancel an unclaimed task.
        Successful launches that return before their child's first prompt keep
        the claim until that prompt arrives; the child's binding then persists.
        """
        parent_session_id, token = _identifier(parent_session_id), _identifier(token)
        with self._transaction():
            cursor = self._db.execute(
                "UPDATE delegations SET finished=CASE "
                "WHEN ? OR finished=1 OR child IS NOT NULL THEN 1 ELSE 2 END "
                "WHERE parent=? AND token=?", (failed, parent_session_id, token)
            )
            if cursor.rowcount == 0:
                raise StateConflict("Unknown delegation cannot be completed.")

    def expect_continuation(self, session_id: str, prompt_hash: str) -> None:
        """Bind a reserved stop to the entire nonce-bearing reason before emitting it."""
        prompt_hash = _digest(prompt_hash)
        with self._transaction():
            self._expect_continuation(session_id, prompt_hash)

    def _expect_continuation(self, session_id: str, prompt_hash: str) -> None:
        session = self._session(session_id)
        existing = self._db.execute(
            "SELECT * FROM continuations WHERE digest=?", (prompt_hash,)
        ).fetchone()
        if existing is not None:
            if (
                existing["session"], existing["owner"], existing["epoch"], existing["event"]
            ) != (session_id, session["owner"], session["epoch"], None):
                raise StateConflict("Continuation reason was reused; include a new unpredictable nonce.")
            return
        reserved = self._db.execute(
            "SELECT stop FROM continuations WHERE owner=? AND epoch=? AND session=? "
            "AND digest IS NULL ORDER BY stop DESC LIMIT 1",
            (session["owner"], session["epoch"], session_id),
        ).fetchone()
        if reserved is None:
            raise StateConflict("A continuation reason requires a reserved next_stop count.")
        self._db.execute(
            "UPDATE continuations SET digest=? WHERE owner=? AND epoch=? AND stop=?",
            (prompt_hash, session["owner"], session["epoch"], reserved["stop"]),
        )

    def _path(self, session: sqlite3.Row, path: str | Path) -> str:
        return canonical_path(path, cast(str | None, session["cwd"]))

    def _store(self, content: bytes) -> str:
        if not isinstance(content, bytes) or len(content) > MAX_CONTENT_BYTES:
            raise GateStateError("Document must be bytes within the state content limit.")
        digest = content_hash(content)
        target = self.content / digest
        canonical_path(target)
        if target.exists():
            if self._load(digest) != content:
                raise GateStateError("Content-addressed artifact integrity failure.")
            return digest
        temporary = self.content / (".pending-" + uuid.uuid4().hex)
        try:
            descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.link(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        return digest

    def _load(self, digest: str) -> bytes:
        path = self.content / _digest(digest)
        value = _read_destination(str(path))
        if value is None or content_hash(value) != digest:
            raise GateStateError("Missing or corrupt content-addressed artifact.")
        return value

    def artifact_path(self, digest: str) -> Path:
        """Return an existing, integrity-checked artifact for baseline recovery."""
        digest = _digest(digest)
        with self._transaction():
            self._load(digest)
            return self.content / digest

    def _revision(self, session: sqlite3.Row, path: str, *, current_epoch: bool = True) -> sqlite3.Row:
        row = self._db.execute(
            "SELECT r.*, d.path FROM aliases a JOIN documents d ON d.id=a.document "
            "JOIN revisions r ON r.id=d.current_revision WHERE a.path=?", (path,),
        ).fetchone()
        if row is None:
            raise StateConflict("Document has no captured first draft.")
        if row["owner"] != session["owner"]:
            raise StateConflict("Document belongs to another session revision.")
        if current_epoch and row["epoch"] != session["epoch"]:
            raise StateConflict("Document belongs to a previous user-request epoch.")
        return cast(sqlite3.Row, row)

    def _authorization(self, session: sqlite3.Row, row: sqlite3.Row) -> sqlite3.Row | None:
        return cast(sqlite3.Row | None, self._db.execute(
            "SELECT * FROM revision_authorizations WHERE revision=? AND document=? AND owner=? "
            "AND epoch=? AND consumed_revision IS NULL",
            (row["id"], row["document"], session["owner"], session["epoch"]),
        ).fetchone())

    def _guard_decision(
        self, session: sqlite3.Row, row: sqlite3.Row, *, allow_authorization: bool = False
    ) -> sqlite3.Row | None:
        if self._db.execute(
            "SELECT 1 FROM decisions WHERE revision=? AND owner=? AND epoch=? AND resolved=0",
            (row["id"], session["owner"], session["epoch"]),
        ).fetchone() is not None:
            raise StateConflict("A human wording decision is still pending for this document.")
        authorization = self._authorization(session, row)
        if authorization is not None and not allow_authorization:
            raise StateConflict("A complete chosen first draft is required before this document can proceed.")
        return authorization

    def _draft(self, row: sqlite3.Row) -> Draft:
        repairs = self._db.execute(
            "SELECT count(*) FROM attempts WHERE revision=? AND candidate<>?",
            (row["id"], row["baseline"]),
        ).fetchone()[0]
        return Draft(
            document_id=row["document"], revision_id=row["id"], session_id=row["owner"], epoch=row["epoch"],
            path=row["path"], baseline=self._load(row["baseline"]),
            baseline_hash=row["baseline"], candidate_hash=row["candidate"],
            expected_hash=row["expected"], status=row["status"], repairs=repairs,
        )

    def _expected(self, row: sqlite3.Row) -> None:
        if _hash_optional(_read_destination(row["path"])) != row["expected"]:
            raise StateConflict("Destination differs from the expected prior bytes; do not overwrite it.")
        if row["move_source"] is not None:
            if _hash_optional(_read_destination(row["move_source"])) != row["move_expected"]:
                raise StateConflict("Rename source differs from its expected prior bytes.")

    def _attempt_allowed(self, row: sqlite3.Row, digest: str) -> None:
        if digest == row["baseline"]:
            return
        existing = self._db.execute(
            "SELECT 1 FROM attempts WHERE revision=? AND candidate=?", (row["id"], digest)
        ).fetchone()
        count = self._db.execute(
            "SELECT count(*) FROM attempts WHERE revision=? AND candidate<>?",
            (row["id"], row["baseline"]),
        ).fetchone()[0]
        if existing is None and count >= MAX_REPAIRS:
            raise AttemptLimit("Three distinct repairs beyond the first draft have been evaluated.")

    def capture(
        self, session_id: str, path: str | Path, candidate: bytes, original: bytes | None,
        *, event_time: int | None = None,
    ) -> Draft:
        if event_time is not None:
            _event_timestamp(event_time)
        with self._transaction():
            session = self._session(session_id)
            path = self._path(session, path)
            expected = _hash_optional(original)
            if _hash_optional(_read_destination(path)) != expected:
                raise StateConflict("Observed destination bytes are stale; do not overwrite it.")
            document = self._db.execute(
                "SELECT d.* FROM aliases a JOIN documents d ON d.id=a.document WHERE a.path=?",
                (path,),
            ).fetchone()
            if document is None:
                cursor = self._db.execute("INSERT INTO documents(path) VALUES(?)", (path,))
                document_id = cursor.lastrowid
                self._db.execute("INSERT INTO aliases(path,document) VALUES(?,?)", (path, document_id))
                current = None
            else:
                document_id = document["id"]
                if document["path"] != path:
                    raise StateConflict("An old path alias cannot create or reset a renamed document.")
                current = self._db.execute(
                    "SELECT r.*, d.path FROM revisions r JOIN documents d ON d.id=r.document "
                    "WHERE r.id=?", (document["current_revision"],),
                ).fetchone()
            if current is not None:
                authorization = self._guard_decision(session, current, allow_authorization=True)
                if current["owner"] != session["owner"] and current["status"] != "verified":
                    raise StateConflict("Another session owns an unresolved revision of this document.")
                if authorization is not None:
                    if session_id not in {authorization["owner"], authorization["question_session"]}:
                        raise StateConflict("Only the root or answering session may supply the chosen first draft.")
                    if _event_timestamp(event_time) <= authorization["event_time"]:
                        raise StateConflict("Chosen draft pre-tool event must occur after the wording answer.")
                    self._expected(current)
                    if current["status"] == "approved" or current["move_source"] is not None:
                        raise StateConflict("A write is in flight for the chosen revision.")
                    digest = self._store(candidate)
                    if original is not None:
                        self._store(original)
                    self._db.execute("UPDATE revisions SET status='superseded' WHERE id=?", (current["id"],))
                    chosen = self._new_revision(session, path, digest, expected, cast(int, document_id))
                    self._db.execute(
                        "UPDATE revision_authorizations SET consumed_revision=? WHERE revision=? AND owner=? AND epoch=?",
                        (chosen.revision_id, current["id"], session["owner"], session["epoch"]),
                    )
                    return chosen
                if current["owner"] == session["owner"] and current["epoch"] == session["epoch"]:
                    self._expected(current)
                    digest = content_hash(candidate)
                    self._attempt_allowed(current, digest)
                    if current["status"] == "approved" and digest != current["candidate"]:
                        raise StateConflict("An approved write is still pending verification.")
                    digest = self._store(candidate)
                    if digest != current["candidate"] or current["status"] == "verified":
                        self._db.execute(
                            "UPDATE revisions SET candidate=?,status='captured',approved_identity=NULL WHERE id=?",
                            (digest, current["id"]),
                        )
                    return self._draft(self._revision(session, path))
                if current["status"] == "approved":
                    raise StateConflict("A previous request still has an approved write in flight.")
                self._db.execute("UPDATE revisions SET status='superseded' WHERE id=?", (current["id"],))
            digest = self._store(candidate)
            if original is not None:
                self._store(original)
            return self._new_revision(session, path, digest, expected, cast(int, document_id))

    def _new_revision(
        self, session: sqlite3.Row, path: str, digest: str, expected: str | None,
        document_id: int | None = None,
    ) -> Draft:
        if document_id is None:
            document_id = cast(int, self._db.execute(
                "INSERT INTO documents(path) VALUES(?)", (path,)
            ).lastrowid)
            self._db.execute("INSERT INTO aliases(path,document) VALUES(?,?)", (path, document_id))
        cursor = self._db.execute(
            "INSERT INTO revisions(document,owner,epoch,baseline,candidate,expected,status) "
            "VALUES(?,?,?,?,?,?,'captured')",
            (document_id, session["owner"], session["epoch"], digest, digest, expected),
        )
        self._db.execute(
            "UPDATE documents SET current_revision=? WHERE id=?", (cursor.lastrowid, document_id)
        )
        return self._draft(self._revision(session, path))

    def observe(
        self, session_id: str, path: str | Path, current: bytes, before_hash: str | None
    ) -> Draft:
        """Reconcile a caller-detected shell write without approving or reverting it.

        The caller supplies its pre-shell digest. Existing snapshot and revision
        expectations must agree with it. Only the current owner can advance an
        existing document; a genuine newer request creates a separate revision.
        """
        if before_hash is not None:
            _digest(before_hash)
        with self._transaction():
            session = self._session(session_id)
            path = self._path(session, path)
            digest = content_hash(current)
            if _hash_optional(_read_destination(path)) != digest:
                raise StateConflict("Observed shell bytes no longer match the destination.")
            found = self._db.execute(
                "SELECT r.*,d.path FROM aliases a JOIN documents d ON d.id=a.document "
                "JOIN revisions r ON r.id=d.current_revision WHERE a.path=?", (path,),
            ).fetchone()
            row = cast(sqlite3.Row | None, found)
            authorization = None
            if row is not None:
                if row["owner"] != session["owner"]:
                    raise StateConflict("Observed shell write belongs to another session revision.")
                if row["path"] != path:
                    raise StateConflict("An old path alias cannot reset a renamed document.")
                authorization = self._guard_decision(session, row, allow_authorization=True)
                if row["status"] == "conflict" and row["epoch"] == session["epoch"]:
                    raise StateConflict("Preserve the conflicting file; a new user request must authorize a revision.")
                if row["status"] == "approved":
                    if row["epoch"] != session["epoch"] or row["candidate"] != digest:
                        raise StateConflict("Shell write conflicts with a previously approved operation.")
                    return self._verify_written(session, row, digest)
                if row["move_source"] is not None:
                    raise StateConflict("An unverified rename cannot be reconciled as a shell overwrite.")
                if authorization is not None and row["expected"] == digest:
                    self._expected(row)
                    self._db.execute(
                        "UPDATE revisions SET status='revision_requested',approved_identity=NULL WHERE id=?", (row["id"],)
                    )
                    return self._draft(self._revision(session, path, current_epoch=False))
                if (
                    authorization is None
                    and row["epoch"] == session["epoch"]
                    and row["expected"] == digest and row["candidate"] == digest
                ):
                    return self._draft(row)
            snapshot = self._db.execute(
                "SELECT digest FROM snapshots WHERE owner=? AND path=?", (session["owner"], path)
            ).fetchone()
            if snapshot is not None and snapshot["digest"] != before_hash:
                raise StateConflict("Pre-shell snapshot is stale; do not adopt the changed destination.")
            if row is not None and row["expected"] != before_hash:
                raise StateConflict("Pre-shell bytes differ from the tracked expected destination.")
            if authorization is not None:
                if snapshot is None:
                    raise StateConflict("A pre-shell snapshot record is required while the chosen draft is pending.")
                self._store(current)
                self._db.execute(
                    "UPDATE revisions SET expected=?,status='revision_requested',approved_identity=NULL WHERE id=?",
                    (digest, authorization["revision"]),
                )
                result = self._draft(self._revision(session, path, current_epoch=False))
            elif row is not None and row["epoch"] == session["epoch"]:
                self._attempt_allowed(row, digest)
                self._store(current)
                status = row["status"] if row["candidate"] == digest else "captured"
                self._db.execute(
                    "UPDATE revisions SET expected=?,candidate=?,status=?,approved_identity=NULL WHERE id=?",
                    (digest, digest, status, row["id"]),
                )
                result = self._draft(self._revision(session, path))
            else:
                self._store(current)
                document_id = None if row is None else cast(int, row["document"])
                if row is not None:
                    self._db.execute(
                        "UPDATE revisions SET status='superseded' WHERE id=?", (row["id"],)
                    )
                result = self._new_revision(session, path, digest, digest, document_id)
            self._update_snapshot(session["owner"], path, digest)
            return result

    def record_result(
        self, session_id: str, path: str | Path, candidate: bytes,
        result: dict[str, JsonValue], identity: str,
    ) -> Draft:
        identity = _digest(identity)
        encoded = json.dumps(result, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(encoded.encode("utf-8")) > MAX_RESULT_BYTES:
            raise GateStateError("Gate result exceeds the state result limit.")
        if not isinstance(result.get("accepted"), bool):
            raise GateStateError("Gate result must contain a boolean accepted field.")
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path))
            self._guard_decision(session, row)
            digest = content_hash(candidate)
            if digest != row["candidate"]:
                raise StateConflict("Evaluation belongs to a superseded candidate.")
            if result.get("candidate_sha256") != digest:
                raise StateConflict("Evaluation candidate identity does not match its bytes.")
            if "baseline_sha256" not in result or (
                result["baseline_sha256"] != row["baseline"]
                and not (result["baseline_sha256"] is None and digest == row["baseline"])
            ):
                raise StateConflict("Evaluation belongs to a different immutable baseline.")
            self._attempt_allowed(row, digest)
            cached = self._db.execute(
                "SELECT result FROM results WHERE revision=? AND candidate=? AND identity=?",
                (row["id"], digest, identity),
            ).fetchone()
            if cached is not None and cached["result"] != encoded:
                raise StateConflict("Identical evaluation identities produced different results.")
            self._db.execute(
                "INSERT OR IGNORE INTO attempts(revision,candidate) VALUES(?,?)", (row["id"], digest)
            )
            self._db.execute(
                "INSERT OR IGNORE INTO results(revision,candidate,identity,result) VALUES(?,?,?,?)",
                (row["id"], digest, identity, encoded),
            )
            if row["status"] not in {"approved", "verified"}:
                status = "compliant" if result["accepted"] else "repair_required"
                self._db.execute("UPDATE revisions SET status=? WHERE id=?", (status, row["id"]))
            return self._draft(self._revision(session, row["path"]))

    def cached(
        self, session_id: str, path: str | Path, candidate: bytes, identity: str
    ) -> dict[str, JsonValue] | None:
        identity = _digest(identity)
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path))
            self._guard_decision(session, row)
            result = self._db.execute(
                "SELECT result FROM results WHERE revision=? AND candidate=? AND identity=?",
                (row["id"], content_hash(candidate), identity),
            ).fetchone()
            if result is None:
                return None
            return cast(dict[str, JsonValue], json.loads(result["result"]))

    def approve(
        self, session_id: str, path: str | Path, candidate: bytes, identity: str
    ) -> Draft:
        identity = _digest(identity)
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path))
            self._guard_decision(session, row)
            digest = content_hash(candidate)
            if digest != row["candidate"]:
                raise StateConflict("Approval belongs to a superseded candidate.")
            result = self._db.execute(
                "SELECT result FROM results WHERE revision=? AND candidate=? AND identity=?",
                (row["id"], digest, identity),
            ).fetchone()
            if result is None or json.loads(result["result"]).get("accepted") is not True:
                raise StateConflict("No passing result exists for this candidate and identity.")
            self._expected(row)
            self._db.execute(
                "UPDATE revisions SET status='approved',approved_identity=? WHERE id=?", (identity, row["id"])
            )
            return self._draft(self._revision(session, row["path"]))

    def verify_written(
        self, session_id: str, path: str | Path, candidate: bytes | None = None
    ) -> Draft:
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path))
            return self._verify_written(session, row, _hash_optional(candidate))

    def _verify_written(
        self, session: sqlite3.Row, row: sqlite3.Row, candidate_hash: str | None
    ) -> Draft:
        self._guard_decision(session, row)
        if row["status"] not in {"approved", "verified"}:
            raise StateConflict("A write cannot complete without prior approval.")
        if candidate_hash is not None and candidate_hash != row["candidate"]:
            raise StateConflict("Completion belongs to a superseded candidate.")
        actual = _read_destination(row["path"])
        if actual is None or content_hash(actual) != row["candidate"]:
            raise StateConflict("Written bytes do not match the approved candidate.")
        if row["move_source"] is not None and _read_destination(row["move_source"]) is not None:
            raise StateConflict("The rename source still exists.")
        self._db.execute(
            "UPDATE revisions SET expected=candidate,status='verified',"
            "move_source=NULL,move_expected=NULL WHERE id=?", (row["id"],),
        )
        self._update_snapshot(session["owner"], row["path"], row["candidate"])
        return self._draft(self._revision(session, row["path"], current_epoch=False))

    def failed(self, session_id: str, path: str | Path) -> None:
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path), current_epoch=False)
            self._fail_revision(row)

    def invalidate(self, session_id: str, path: str | Path, candidate_hash: str) -> None:
        """Retain a rejected verification without treating it as a late tool failure."""
        candidate_hash = _digest(candidate_hash)
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path), current_epoch=False)
            if row["candidate"] != candidate_hash or row["status"] not in {"approved", "verified"}:
                raise StateConflict("Verification changed while its file was being checked.")
            self._db.execute(
                "UPDATE revisions SET status='conflict',approved_identity=NULL WHERE id=?", (row["id"],)
            )

    def stage_decision(
        self, session_id: str, token: str, path: str | Path, baseline_hash: str,
    ) -> None:
        token, baseline_hash = _digest(token), _digest(baseline_hash)
        with self._transaction():
            session = self._session(session_id)
            row = self._revision(session, self._path(session, path), current_epoch=False)
            if row["baseline"] != baseline_hash:
                raise StateConflict("Wording question refers to a different frozen draft.")
            if row["status"] == "approved" or row["move_source"] is not None:
                raise StateConflict("Finish the pending write or rename before asking a wording question.")
            if self._authorization(session, row) is not None:
                raise StateConflict("Supply the complete chosen first draft before asking another wording question.")
            self._expected(row)
            existing = self._db.execute(
                "SELECT * FROM decisions WHERE session=? AND token=?", (session_id, token)
            ).fetchone()
            if existing is not None:
                if existing["resolved"] or (
                    existing["owner"], existing["epoch"], existing["revision"], existing["baseline"],
                    existing["candidate"], existing["path"], existing["expected"]
                ) != (
                    session["owner"], session["epoch"], row["id"], baseline_hash,
                    row["candidate"], row["path"], row["expected"]
                ):
                    raise StateConflict("Wording question is stale or already answered.")
                return
            if self._db.execute(
                "SELECT 1 FROM decisions WHERE revision=? AND epoch=? AND resolved=0",
                (row["id"], session["epoch"]),
            ).fetchone() is not None:
                raise StateConflict("Gather related wording choices in the existing pending question.")
            self._db.execute(
                "INSERT INTO decisions(session,token,owner,epoch,revision,baseline,candidate,path,expected) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (session_id, token, session["owner"], session["epoch"], row["id"], baseline_hash,
                 row["candidate"], row["path"], row["expected"]),
            )

    def resolve_decision(
        self, session_id: str, token: str, answer_hash: str | None, event_id: str,
        *, event_time: int | None = None,
    ) -> bool:
        """Authorize only this question's document; consuming capture needs a later hook timestamp."""
        token, event_id = _digest(token), _identifier(event_id)
        if answer_hash is not None:
            _digest(answer_hash)
        with self._transaction():
            session = self._session(session_id)
            decision = self._db.execute(
                "SELECT * FROM decisions WHERE session=? AND token=?", (session_id, token)
            ).fetchone()
            if decision is None:
                if answer_hash is None:
                    return False
                raise StateConflict("No matching wording question was registered.")
            if decision["resolved"]:
                return False
            if answer_hash is None:
                self._db.execute(
                    "UPDATE decisions SET resolved=1 WHERE session=? AND token=?", (session_id, token)
                )
                return False
            timestamp = _event_timestamp(event_time)
            if (decision["owner"], decision["epoch"]) != (session["owner"], session["epoch"]):
                raise StateConflict("Wording answer belongs to a stale request.")
            row = self._db.execute(
                "SELECT r.*,d.path FROM revisions r JOIN documents d ON d.current_revision=r.id WHERE r.id=?",
                (decision["revision"],),
            ).fetchone()
            if row is None or (
                row["baseline"], row["candidate"], row["path"], row["expected"]
            ) != (
                decision["baseline"], decision["candidate"], decision["path"], decision["expected"]
            ):
                raise StateConflict("The document changed while the wording question was open.")
            if row["status"] == "approved" or row["move_source"] is not None:
                raise StateConflict("A write is in flight for the wording question.")
            self._expected(row)
            self._update_snapshot(session["owner"], row["path"], row["expected"])
            self._db.execute(
                "UPDATE decisions SET resolved=1 WHERE session=? AND token=?", (session_id, token)
            )
            self._db.execute(
                "UPDATE revisions SET status='revision_requested',approved_identity=NULL WHERE id=?", (row["id"],)
            )
            self._db.execute(
                "INSERT INTO revision_authorizations("
                "revision,document,owner,epoch,question_session,question_token,answer_hash,event_id,event_time) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (row["id"], row["document"], session["owner"], session["epoch"],
                 session_id, token, answer_hash, event_id, timestamp),
            )
            return True

    def _fail_revision(self, row: sqlite3.Row) -> None:
        if row["status"] == "verified":
            return
        if row["move_source"] is not None:
            if (
                _hash_optional(_read_destination(row["move_source"])) != row["move_expected"]
                or _read_destination(row["path"]) is not None
            ):
                raise StateConflict("Failed rename changed the filesystem; its reservation cannot be undone safely.")
            self._db.execute(
                "DELETE FROM aliases WHERE path=? AND document=?", (row["path"], row["document"])
            )
            self._db.execute(
                "UPDATE documents SET path=? WHERE id=?", (row["move_source"], row["document"])
            )
            self._db.execute(
                "UPDATE revisions SET expected=move_expected,move_source=NULL,move_expected=NULL WHERE id=?",
                (row["id"],),
            )
        self._db.execute(
            "UPDATE revisions SET status='failed',approved_identity=NULL WHERE id=?", (row["id"],)
        )

    def pending(self, session_id: str, limit: int = 1000) -> list[Draft]:
        return self._enumerate_drafts(session_id, limit, pending_only=True)

    def tracked(self, session_id: str, limit: int = 1000) -> list[Draft]:
        """Return current-request documents plus every unresolved older revision."""
        return self._enumerate_drafts(session_id, limit, pending_only=False)

    def draft(self, session_id: str, path: str | Path) -> Draft | None:
        with self._transaction():
            session = self._session(session_id)
            path = self._path(session, path)
            if self._db.execute("SELECT 1 FROM aliases WHERE path=?", (path,)).fetchone() is None:
                return None
            return self._draft(self._revision(session, path, current_epoch=False))

    def _enumerate_drafts(
        self, session_id: str, limit: int, *, pending_only: bool
    ) -> list[Draft]:
        if not 1 <= limit <= MAX_SNAPSHOTS:
            raise GateStateError("Invalid pending-document enumeration bound.")
        with self._transaction():
            session = self._session(session_id)
            rows = self._db.execute(
                "SELECT r.*,d.path FROM revisions r JOIN documents d ON d.current_revision=r.id "
                "WHERE r.owner=? AND (r.status<>'verified' OR (?=0 AND r.epoch=?)) "
                "ORDER BY d.path LIMIT ?",
                (session["owner"], pending_only, session["epoch"], limit + 1),
            ).fetchall()
            if len(rows) > limit:
                raise StateConflict("Pending-document enumeration limit exceeded; no records were omitted silently.")
            return [self._draft(row) for row in rows]

    def stage_operation(
        self, session_id: str, token: str, paths: Sequence[str | Path]
    ) -> None:
        """Persist the exact approved revisions for one tool-argument operation token."""
        token = _identifier(token)
        if isinstance(paths, (str, bytes)) or len(paths) > MAX_OPERATION_PATHS:
            raise StateConflict("Operation paths must be a bounded sequence of document paths.")
        with self._transaction():
            session = self._session(session_id)
            normalized = [self._path(session, path) for path in paths]
            if len(set(normalized)) != len(normalized):
                raise StateConflict("Operation lists the same canonical document more than once.")
            rows = [self._revision(session, path) for path in normalized]
            for path, row in zip(normalized, rows):
                if row["path"] != path or row["status"] != "approved":
                    raise StateConflict("An operation can stage only current approved document paths.")
                self._expected(row)
                other = self._db.execute(
                    "SELECT 1 FROM operation_documents d JOIN operations o "
                    "ON o.session=d.session AND o.token=d.token "
                    "WHERE d.revision=? AND o.status='pending' AND NOT(o.session=? AND o.token=?)",
                    (row["id"], session_id, token),
                ).fetchone()
                if other is not None:
                    raise StateConflict("Another pending operation owns this approved document.")
            existing = self._db.execute(
                "SELECT * FROM operations WHERE session=? AND token=?", (session_id, token)
            ).fetchone()
            if existing is not None and existing["status"] == "pending":
                previous = self._operation_rows(session_id, token)
                if [(row["path"], row["id"], row["candidate"]) for row in previous] != [
                    (row["path"], row["id"], row["candidate"]) for row in rows
                ]:
                    raise StateConflict("A pending operation token cannot be rebound to different writes.")
                return
            active = self._db.execute(
                "SELECT count(*) FROM operations WHERE owner=? AND status='pending'", (session["owner"],)
            ).fetchone()[0]
            if active >= MAX_OPERATIONS:
                raise StateConflict("Pending operation limit exceeded.")
            self._db.execute(
                "INSERT INTO operations(session,token,owner,epoch,status) VALUES(?,?,?,?,'pending') "
                "ON CONFLICT(session,token) DO UPDATE SET owner=excluded.owner,epoch=excluded.epoch,status='pending'",
                (session_id, token, session["owner"], session["epoch"]),
            )
            self._db.execute(
                "DELETE FROM operation_documents WHERE session=? AND token=?", (session_id, token)
            )
            self._db.executemany(
                "INSERT INTO operation_documents(session,token,position,path,revision,candidate,identity) "
                "VALUES(?,?,?,?,?,?,?)",
                [
                    (session_id, token, position, row["path"], row["id"], row["candidate"], row["approved_identity"])
                    for position, row in enumerate(rows)
                ],
            )

    def _operation_rows(self, session_id: str, token: str) -> list[sqlite3.Row]:
        session = self._session(session_id)
        operation = self._db.execute(
            "SELECT * FROM operations WHERE session=? AND token=?", (session_id, token)
        ).fetchone()
        if operation is None or operation["status"] != "pending":
            return []
        if (operation["owner"], operation["epoch"]) != (session["owner"], session["epoch"]):
            raise StateConflict("Operation belongs to a previous request revision.")
        entries = self._db.execute(
            "SELECT * FROM operation_documents WHERE session=? AND token=? ORDER BY position", (session_id, token)
        ).fetchall()
        rows: list[sqlite3.Row] = []
        for entry in entries:
            row = self._revision(session, entry["path"])
            if (
                row["id"], row["path"], row["candidate"], row["approved_identity"]
            ) != (entry["revision"], entry["path"], entry["candidate"], entry["identity"]):
                raise StateConflict("Operation's approved document revision has been superseded.")
            rows.append(row)
        return rows

    def operation_paths(self, session_id: str, token: str) -> list[str]:
        """Return only this pending operation's paths; unrelated tool events return no paths."""
        token = _identifier(token)
        with self._transaction():
            return [row["path"] for row in self._operation_rows(session_id, token)]

    def complete_operation(self, session_id: str, token: str) -> list[Draft]:
        """Verify exactly the recorded writes and close their operation in one transaction."""
        token = _identifier(token)
        with self._transaction():
            session = self._session(session_id)
            rows = self._operation_rows(session_id, token)
            drafts = [self._verify_written(session, row, row["candidate"]) for row in rows]
            self._db.execute(
                "UPDATE operations SET status='completed' WHERE session=? AND token=? AND status='pending'",
                (session_id, token),
            )
            return drafts

    def fail_operation(self, session_id: str, token: str) -> None:
        """Close one failed tool operation, retaining every baseline and pending document."""
        token = _identifier(token)
        with self._transaction():
            rows = self._operation_rows(session_id, token)
            for row in rows:
                self._fail_revision(row)
            self._db.execute(
                "UPDATE operations SET status='failed' WHERE session=? AND token=? AND status='pending'",
                (session_id, token),
            )

    def finish_operation(self, session_id: str, token: str) -> None:
        """Retire a manifest after individually handled post-tool results; never mark documents verified."""
        session_id, token = _identifier(session_id), _identifier(token)
        with self._transaction():
            self._db.execute(
                "UPDATE operations SET status='finished' WHERE session=? AND token=? AND status='pending'",
                (session_id, token),
            )

    def move(self, session_id: str, source: str | Path, destination: str | Path) -> Draft:
        """Register a supported rename before its tool runs; never perform it."""
        with self._transaction():
            session = self._session(session_id)
            source, destination = self._path(session, source), self._path(session, destination)
            row = self._revision(session, source)
            self._guard_decision(session, row)
            if destination == row["path"]:
                return self._draft(row)
            if source != row["path"]:
                raise StateConflict("An old alias cannot initiate another rename.")
            if row["status"] == "approved" or row["move_source"] is not None:
                raise StateConflict("A write or rename is already pending.")
            self._expected(row)
            if self._db.execute("SELECT 1 FROM aliases WHERE path=?", (destination,)).fetchone() is not None:
                raise StateConflict("Rename destination already identifies a tracked document.")
            if _read_destination(destination) is not None:
                raise StateConflict("Rename destination already exists; do not overwrite it.")
            self._db.execute(
                "INSERT INTO aliases(path,document) VALUES(?,?)", (destination, row["document"])
            )
            self._db.execute("UPDATE documents SET path=? WHERE id=?", (destination, row["document"]))
            self._db.execute(
                "UPDATE revisions SET move_source=?,move_expected=expected,expected=NULL,"
                "status='captured',approved_identity=NULL WHERE id=?", (source, row["id"]),
            )
            return self._draft(self._revision(session, destination))

    def _register_root(self, owner: str, path: str) -> None:
        if self._db.execute("SELECT 1 FROM roots WHERE owner=? AND path=?", (owner, path)).fetchone():
            return
        if self._db.execute("SELECT count(*) FROM roots WHERE owner=?", (owner,)).fetchone()[0] >= MAX_ROOTS:
            raise StateConflict("Known-root limit exceeded.")
        self._db.execute("INSERT INTO roots(owner,path) VALUES(?,?)", (owner, path))

    def register_root(self, session_id: str, path: str | Path) -> None:
        with self._transaction():
            session = self._session(session_id, require_epoch=False)
            self._register_root(session["owner"], self._path(session, path))

    def session_roots(self, session_id: str) -> list[str]:
        with self._transaction():
            session = self._session(session_id, require_epoch=False)
            return [
                row["path"] for row in self._db.execute(
                    "SELECT path FROM roots WHERE owner=? ORDER BY path", (session["owner"],)
                )
            ]

    def _update_snapshot(self, owner: str, path: str, digest: str | None) -> None:
        existing = self._db.execute(
            "SELECT 1 FROM snapshots WHERE owner=? AND path=?", (owner, path)
        ).fetchone()
        if existing is None and self._db.execute(
            "SELECT count(*) FROM snapshots WHERE owner=?", (owner,)
        ).fetchone()[0] >= MAX_SNAPSHOTS:
            raise StateConflict("Filesystem snapshot record limit exceeded.")
        self._db.execute(
            "INSERT INTO snapshots(owner,path,digest) VALUES(?,?,?) "
            "ON CONFLICT(owner,path) DO UPDATE SET digest=excluded.digest", (owner, path, digest)
        )

    def update_snapshot(self, session_id: str, path: str | Path, digest: str | None) -> None:
        if digest is not None:
            _digest(digest)
        with self._transaction():
            session = self._session(session_id, require_epoch=False)
            self._update_snapshot(session["owner"], self._path(session, path), digest)

    def snapshots(self, session_id: str, limit: int = MAX_SNAPSHOTS) -> dict[str, str | None]:
        if not 1 <= limit <= MAX_SNAPSHOTS:
            raise GateStateError("Invalid filesystem snapshot enumeration bound.")
        with self._transaction():
            session = self._session(session_id, require_epoch=False)
            rows = self._db.execute(
                "SELECT path,digest FROM snapshots WHERE owner=? ORDER BY path LIMIT ?",
                (session["owner"], limit + 1),
            ).fetchall()
            if len(rows) > limit:
                raise StateConflict("Filesystem snapshot enumeration limit exceeded.")
            return {row["path"]: row["digest"] for row in rows}

    def snapshots_ready(self, session_id: str) -> bool:
        with self._transaction():
            session = self._session(session_id)
            row = self._db.execute(
                "SELECT epoch FROM snapshot_epochs WHERE owner=?", (session["owner"],)
            ).fetchone()
            return row is not None and row["epoch"] == session["epoch"]

    def mark_snapshots_ready(self, session_id: str) -> None:
        with self._transaction():
            session = self._session(session_id)
            self._db.execute(
                "INSERT INTO snapshot_epochs(owner,epoch) VALUES(?,?) "
                "ON CONFLICT(owner) DO UPDATE SET epoch=excluded.epoch",
                (session["owner"], session["epoch"]),
            )

    def next_stop(self, session_id: str, prompt_hash: str | None = None) -> int:
        """Reserve one shared continuation and optionally register its reason atomically."""
        if prompt_hash is not None:
            _digest(prompt_hash)
        with self._transaction():
            session = self._session(session_id)
            count = self._db.execute(
                "SELECT stops FROM requests WHERE owner=? AND epoch=?",
                (session["owner"], session["epoch"]),
            ).fetchone()[0]
            if count >= MAX_STOPS:
                raise StopLimit("Six shared stop continuations have been exhausted.")
            self._db.execute(
                "UPDATE requests SET stops=stops+1 WHERE owner=? AND epoch=?",
                (session["owner"], session["epoch"]),
            )
            self._db.execute(
                "INSERT INTO continuations(owner,epoch,stop,session) VALUES(?,?,?,?)",
                (session["owner"], session["epoch"], count + 1, session_id),
            )
            if prompt_hash is not None:
                self._expect_continuation(session_id, prompt_hash)
            return cast(int, count) + 1
