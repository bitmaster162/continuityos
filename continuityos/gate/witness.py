"""External durable anti-rollback witness for product governance state.

This module intentionally uses only the Python standard library.  The witness
is outside both SQLite authority stores and is advanced only after a durable
ledger commit.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import secrets
import sqlite3
import stat
import threading
import uuid

from .ledger import GENESIS, HASH_SCHEME

SCHEMA = "continuityos.external-anti-rollback-witness.v1"
_KEYS = {
    "schema", "state_id", "event_count", "event_hash", "hash_scheme",
    "integrity_sha256",
}
_HEX = set("0123456789abcdef")
MAX_DOCUMENT_BYTES = 4096
_LOCKS_GUARD = threading.Lock()
_LOCKS = {}


class WitnessError(RuntimeError):
    """The external governance witness cannot authorize current state."""


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _is_hash(value):
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX


def _is_state_id(value):
    return _is_hash(value) and value != GENESIS


def _normalize_path(path):
    # Keep the caller-visible lexical path. Resolving links here would hide the
    # very symlink/junction substitution that R14 must reject.
    return os.path.normcase(os.path.abspath(os.path.expanduser(path)))


def _is_link_or_reparse(st):
    if stat.S_ISLNK(st.st_mode):
        return True
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attrs = getattr(st, "st_file_attributes", 0)
    return bool(marker and attrs & marker)


def _assert_no_reparse_chain(path):
    """Reject any existing symlink/reparse component in an authority path."""
    current = _normalize_path(path)
    chain = []
    while True:
        chain.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for component in reversed(chain):
        if not os.path.lexists(component):
            continue
        try:
            st = os.lstat(component)
        except OSError as exc:
            raise WitnessError(
                f"cannot inspect governance authority path component: {component}"
            ) from exc
        if _is_link_or_reparse(st):
            raise WitnessError(
                f"governance authority path uses symlink/reparse component: {component}"
            )


def _stat_identity(st):
    # st_dev + st_ino is the volume/file identity on supported CPython Windows
    # and POSIX builds. Include object type to reject file/directory swaps.
    return (int(st.st_dev), int(st.st_ino), stat.S_IFMT(st.st_mode))


def _path_identity(path):
    st = os.lstat(path)
    if _is_link_or_reparse(st):
        raise WitnessError(f"governance authority path is a symlink/reparse point: {path}")
    return _stat_identity(st)


def _open_nofollow(path, flags, mode=0o600):
    """Open a regular authority leaf and prove the path still names that fd."""
    _assert_no_reparse_chain(path)
    safe_flags = flags | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, safe_flags, mode)
    try:
        fd_identity = _stat_identity(os.fstat(fd))
        path_identity = _path_identity(path)
        if fd_identity != path_identity:
            raise WitnessError("governance authority path identity changed during open")
        return fd
    except Exception:
        os.close(fd)
        raise


def _read_nofollow(path, limit):
    fd = _open_nofollow(path, os.O_RDONLY)
    try:
        chunks = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(fd, remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _document(state_id, event_count, event_hash):
    body = {
        "schema": SCHEMA,
        "state_id": state_id,
        "event_count": event_count,
        "event_hash": event_hash,
        "hash_scheme": HASH_SCHEME,
    }
    return {**body, "integrity_sha256": hashlib.sha256(_canonical(body)).hexdigest()}


class _LockState:
    def __init__(self):
        self.lock = threading.RLock()
        self.local = threading.local()


def _lock_state(path):
    key = _normalize_path(path)
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, _LockState())


def _lock_fd(fd):
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_size_t),
                ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        lock = ctypes.WinDLL("kernel32", use_last_error=True).LockFileEx
        lock.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(OVERLAPPED),
        ]
        lock.restype = wintypes.BOOL
        overlapped = OVERLAPPED()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        if not lock(handle, 0x2, 0, 1, 0, ctypes.byref(overlapped)):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_EX)


def _unlock_fd(fd):
    if os.name == "nt":
        import ctypes
        import msvcrt
        from ctypes import wintypes

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_size_t),
                ("InternalHigh", ctypes.c_size_t),
                ("Offset", wintypes.DWORD),
                ("OffsetHigh", wintypes.DWORD),
                ("hEvent", wintypes.HANDLE),
            ]

        unlock = ctypes.WinDLL("kernel32", use_last_error=True).UnlockFileEx
        unlock.argtypes = [
            wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD,
            wintypes.DWORD, ctypes.POINTER(OVERLAPPED),
        ]
        unlock.restype = wintypes.BOOL
        overlapped = OVERLAPPED()
        handle = wintypes.HANDLE(msvcrt.get_osfhandle(fd))
        if not unlock(handle, 0, 1, 0, ctypes.byref(overlapped)):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        import fcntl
        fcntl.flock(fd, fcntl.LOCK_UN)


def _flush_directory(path):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    if os.name != "nt":
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        fd = os.open(directory, flags)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _atomic_replace(temp, path):
    if os.name != "nt":
        os.replace(temp, path)
        _flush_directory(path)
        return
    # MOVEFILE_WRITE_THROUGH supplies the Windows durability barrier while
    # MOVEFILE_REPLACE_EXISTING retains atomic replacement semantics.
    import ctypes
    from ctypes import wintypes
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    move = kernel32.MoveFileExW
    move.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    move.restype = wintypes.BOOL
    if not move(temp, path, 0x1 | 0x8):
        raise OSError(ctypes.get_last_error(), "durable witness replacement failed")


def durable_atomic_write(path, data):
    directory = os.path.dirname(os.path.abspath(path)) or "."
    _assert_no_reparse_chain(directory)
    os.makedirs(directory, exist_ok=True)
    _assert_no_reparse_chain(directory)
    _assert_no_reparse_chain(path)
    temp = os.path.join(directory, ".%s.%s.tmp" % (os.path.basename(path), uuid.uuid4().hex))
    fd = None
    try:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError("short witness write")
            view = view[written:]
        os.fsync(fd)
        os.close(fd)
        fd = None
        _assert_no_reparse_chain(path)
        _atomic_replace(temp, path)
        _assert_no_reparse_chain(path)
    finally:
        if fd is not None:
            os.close(fd)
        try:
            os.unlink(temp)
        except FileNotFoundError:
            pass


class WitnessAuthority:
    """One external witness bound to one ledger and one broker registry."""

    def __init__(self, path, ledger_path, registry_path):
        self.path = _normalize_path(path)
        self.ledger_path = _normalize_path(ledger_path)
        self.registry_path = _normalize_path(registry_path)
        self.lock_path = self.path + ".lock"
        if len({self.path, self.ledger_path, self.registry_path, self.lock_path}) != 4:
            raise WitnessError(
                "governance witness, ledger, registry, and lock paths must be distinct"
            )
        self._state = _lock_state(self.lock_path)
        self._identity_guard = threading.Lock()
        self._lock_identity = None
        # On POSIX keep the originally pinned lock inode referenced for the
        # lifetime of this authority. Otherwise unlink/recreate can recycle
        # the same inode number and defeat an identity tuple comparison.
        self._anchor_fd = None
        self._parent_identities = {}
        for authority_path in (
            self.path, self.ledger_path, self.registry_path, self.lock_path
        ):
            _assert_no_reparse_chain(authority_path)
            parent = _normalize_path(os.path.dirname(authority_path) or ".")
            if parent not in self._parent_identities:
                self._parent_identities[parent] = (
                    _path_identity(parent) if os.path.isdir(parent) else None
                )
        # Existing hard-link aliases are authority collisions even when their
        # lexical names differ. Missing fresh-bootstrap files are checked later.
        existing = {}
        for role, authority_path in (
            ("witness", self.path), ("ledger", self.ledger_path),
            ("registry", self.registry_path), ("lock", self.lock_path),
        ):
            if os.path.lexists(authority_path):
                identity = _path_identity(authority_path)
                prior = existing.get(identity)
                if prior is not None:
                    raise WitnessError(
                        f"governance authority files alias each other: {prior} and {role}"
                    )
                existing[identity] = role

        # The cross-process lock is itself authority. Create and pin its file
        # identity during construction, before any caller can treat this object
        # as a capability. This prevents a lock-path replacement between
        # construction and the first locked() call from silently becoming the
        # authoritative lock.
        witness_parent = _normalize_path(os.path.dirname(self.lock_path) or ".")
        _assert_no_reparse_chain(witness_parent)
        os.makedirs(witness_parent, exist_ok=True)
        _assert_no_reparse_chain(witness_parent)
        current_parent = _path_identity(witness_parent)
        expected_parent = self._parent_identities.get(witness_parent)
        if expected_parent is None:
            self._parent_identities[witness_parent] = current_parent
        elif current_parent != expected_parent:
            raise WitnessError(
                f"governance authority parent identity changed: {witness_parent}"
            )
        fd = _open_nofollow(self.lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
                os.fsync(fd)
            self._lock_identity = _stat_identity(os.fstat(fd))
            if _path_identity(self.lock_path) != self._lock_identity:
                raise WitnessError("witness lock path changed during construction")
            if os.name != "nt":
                self._anchor_fd = fd
                fd = None
        finally:
            if fd is not None:
                os.close(fd)
        self.bootstrap_recovery = False

    def _release_anchor(self):
        """Release the POSIX inode anchor during object finalization."""
        with self._identity_guard:
            fd = self._anchor_fd
            self._anchor_fd = None
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass

    def __del__(self):
        try:
            self._release_anchor()
        except Exception:
            pass

    def _validate_stable_paths(self, *, create_witness_parent=False):
        witness_parent = _normalize_path(os.path.dirname(self.path) or ".")
        if create_witness_parent:
            _assert_no_reparse_chain(witness_parent)
            os.makedirs(witness_parent, exist_ok=True)
        for authority_path in (
            self.path, self.ledger_path, self.registry_path, self.lock_path
        ):
            _assert_no_reparse_chain(authority_path)
        with self._identity_guard:
            for parent, expected in list(self._parent_identities.items()):
                if not os.path.isdir(parent):
                    if expected is not None:
                        raise WitnessError(
                            f"governance authority parent disappeared: {parent}"
                        )
                    continue
                current = _path_identity(parent)
                if expected is None:
                    self._parent_identities[parent] = current
                elif current != expected:
                    raise WitnessError(
                        f"governance authority parent identity changed: {parent}"
                    )
        if self._lock_identity is not None:
            if not os.path.lexists(self.lock_path):
                raise WitnessError("witness lock file disappeared")
            if _path_identity(self.lock_path) != self._lock_identity:
                raise WitnessError("witness lock file identity changed")

    @contextlib.contextmanager
    def locked(self):
        state = self._state
        with state.lock:
            # Reentrancy belongs to the shared path lock, not to a particular
            # WitnessAuthority object. Validate this authority on every entry
            # so a second object cannot inherit another object's validation.
            self._validate_stable_paths(create_witness_parent=True)
            depth = getattr(state.local, "depth", 0)
            if depth == 0:
                fd = _open_nofollow(
                    self.lock_path, os.O_RDWR | os.O_CREAT, 0o600
                )
                fd_identity = _stat_identity(os.fstat(fd))
                with self._identity_guard:
                    if self._lock_identity is None:
                        self._lock_identity = fd_identity
                    elif self._lock_identity != fd_identity:
                        os.close(fd)
                        raise WitnessError("witness lock file identity changed")
                if os.fstat(fd).st_size == 0:
                    os.write(fd, b"0")
                    os.fsync(fd)
                try:
                    _lock_fd(fd)
                    self._validate_stable_paths()
                    if _path_identity(self.lock_path) != fd_identity:
                        raise WitnessError(
                            "witness lock path changed after lock acquisition"
                        )
                except Exception:
                    try:
                        _unlock_fd(fd)
                    except Exception:
                        pass
                    os.close(fd)
                    raise
                state.local.fd = fd
            state.local.depth = depth + 1
            try:
                yield
            finally:
                state.local.depth -= 1
                if state.local.depth == 0:
                    fd = state.local.fd
                    try:
                        _unlock_fd(fd)
                    finally:
                        os.close(fd)
                        del state.local.fd

    def read(self):
        self._validate_stable_paths()
        try:
            raw = _read_nofollow(self.path, MAX_DOCUMENT_BYTES + 1)
        except FileNotFoundError as exc:
            raise WitnessError("external anti-rollback witness is missing") from exc
        self._validate_stable_paths()
        if len(raw) > MAX_DOCUMENT_BYTES:
            raise WitnessError("external anti-rollback witness exceeds maximum size")
        def strict_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate witness key: {key}")
                result[key] = value
            return result
        try:
            doc = json.loads(
                raw.decode("utf-8"), object_pairs_hook=strict_object
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
            raise WitnessError("external anti-rollback witness is corrupt") from exc
        if not isinstance(doc, dict) or set(doc) != _KEYS:
            raise WitnessError("external anti-rollback witness schema is not strict")
        if (
            doc["schema"] != SCHEMA
            or doc["hash_scheme"] != HASH_SCHEME
            or not _is_state_id(doc["state_id"])
            or type(doc["event_count"]) is not int
            or doc["event_count"] < 0
            or not _is_hash(doc["event_hash"])
            or not _is_hash(doc["integrity_sha256"])
        ):
            raise WitnessError("external anti-rollback witness fields are invalid")
        body = {key: doc[key] for key in (
            "schema", "state_id", "event_count", "event_hash", "hash_scheme"
        )}
        if hashlib.sha256(_canonical(body)).hexdigest() != doc["integrity_sha256"]:
            raise WitnessError("external anti-rollback witness integrity mismatch")
        if raw != _canonical(doc):
            raise WitnessError("external anti-rollback witness is not canonical JSON")
        if doc["event_count"] == 0 and doc["event_hash"] != GENESIS:
            raise WitnessError("empty witness frontier is not genesis")
        return doc

    @staticmethod
    def _empty_sqlite_fragment(path, expected_tables, state_id):
        if not os.path.exists(path):
            return True
        if os.path.getsize(path) == 0:
            return True
        try:
            con = sqlite3.connect(
                "file:" + path.replace("\\", "/") + "?mode=ro",
                uri=True, timeout=5,
            )
        except sqlite3.Error:
            return False
        try:
            tables = {row[0] for row in con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )}
            visible = {name for name in tables if not name.startswith("sqlite_")}
            if not visible <= set(expected_tables):
                return False
            for table in expected_tables - {"governance_metadata"}:
                if table in tables and con.execute(
                    f"SELECT COUNT(*) FROM {table}"
                ).fetchone()[0] != 0:
                    return False
            if "governance_metadata" in tables:
                rows = con.execute(
                    "SELECT singleton,state_id FROM governance_metadata"
                ).fetchall()
                if len(rows) > 1:
                    return False
                if rows and (rows[0][0] != 1 or rows[0][1] != state_id):
                    return False
            return True
        except sqlite3.Error:
            return False
        finally:
            con.close()

    def _safe_genesis_bootstrap_fragment(self, doc):
        if doc["event_count"] != 0 or doc["event_hash"] != GENESIS:
            return False
        return (
            self._empty_sqlite_fragment(
                self.ledger_path,
                {"events", "execution_attempts", "governance_metadata"},
                doc["state_id"],
            )
            and self._empty_sqlite_fragment(
                self.registry_path,
                {"broker_requests", "governance_metadata"},
                doc["state_id"],
            )
        )

    def bootstrap(self):
        """Bootstrap or recover only an externally anchored empty GENESIS state."""
        with self.locked():
            self._validate_stable_paths()
            witness_exists = os.path.exists(self.path)
            ledger_exists = os.path.exists(self.ledger_path)
            registry_exists = os.path.exists(self.registry_path)
            if not witness_exists and not ledger_exists and not registry_exists:
                doc = _document(secrets.token_hex(32), 0, GENESIS)
                durable_atomic_write(self.path, _canonical(doc))
                self._validate_stable_paths()
                self.bootstrap_recovery = True
                return doc
            if not witness_exists:
                raise WitnessError(
                    "external anti-rollback witness is missing for existing governance state"
                )
            doc = self.read()
            if ledger_exists and registry_exists:
                # Fully present states are validated by ledger/registry identity and
                # frontier checks. Empty pre-metadata fragments may finish bootstrap.
                self.bootstrap_recovery = self._safe_genesis_bootstrap_fragment(doc)
                return doc
            if self._safe_genesis_bootstrap_fragment(doc):
                self.bootstrap_recovery = True
                return doc
            raise WitnessError(
                "incomplete governance state is not a safe GENESIS bootstrap fragment"
            )

    def validate_ledger(self, ledger):
        doc = self.read()
        state_id = ledger.state_id()
        if state_id != doc["state_id"]:
            raise WitnessError("ledger state_id does not match external witness")
        verification = ledger.verify()
        if not verification.get("ok"):
            raise WitnessError("ledger hash chain verification failed")
        count = verification["verified"]
        if count < doc["event_count"]:
            raise WitnessError("ledger is shorter than witnessed frontier")
        if doc["event_count"]:
            row = ledger.con.execute(
                "SELECT hash FROM events ORDER BY id LIMIT 1 OFFSET ?",
                (doc["event_count"] - 1,),
            ).fetchone()
            if row is None or row[0] != doc["event_hash"]:
                raise WitnessError("ledger diverges from witnessed frontier")
        elif doc["event_hash"] != GENESIS:
            raise WitnessError("witness genesis frontier is invalid")
        frontier = ledger.frontier()
        if count == doc["event_count"] and frontier["event_hash"] != doc["event_hash"]:
            raise WitnessError("ledger frontier does not equal witness")
        return doc, frontier

    def reconcile_ledger(self, ledger):
        doc, frontier = self.validate_ledger(ledger)
        if frontier["event_count"] > doc["event_count"]:
            self.advance(ledger, expected_state_id=doc["state_id"])
        return self.read()

    def advance(self, ledger, expected_state_id=None):
        """Advance to a verified forward ledger frontier; caller holds lock."""
        doc, frontier = self.validate_ledger(ledger)
        if expected_state_id is not None and doc["state_id"] != expected_state_id:
            raise WitnessError("witness state_id changed")
        if frontier["event_count"] < doc["event_count"]:
            raise WitnessError("witness advance would roll back")
        if frontier["event_count"] == doc["event_count"]:
            return doc
        updated = _document(
            doc["state_id"], frontier["event_count"], frontier["event_hash"]
        )
        self._validate_stable_paths()
        durable_atomic_write(self.path, _canonical(updated))
        self._validate_stable_paths()
        return updated
