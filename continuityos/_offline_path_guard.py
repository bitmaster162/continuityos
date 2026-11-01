"""Fail-closed local-file boundary for offline evidence only (no writes)."""
from __future__ import annotations

import os
import stat
from pathlib import Path

_REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


def _snapshot(path: Path) -> os.stat_result:
    if not path.is_absolute():
        raise ValueError("OFFLINE_PATH_UNSAFE")
    absolute = Path(os.path.abspath(path))
    for component in (absolute, *absolute.parents):
        info = component.lstat()
        if stat.S_ISLNK(info.st_mode) or (getattr(info, "st_file_attributes", 0) & _REPARSE):
            raise ValueError("OFFLINE_PATH_UNSAFE")
    if os.path.normcase(os.path.realpath(absolute)) != os.path.normcase(str(absolute)):
        raise ValueError("OFFLINE_PATH_UNSAFE")
    return absolute.stat()


def require_plain_dir(path: Path) -> None:
    try:
        if not stat.S_ISDIR(_snapshot(path).st_mode):
            raise ValueError("OFFLINE_DIRECTORY_UNSAFE")
    except (OSError, ValueError):
        raise ValueError("OFFLINE_DIRECTORY_UNSAFE") from None


def _identity(left: os.stat_result, right: os.stat_result) -> bool:
    return (left.st_dev == right.st_dev and left.st_ino != 0
            and left.st_ino == right.st_ino and left.st_size == right.st_size
            and left.st_mtime_ns == right.st_mtime_ns)


def read_bounded_file(path: Path, limit: int) -> bytes:
    """Read only a plain, stable file; validate the same opened handle."""
    try:
        before = _snapshot(path)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("OFFLINE_PATH_UNSAFE")
        if before.st_size > limit:
            raise ValueError("OFFLINE_FILE_TOO_LARGE")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not _identity(before, opened):
                raise ValueError("OFFLINE_PATH_UNSAFE")
            raw = handle.read(limit + 1)
            after = _snapshot(path)
            if not _identity(opened, after):
                raise ValueError("OFFLINE_PATH_UNSAFE")
        if len(raw) > limit:
            raise ValueError("OFFLINE_FILE_TOO_LARGE")
        return raw
    except OSError:
        raise ValueError("OFFLINE_PATH_UNSAFE") from None
