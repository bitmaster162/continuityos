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


# Windows opens *every* ancestor as a retained, read-share-only handle.
# An open directory handle without SHARE_WRITE/SHARE_DELETE prevents an
# ordinary rename/reparse replacement while descendants are opened.
# Final-path and reparse checks apply to the handle itself, not prior lstat.
if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes
    from contextlib import contextmanager

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _kernel32.CreateFileW.argtypes = (
        wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
        wintypes.LPVOID, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE)
    _kernel32.CreateFileW.restype = wintypes.HANDLE
    _kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    _kernel32.CloseHandle.restype = wintypes.BOOL
    _kernel32.GetFinalPathNameByHandleW.argtypes = (
        wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD)
    _kernel32.GetFinalPathNameByHandleW.restype = wintypes.DWORD

    class _WinFileInfo(ctypes.Structure):
        _fields_ = [
            ("attributes", wintypes.DWORD),
            ("creation_low", wintypes.DWORD), ("creation_high", wintypes.DWORD),
            ("access_low", wintypes.DWORD), ("access_high", wintypes.DWORD),
            ("write_low", wintypes.DWORD), ("write_high", wintypes.DWORD),
            ("volume_serial", wintypes.DWORD),
            ("size_high", wintypes.DWORD), ("size_low", wintypes.DWORD),
            ("links", wintypes.DWORD),
            ("file_index_high", wintypes.DWORD), ("file_index_low", wintypes.DWORD),
        ]
    _kernel32.GetFileInformationByHandle.argtypes = (
        wintypes.HANDLE, ctypes.POINTER(_WinFileInfo))
    _kernel32.GetFileInformationByHandle.restype = wintypes.BOOL

    # NtCreateFile with OBJECT_ATTRIBUTES.RootDirectory: resolve each
    # *single* child name relative to the previously verified open handle,
    # not via a potentially substituted absolute parent path.
    _ntdll = ctypes.WinDLL("ntdll")
    class _UnicodeString(ctypes.Structure):
        _fields_ = [("Length", wintypes.USHORT),
                    ("MaximumLength", wintypes.USHORT),
                    ("Buffer", wintypes.LPWSTR)]
    class _ObjectAttributes(ctypes.Structure):
        _fields_ = [("Length", wintypes.ULONG),
                    ("RootDirectory", wintypes.HANDLE),
                    ("ObjectName", ctypes.POINTER(_UnicodeString)),
                    ("Attributes", wintypes.ULONG),
                    ("SecurityDescriptor", wintypes.LPVOID),
                    ("SecurityQualityOfService", wintypes.LPVOID)]
    class _IoStatusBlock(ctypes.Structure):
        _fields_ = [("Status", ctypes.c_long), ("Information", ctypes.c_void_p)]
    _ntdll.NtCreateFile.argtypes = (
        ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
        ctypes.POINTER(_ObjectAttributes), ctypes.POINTER(_IoStatusBlock),
        ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
        wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD)
    _ntdll.NtCreateFile.restype = ctypes.c_long

    def _win_open_relative(parent, name: str, *, directory: bool):
        if (not name or name in (".", "..") or name.endswith((".", " "))
                or any(c in name for c in "\\/:")):
            raise ValueError("OFFLINE_PATH_UNSAFE")
        text_buf = ctypes.create_unicode_buffer(name)
        obj_name = _UnicodeString(len(name) * 2, (len(name) + 1) * 2,
                                  ctypes.cast(text_buf, wintypes.LPWSTR))
        object_attributes = _ObjectAttributes(
            ctypes.sizeof(_ObjectAttributes), parent,
            ctypes.pointer(obj_name), 0x40 | 0x1000, None, None)
        iosb = _IoStatusBlock()
        handle = wintypes.HANDLE()
        options = (0x00200000 | 0x20
                   | (0x01 | 0x4000 if directory else 0x40))
        # Match CM-R9: requested directory LIST/TRAVERSE enables Windows
        # sharing enforcement; READ_ATTRIBUTES alone does not pin renames.
        access = 0x80 | 0x100000 | (0x01 | 0x20 if directory else 0x01)
        status = _ntdll.NtCreateFile(
            ctypes.byref(handle), access, ctypes.byref(object_attributes),
            ctypes.byref(iosb), None, 0, 0x01, 1, options, None, 0)
        if status < 0 or not handle.value:
            raise ValueError("OFFLINE_PATH_UNSAFE")
        return handle
    _INVALID_HANDLE = ctypes.c_void_p(-1).value
    _WIN_FLAG_OPEN_REPARSE = 0x00200000
    _WIN_FLAG_DIRECTORY = 0x02000000
    _WIN_ACCESS_ATTR = 0x80
    _WIN_ACCESS_READ = 0x01

    def _win_handle_path(handle) -> str:
        buff = ctypes.create_unicode_buffer(32768)
        count = _kernel32.GetFinalPathNameByHandleW(handle, buff, len(buff), 0)
        if not count or count >= len(buff):
            raise ValueError("OFFLINE_PATH_UNSAFE")
        observed = buff.value
        if not observed.startswith("\\\\?\\"):
            raise ValueError("OFFLINE_PATH_UNSAFE")
        return observed[4:]

    def _win_open_handle(path: str, *, directory: bool):
        flags = _WIN_FLAG_OPEN_REPARSE | (_WIN_FLAG_DIRECTORY if directory else 0)
        access = (_WIN_ACCESS_ATTR | 0x100000 |
                  (0x01 | 0x20 if directory else _WIN_ACCESS_READ))
        handle = _kernel32.CreateFileW(path, access, 0x01, None, 3, flags, None)
        if ctypes.c_void_p(handle).value == _INVALID_HANDLE or not handle:
            raise ValueError("OFFLINE_PATH_UNSAFE")
        return handle

    @contextmanager
    def _win_anchored(path: Path, *, directory: bool):
        handles = []
        try:
            if not path.is_absolute():
                raise ValueError("OFFLINE_PATH_UNSAFE")
            original = str(path)
            # Reject alternate streams, UNC/device paths and dot traversal.
            drive, tail = os.path.splitdrive(original)
            if (len(drive) != 2 or drive[1] != ":"
                    or not drive[0].isalpha()
                    or not tail.startswith("\\")
                    or any(part in (".", "..") or part.endswith((".", " "))
                           or ":" in part
                           for part in tail.split("\\") if part)):
                raise ValueError("OFFLINE_PATH_UNSAFE")
            parts = [part for part in tail.split("\\") if part]
            current = drive + "\\"
            all_paths = [current]
            for part in parts:
                current = os.path.join(current, part)
                all_paths.append(current)
            for i, candidate in enumerate(all_paths):
                is_dir = i < len(all_paths) - 1 or directory
                handle = (_win_open_handle(candidate, directory=True)
                          if i == 0 else
                          _win_open_relative(handles[-1], parts[i-1], directory=is_dir))
                handles.append(handle)
                info = _WinFileInfo()
                if not _kernel32.GetFileInformationByHandle(handle, ctypes.byref(info)):
                    raise ValueError("OFFLINE_PATH_UNSAFE")
                if info.attributes & _REPARSE:
                    raise ValueError("OFFLINE_PATH_UNSAFE")
                if bool(info.attributes & 0x10) != is_dir:
                    raise ValueError("OFFLINE_PATH_UNSAFE")
                if not is_dir and info.links > 1:
                    raise ValueError("OFFLINE_PATH_UNSAFE")
                if os.path.normcase(_win_handle_path(handle)) != os.path.normcase(candidate):
                    raise ValueError("OFFLINE_PATH_UNSAFE")
            yield handles
        except OSError:
            raise ValueError("OFFLINE_PATH_UNSAFE") from None
        finally:
            for handle in reversed(handles):
                if handle is not None:
                    _kernel32.CloseHandle(handle)

    def _win_read_bounded(path: Path, limit: int) -> bytes:
        try:
            with _win_anchored(path, directory=False) as handles:
                handle = handles[-1]
                fd = msvcrt.open_osfhandle(handle.value if hasattr(handle, "value") else handle, os.O_RDONLY | os.O_BINARY)
                handles[-1] = None  # CRT owns the HANDLE after open_osfhandle.
                try:
                    stream = os.fdopen(fd, "rb")
                except BaseException:
                    # fdopen may fail before adopting the CRT descriptor.
                    # Do not leak the descriptor or double-close the HANDLE.
                    os.close(fd)
                    raise
                with stream:
                    before = os.fstat(stream.fileno())
                    if before.st_size > limit:
                        raise ValueError("OFFLINE_FILE_TOO_LARGE")
                    data = stream.read(limit + 1)
                    after = os.fstat(stream.fileno())
                    if not _identity(before, after):
                        raise ValueError("OFFLINE_PATH_UNSAFE")
                    if len(data) > limit:
                        raise ValueError("OFFLINE_FILE_TOO_LARGE")
                    return data
        except OSError:
            raise ValueError("OFFLINE_PATH_UNSAFE") from None


def require_plain_dir(path: Path) -> None:
    if os.name == "nt":
        with _win_anchored(path, directory=True):
            return
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
    if os.name == "nt":
        return _win_read_bounded(path, limit)
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
