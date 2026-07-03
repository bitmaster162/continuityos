"""ContinuityOS — durable, hybrid memory + continuity layer for AI agents and humans.

Memory: structural (namespaces + keyword FTS) + semantic (vector cosine) recall.
Continuity: canon, frontiers, open loops, checkpoints, anti-drift doctor, handoff.
Local-first. No data leaves the machine.
"""
from importlib.metadata import PackageNotFoundError, version as _pkg_version

from .memory import Memory, MemoryItem
from .continuity import Continuity
from .agents import Council, Actor
from .twin import Twin
from .control import ControlPlane
from . import fork
__all__ = ["Memory", "MemoryItem", "Continuity", "Council", "Actor", "Twin", "ControlPlane", "fork"]
try:
    __version__ = _pkg_version("continuityos")
except PackageNotFoundError:
    # Source-tree fallback for tests or direct execution before installation.
    __version__ = "0.8.2"
