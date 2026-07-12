"""ContinuityOS — durable, hybrid memory + continuity layer for AI agents and humans.

Memory: structural (namespaces + keyword FTS) + semantic (vector cosine) recall.
Continuity: canon, frontiers, open loops, checkpoints, anti-drift doctor, handoff.
Local-first. No data leaves the machine.
"""
from .memory import Memory, MemoryItem
from .continuity import Continuity
from .agents import Council, Actor
from .twin import Twin
from .control import ControlPlane
from . import fork
from ._version import __version__
__all__ = ["Memory", "MemoryItem", "Continuity", "Council", "Actor", "Twin", "ControlPlane", "fork"]
