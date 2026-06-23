"""ContinuityOS — durable, hybrid memory for AI agents and humans.

Structural (namespaces/collections + keyword FTS) + semantic (vector cosine)
recall over a local SQLite store. No data leaves the machine.
"""
from .memory import Memory, MemoryItem
__all__ = ["Memory", "MemoryItem"]
__version__ = "0.1.0"
