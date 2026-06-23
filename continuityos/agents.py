"""Multi-agent council — many agents (and the human) on one ContinuityOS.

Generalized from the Continuity OS AGENT_COUNCIL / INTERNAL_AGENTS canon:
every actor has an authority level (1..5); namespaces have a minimum write
level; the human operator is Sovereign (5). Internal roles are stable
attention functions (Archivist / Builder / Critic / Steward), not personas.
Every memory written through the council is tagged with its author + authority,
so a swarm can share one memory without overwriting trust.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Optional
from .memory import Memory

# authority levels
SOVEREIGN, STEWARD, BUILDER, CRITIC, READER = 5, 4, 3, 2, 1
LEVEL_NAME = {5:"sovereign",4:"steward",3:"builder",2:"critic",1:"reader"}

# internal roles = stable attention functions (from INTERNAL_AGENTS canon)
ROLES = {
    "archivist": "Read everything; extract the delta without drowning in raw archive.",
    "builder":   "Make the change; turn intent into concrete artifacts.",
    "critic":    "Challenge; surface risks, gaps, and false trails before they ship.",
    "steward":   "Maintain integrity; enforce canon, anti-drift, and closure.",
}

# minimum authority level required to WRITE into a namespace
NAMESPACE_MIN_WRITE = {
    "canon": SOVEREIGN,      # only the human changes non-negotiable truths
    "frontier": STEWARD,
    "checkpoint": BUILDER,
    "loop": BUILDER,
    "rules": STEWARD,
    "default": CRITIC,       # most namespaces: critic+ may write
}

@dataclass
class Actor:
    name: str
    authority: int = BUILDER
    role: str = "builder"

class Council:
    def __init__(self, memory: Optional[Memory] = None, db: str = "continuityos.db"):
        self.m = memory or Memory(db)
        self.actors: Dict[str, Actor] = {}

    def register(self, name: str, authority: int = BUILDER, role: str = "builder") -> Actor:
        a = Actor(name=name, authority=int(authority), role=role)
        self.actors[name] = a
        return a

    def can_write(self, actor: str, namespace: str) -> bool:
        a = self.actors.get(actor)
        if not a:
            return False
        need = NAMESPACE_MIN_WRITE.get(namespace, NAMESPACE_MIN_WRITE["default"])
        return a.authority >= need

    def remember(self, actor: str, text: str, namespace: str = "notes",
                 tags: Optional[List[str]] = None) -> int:
        a = self.actors.get(actor)
        if not a:
            raise PermissionError(f"unknown actor '{actor}'")
        if not self.can_write(actor, namespace):
            need = NAMESPACE_MIN_WRITE.get(namespace, NAMESPACE_MIN_WRITE["default"])
            raise PermissionError(
                f"{actor} (L{a.authority}/{LEVEL_NAME.get(a.authority)}) cannot write "
                f"[{namespace}] — needs L{need}/{LEVEL_NAME.get(need)}")
        tags = (tags or []) + [f"by:{actor}", f"role:{a.role}", f"auth:{a.authority}"]
        return self.m.remember(text, namespace=namespace, tags=tags,
                               meta={"author": actor, "authority": a.authority, "role": a.role})

    def roster(self) -> List[Dict]:
        return [{"name":a.name,"authority":a.authority,"level":LEVEL_NAME.get(a.authority),"role":a.role}
                for a in self.actors.values()]
