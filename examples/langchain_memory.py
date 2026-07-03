"""LangChain memory adapter for ContinuityOS (integration multiplier #1, pre-launch).

Zero hard dependency on langchain: duck-typed to the BaseMemory interface
(load_memory_variables / save_context / clear), so it works with
langchain>=0.1 ConversationChain and LCEL RunnableWithMessageHistory alike.

    pip install continuityos langchain-openai
    from examples.langchain_memory import ContinuityOSMemory
    memory = ContinuityOSMemory(db="~/.continuityos/memory.db", k=6)
    chain = ConversationChain(llm=llm, memory=memory)

Every turn is stored ADD-only (Mem0 v3 pattern) with auto-extraction of durable
facts; recall is hybrid (FTS+vector) with bi-temporal current_only filtering —
so the chain remembers what is CURRENTLY true, not what was superseded.
"""
from __future__ import annotations
import os
from typing import Any, Dict, List

from continuityos import Memory
from continuityos.extract import extract_and_store


class ContinuityOSMemory:
    """Duck-typed langchain BaseMemory backed by ContinuityOS."""

    memory_key: str = "history"

    def __init__(self, db: str = "~/.continuityos/langchain.db",
                 namespace: str = "chat", k: int = 6,
                 auto_extract: bool = True):
        self.m = Memory(os.path.expanduser(db))
        self.namespace = namespace
        self.k = k
        self.auto_extract = auto_extract

    # -- langchain BaseMemory interface --
    @property
    def memory_variables(self) -> List[str]:
        return [self.memory_key]

    def load_memory_variables(self, inputs: Dict[str, Any]) -> Dict[str, str]:
        query = next(iter(inputs.values())) if inputs else ""
        hits = self.m.recall(str(query), k=self.k, namespace=self.namespace,
                             current_only=True)
        ctx = "\n".join(f"- {h.text}" for h in hits)
        return {self.memory_key: ctx}

    def save_context(self, inputs: Dict[str, Any], outputs: Dict[str, str]) -> None:
        user = str(next(iter(inputs.values()), ""))
        ai = str(next(iter(outputs.values()), ""))
        self.m.remember(f"user: {user}", namespace=self.namespace, mtype="event")
        self.m.remember(f"assistant: {ai}", namespace=self.namespace, mtype="event")
        if self.auto_extract:  # durable facts -> long-term namespace
            extract_and_store(f"{user}\n{ai}", self.m, namespace="facts")

    def clear(self) -> None:
        # append-only philosophy: nothing is destroyed; start a new namespace instead
        self.namespace = self.namespace + "_new"


if __name__ == "__main__":
    mem = ContinuityOSMemory(db="/tmp/lc_demo.db")
    mem.save_context({"input": "меня зовут Роберт, я строю арену ботов"},
                     {"output": "Принял, Роберт. Арена — сильный проект."})
    print(mem.load_memory_variables({"input": "как меня зовут и что я строю?"}))
