"""Seed a demo memory with SYNTHETIC data (no personal data). Run:
    python examples/seed_demo.py
Then:  cos --db demo.db recall "how do agents stay consistent?"
"""
from continuityos import Memory

DEMO = [
 ("identity", ["role"],   "The user is a solo developer building autonomous agents."),
 ("rules",    ["style"],  "Always write code with tests; prefer permissive open-source licenses."),
 ("rules",    ["safety"], "Never execute irreversible actions without explicit confirmation."),
 ("projects", ["product"],"ContinuityOS gives agents durable memory across sessions."),
 ("projects", ["product"],"Hybrid recall blends keyword (FTS) and vector (semantic) search."),
 ("facts",    ["mcp"],    "MCP lets an agent fetch relevant memory automatically before answering."),
 ("facts",    ["arch"],   "Memory is stored locally in one SQLite file; nothing leaves the machine."),
 ("events",   ["log"],    "On 2026-06-17 the team shipped ContinuityOS v0.1 under Apache-2.0."),
]

if __name__ == "__main__":
    m = Memory("demo.db")
    for ns, tags, text in DEMO:
        m.remember(text, namespace=ns, tags=tags)
    print(f"seeded {m.count()} synthetic memories into demo.db")
    print("\nrecall('how do agents stay consistent between sessions?'):")
    for h in m.recall("how do agents stay consistent between sessions?", k=3):
        print(f"  {h.score:.3f} [{h.namespace}] {h.text}")
