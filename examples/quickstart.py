#!/usr/bin/env python3
"""Quickstart demo — ContinuityOS in 60 seconds.

Run: python examples/quickstart.py
Shows: memory storage, semantic recall, checkpoint, gate, predict.
"""
from continuityos import Memory, Continuity
from continuityos.twin import Twin
from continuityos.gate.spec import ActionSpec
from continuityos.gate.engine import preflight as gate_preflight
import tempfile, os

DB = os.path.join(tempfile.gettempdir(), "cos_demo.db")
if os.path.exists(DB):
    os.remove(DB)

print("=" * 60)
print("  ContinuityOS Quickstart Demo")
print("=" * 60)

# 1. Memory
print("\n📝 1. Storing memories...")
m = Memory(DB)
m.remember("Python 3.12 is our runtime", namespace="facts", tags=["infra"])
m.remember("Never deploy on Fridays — rule #4", namespace="rules", tags=["canon"])
m.remember("Trading Phase B: 51 trades, 58.8% WR, +$445 paper", namespace="facts")
m.remember("Database is PostgreSQL on port 5432", namespace="facts")
print("   ✓ 4 memories stored")

# 2. Recall
print("\n🔍 2. Semantic recall...")
hits = m.recall("what database do we use", k=2)
for h in hits:
    print(f"   {h.score:.2f} [{h.namespace}] {h.text[:60]}...")

# 3. Context
print("\n📋 3. Context block for LLM injection...")
ctx = m.context("trading results", k=2)
print(f"   {ctx[:120]}...")

# 4. Checkpoint
print("\n📦 4. Creating checkpoint...")
c = Continuity(memory=m)
cid = c.checkpoint(
    summary="Quickstart demo completed",
    next_action="Run production boot with real data"
)
print(f"   ✓ Checkpoint #{cid}")

# 5. Twin (predict + alignment)
print("\n🧠 5. Digital Twin...")
t = Twin(memory=m)
pred = t.predict("should I deploy on Friday?")
print(f"   Predict: {pred.get('predicted_stance', 'N/A')[:80]}...")

align = t.alignment("delete all trading data")
print(f"   Alignment: {align.get('verdict', 'N/A')}")

# 6. Gate
print("\n🛡️ 6. Governance Gate...")
spec1 = ActionSpec(tool="shell", command="rm -rf /production")
r1 = gate_preflight(spec1)
print(f"   rm -rf /production → {r1.get('decision', 'N/A')} ({r1.get('severity', 'N/A')})")

spec2 = ActionSpec(tool="shell", command="ls -la /tmp")
r2 = gate_preflight(spec2)
print(f"   ls -la /tmp       → {r2.get('decision', 'N/A')} ({r2.get('severity', 'N/A')})")

# Cleanup
print("\n✅ Demo complete! DB saved at:", DB)
print("   Run `cos --db " + DB + " doctor` to check health.")
