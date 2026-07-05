"""cos audit — full-system audit: inventory + invariants + optional devil's advocate.

Turns doctor()'s health check into an auditor's queryable record: memory
inventory, append-only integrity, bi-temporal consistency, canon presence,
gate availability, and dangling supersede pointers. Emits JSON + markdown — the
EU AI Act Article-12 "record of decisions" spirit. With devil=True, every FAILING
finding (plus any extra claims) is challenged by DevilsAdvocate.

    from continuityos.audit import SystemAudit
    rep = SystemAudit(memory, continuity, twin).run(devil=True)
    print(SystemAudit(memory).render(rep))

stdlib-only, deterministic.
"""
from __future__ import annotations
import json, time
from typing import Any, Dict, List, Optional

try:
    from .advocate import DevilsAdvocate
except ImportError:  # standalone / test
    from advocate import DevilsAdvocate


class SystemAudit:
    def __init__(self, memory, continuity=None, twin=None):
        self.m = memory
        self.c = continuity
        self.twin = twin

    def _rows(self, namespace: Optional[str] = None):
        return self.m.store.all_with_vecs(namespace=namespace)

    def inventory(self) -> Dict[str, int]:
        inv: Dict[str, int] = {}
        for r in self._rows():
            inv[r["namespace"]] = inv.get(r["namespace"], 0) + 1
        return dict(sorted(inv.items()))

    def _gate_status(self):
        try:
            try:
                from .gate import engine as ge
            except ImportError:
                from continuityos.gate import engine as ge
            return (callable(getattr(ge, "preflight", None)), "gate.preflight available")
        except Exception as e:
            return (False, f"gate import failed: {e}")

    def run(self, devil: bool = False, extra_claims: Optional[List[str]] = None) -> Dict[str, Any]:
        findings: List[Dict[str, Any]] = []

        def f(check, ok, severity, detail):
            findings.append({"check": check, "ok": bool(ok), "severity": severity, "detail": detail})

        rows = self._rows()
        total = len(rows)
        byid = {r["id"]: r for r in rows}

        canon = [r for r in rows if r["namespace"] == "canon"]
        f("canon_present", len(canon) > 0, "high", f"{len(canon)} canon rule(s)")

        dangling: List[tuple] = []
        superseded_no_vt = 0
        bitemporal_bad = 0
        chains = 0
        for r in rows:
            meta = json.loads(r["meta"])
            sb, sup = meta.get("superseded_by"), meta.get("supersedes")
            vf, vt = meta.get("valid_from"), meta.get("valid_to")
            if sb is not None:
                chains += 1
                if sb not in byid:
                    dangling.append((r["id"], "superseded_by", sb))
                if vt is None:
                    superseded_no_vt += 1
            if sup is not None and sup not in byid:
                dangling.append((r["id"], "supersedes", sup))
            if vf is not None and vt is not None:
                try:
                    if float(vf) > float(vt):
                        bitemporal_bad += 1
                except (TypeError, ValueError):
                    pass
        f("no_dangling_pointers", not dangling, "high",
          f"{len(dangling)} dangling" + (f" e.g. {dangling[:3]}" if dangling else ""))
        f("superseded_have_valid_to", superseded_no_vt == 0, "med",
          f"{superseded_no_vt} superseded row(s) missing valid_to (of {chains} chains)")
        f("bitemporal_ordering", bitemporal_bad == 0, "high",
          f"{bitemporal_bad} row(s) with valid_from > valid_to")

        gate_ok, gate_detail = self._gate_status()
        f("gate_available", gate_ok, "med", gate_detail)

        if self.c is not None:
            try:
                doc = self.c.doctor()
                f("doctor_healthy", doc.get("healthy"), "low",
                  f"{doc.get('passed')}/{doc.get('total')} doctor checks")
            except Exception as e:
                f("doctor_healthy", False, "low", f"doctor error: {e}")

        f("memory_nonempty", total > 0, "high", f"{total} memories")

        passed = sum(1 for x in findings if x["ok"])
        report = {"ts": time.time(),
                  "summary": {"total_memories": total, "namespaces": self.inventory(),
                              "passed": passed, "total_checks": len(findings),
                              "clean": passed == len(findings)},
                  "findings": findings}

        if devil:
            da = DevilsAdvocate(self.m, self.twin)
            claims = ["%s: %s" % (x["check"], x["detail"]) for x in findings if not x["ok"]]
            claims += (extra_claims or [])
            report["devil"] = [da.challenge(c) for c in claims]
            report["devil_summary"] = {
                "challenged": len(claims),
                "stop": sum(1 for d in report["devil"] if d["verdict"].startswith("STOP")),
                "reconsider": sum(1 for d in report["devil"] if d["verdict"].startswith("RECONSIDER"))}
        return report

    def render(self, report: Dict[str, Any]) -> str:
        s = report["summary"]
        out = ["# ContinuityOS system audit",
               f"memories: {s['total_memories']}  |  checks passed: {s['passed']}/{s['total_checks']}"
               + ("  ✓ CLEAN" if s["clean"] else "  ⚠ ISSUES"),
               "namespaces: " + ", ".join(f"{k}={v}" for k, v in s["namespaces"].items()),
               "", "## Findings"]
        for x in report["findings"]:
            mark = "✓" if x["ok"] else {"high": "⛔", "med": "⚠", "low": "·"}.get(x["severity"], "✗")
            out.append(f"  {mark} [{x['severity']}] {x['check']}: {x['detail']}")
        if "devil" in report:
            ds = report.get("devil_summary", {})
            out += ["", f"## Devil's advocate ({ds.get('challenged',0)} challenged; "
                        f"{ds.get('stop',0)} STOP, {ds.get('reconsider',0)} RECONSIDER)"]
            for d in report["devil"]:
                out.append(f"  {d['verdict'].split(' —')[0]}: {d['claim'][:70]}")
        return "\n".join(out)

    def export_article12(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """EU AI Act Article-12 (record-keeping) export: an automatically-generated,
        queryable record of the system state + governance decisions over its operation.
        Records are append-only + bi-temporal (nothing deleted), produced as a byproduct
        of operations. A record-keeping export, not legal advice or a compliance guarantee."""
        import datetime as _dt
        decisions = []
        for r in self._rows("audit"):
            meta = json.loads(r["meta"])
            decisions.append({"id": r["id"], "record": r["text"], "verdict": meta.get("verdict"),
                              "flags": meta.get("flags"), "ts": meta.get("ts")})
        s = report["summary"]
        return {
            "standard": "EU AI Act Article 12 - record-keeping / logging",
            "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "system": {"product": "ContinuityOS", "memories": s["total_memories"], "namespaces": s["namespaces"]},
            "integrity_findings": {f["check"]: {"ok": f["ok"], "severity": f["severity"], "detail": f["detail"]}
                                   for f in report["findings"]},
            "invariants_clean": s["clean"],
            "governance_decisions": decisions,
            "decision_count": len(decisions),
            "traceability": "Append-only + bi-temporal (valid_from/valid_to, supersede) - nothing is deleted; "
                            "this log is generated automatically as a byproduct of operations.",
            "disclaimer": "A record-keeping export, not legal advice or a certified compliance guarantee.",
        }
