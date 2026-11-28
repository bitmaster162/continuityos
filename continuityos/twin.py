"""Legacy retrieval-based Twin helpers.

These helpers surface current recorded evidence and a keyword-negation review
heuristic. They do not predict a person's behavior, calibrate confidence, prove
semantic compatibility, or implement the separate Person/R21H admission path.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from functools import wraps
from typing import Any, Dict, List, Optional

from .continuity import _current_record, _matches_scope, _scope_value, _unreviewed_record
from .memory import Memory

_PROHIBITION = re.compile(r"\b(?:never|not|don't|avoid|нельзя|не|запрещ\w*)\b", re.IGNORECASE)


def _candidate(meta: Dict[str, Any]) -> bool:
    return _unreviewed_record(meta)


def _read_snapshot(method):
    @wraps(method)
    def read(self, *args, **kwargs):
        with self.m.store.read_snapshot():
            return method(self, *args, **kwargs)
    return read


class Twin:
    def __init__(self, memory: Optional[Memory] = None, db: str = "continuityos.db",
                 owner: str = "owner", *, project: Optional[str] = None,
                 subject: Optional[str] = None):
        self.project = _scope_value(project, "project")
        self.subject = _scope_value(subject, "subject")
        self.m = memory if memory is not None else Memory(db)
        self.owner = owner

    def _scope(self, project: Optional[str], subject: Optional[str]) -> Dict[str, Optional[str]]:
        return {"project": _scope_value(project, "project") if project is not None else self.project,
                "subject": _scope_value(subject, "subject") if subject is not None else self.subject}

    @staticmethod
    def _limit(k: int) -> None:
        if isinstance(k, bool) or not isinstance(k, int) or k < 1:
            raise ValueError("k must be a positive integer")

    @staticmethod
    def _evidence(row: Any, score: Optional[float], why: str, observed_at: float) -> Dict[str, Any]:
        meta = json.loads(row["meta"])
        # Only recorded scalar source locators are projected, not arbitrary metadata.
        source_fields = ("source", "source_id", "source_uri", "source_version", "source_sha256")
        source = {key: meta[key] for key in source_fields if isinstance(meta.get(key), str)}
        return {"id": row["id"], "memory_ref": f"mem:{row['id']}",
                "namespace": row["namespace"], "text": row["text"],
                "score": round(score, 4) if score is not None else None, "why": why,
                "current_status": "CURRENT_AT_SNAPSHOT", "observed_at": observed_at,
                "scope": {"project": meta.get("project"), "subject": meta.get("subject")},
                "acceptance_status": ("UNREVIEWED_OR_EXCLUDED_CANDIDATE" if _candidate(meta) else
                                      "RECORDED_ACCEPTANCE_UNVERIFIED" if meta.get("accepted") is True else
                                      "RECORDED_NOT_VERIFIED"),
                "review_status": meta.get("review_status"),
                "admission_status": meta.get("admission_status"),
                "provenance": {"memory_version": row["version"], "recorded_at": row["created_at"],
                               "source": source, "source_status": "RECORDED_UNVERIFIED" if source else "NOT_RECORDED",
                               "text_sha256": hashlib.sha256(row["text"].encode("utf-8")).hexdigest(),
                               "origin_verified": False}}

    def _retrieve(self, query: str, namespaces: tuple[str, ...], k: int,
                  scope: Dict[str, Optional[str]], observed_at: float, *,
                  candidates_only: bool = False) -> List[Dict[str, Any]]:
        evidence = []
        for namespace in namespaces:
            for hit in self.m.recall(query, k=k, namespace=namespace, current_only=True,
                                     scope=scope, include_global=namespace in ("canon", "rules"),
                                     exclude_unreviewed=not candidates_only):
                if hit.score <= 0:
                    continue
                # Re-read record identity and current status rather than project an
                # outdated MemoryItem after a supersession between query and output.
                row = self.m.store.get(hit.id)
                if row is None or row["namespace"] != namespace or row["text"] != hit.text:
                    continue
                meta = json.loads(row["meta"])
                if _candidate(meta) != candidates_only:
                    continue
                if not _current_record(meta, row["created_at"], observed_at):
                    continue
                if not _matches_scope(meta, scope, include_global=namespace in ("canon", "rules")):
                    continue
                evidence.append(self._evidence(row, hit.score, hit.why, observed_at))
        return sorted(evidence, key=lambda item: (-item["score"], item["id"]))

    @_read_snapshot
    def profile(self, k: int = 8, *, project: Optional[str] = None,
                subject: Optional[str] = None) -> Dict[str, Any]:
        self._limit(k)
        scope, observed_at = self._scope(project, subject), time.time()
        evidence, candidate_evidence, coverage = {}, {}, {}
        for namespace in ("identity", "canon", "rules"):
            applicable, candidates = [], []
            for row in self.m.store.all_with_vecs(namespace=namespace):
                meta = json.loads(row["meta"])
                if _current_record(meta, row["created_at"], observed_at) and _matches_scope(
                    meta, scope, include_global=namespace in ("canon", "rules"),
                ):
                    target = candidates if _candidate(meta) else applicable
                    target.append(self._evidence(row, None, "current scoped record", observed_at))
            applicable.sort(key=lambda item: item["id"])
            candidates.sort(key=lambda item: item["id"])
            evidence[namespace] = applicable[:k]
            candidate_evidence[namespace] = candidates[:k]
            coverage[namespace] = {"available": len(applicable), "included": min(len(applicable), k),
                                   "omitted": max(0, len(applicable) - k),
                                   "excluded_candidates": len(candidates)}
        return {"owner": self.owner, "scope": scope,
                **{namespace: [item["text"] for item in evidence[namespace]] for namespace in evidence},
                "evidence": evidence, "candidate_evidence": candidate_evidence, "coverage": coverage,
                "profile_status": "RECORDED_PROFILE_ONLY", "behavior_validated": False}

    @_read_snapshot
    def predict(self, situation: str, k: int = 5, *, project: Optional[str] = None,
                subject: Optional[str] = None) -> Dict[str, Any]:
        """Surface relevant records; the legacy method name is retained for callers."""
        self._limit(k)
        scope, observed_at = self._scope(project, subject), time.time()
        candidates = self._retrieve(situation, ("canon", "rules", "checkpoint", "facts"),
                                     k, scope, observed_at)
        unreviewed = self._retrieve(situation, ("canon", "rules", "checkpoint", "facts"),
                                     k, scope, observed_at, candidates_only=True)
        evidence = candidates[:k]
        stance = ("Relevant recorded evidence: " + "; ".join(item["text"] for item in evidence)) if evidence else \
                 "No current applicable evidence was retrieved for this situation."
        return {"situation": situation, "scope": scope, "predicted_stance": stance,
                "prediction_status": "NOT_A_BEHAVIORAL_PREDICTION",
                "evidence_status": ("RETRIEVED_EVIDENCE" if evidence else
                                    "INSUFFICIENT_ACCEPTED_EVIDENCE" if unreviewed else "NO_EVIDENCE"),
                "evidence": evidence, "candidate_evidence": unreviewed[:k],
                "retrieval_signal": {"kind": "UNCALIBRATED_RETRIEVAL_SCORE",
                                     "strongest_score": evidence[0]["score"] if evidence else None,
                                     "returned_evidence_count": len(evidence),
                                     "score_is_probability": False},
                "coverage": {"kind": "RETRIEVED_CURRENT_RECORDS_ONLY",
                             "retrieved": len(candidates), "included": len(evidence),
                             "omitted": len(candidates) - len(evidence), "exhaustive": False,
                             "excluded_candidates_retrieved": len(unreviewed)},
                "authority_granted": False}

    @_read_snapshot
    def alignment(self, proposed_action: str, k: int = 6, *, project: Optional[str] = None,
                  subject: Optional[str] = None) -> Dict[str, Any]:
        """Flag retrieved prohibitive wording; absence of a flag is not permission."""
        self._limit(k)
        scope, observed_at = self._scope(project, subject), time.time()
        evidence = self._retrieve(proposed_action, ("canon", "rules"), k, scope, observed_at)
        unreviewed = self._retrieve(proposed_action, ("canon", "rules"), k, scope,
                                     observed_at, candidates_only=True)
        hits = [{**item, "rule": item["text"], "relevance": item["score"]} for item in evidence]
        flags = [item for item in hits if _PROHIBITION.search(item["rule"])]
        if not hits:
            verdict_code = "INSUFFICIENT_ACCEPTED_EVIDENCE" if unreviewed else "INSUFFICIENT_EVIDENCE"
            verdict = "UNKNOWN — only unreviewed/excluded candidates were retrieved" if unreviewed else \
                      "UNKNOWN — no current applicable rule was retrieved"
        elif flags:
            verdict_code = "REVIEW_PROHIBITIVE_RULE"
            verdict = "REVIEW — retrieved prohibitive wording; semantic compatibility is unverified"
        else:
            verdict_code = "NO_HEURISTIC_CONFLICT_FOUND"
            verdict = "UNKNOWN — no keyword conflict detected; semantic compatibility is unverified"
        return {"action": proposed_action, "scope": scope, "relevant_rules": hits[:k],
                "candidate_evidence": unreviewed[:k],
                "possible_conflicts": flags[:k], "verdict_code": verdict_code, "verdict": verdict,
                "evidence_status": ("RETRIEVED_RULES" if hits else
                                    "INSUFFICIENT_ACCEPTED_EVIDENCE" if unreviewed else "NO_EVIDENCE"),
                "check_kind": "KEYWORD_NEGATION_HEURISTIC", "semantic_compatibility": "UNVERIFIED",
                "coverage": {"kind": "RETRIEVED_CURRENT_RECORDS_ONLY", "retrieved": len(hits),
                             "included": min(len(hits), k), "omitted": max(0, len(hits) - k),
                             "exhaustive": False, "excluded_candidates_retrieved": len(unreviewed)},
                "authority_granted": False}
