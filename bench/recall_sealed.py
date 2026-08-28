#!/usr/bin/env python3
"""Checksum-bound ContinuityOS recall/current-truth benchmark runner."""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

os.environ["CONTINUITYOS_SILENCE_EMBED_WARN"] = "1"
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuityos.embed import HashingEmbedder
from continuityos.memory import Memory
from bench.recall_bench import DISTRACTORS, GOLD, NS, UPDATES, build
from bench.sealing import (
    build_manifest,
    canonical_sha256,
    model_identity,
    require_sealed_model,
    sha256_file,
    write_json,
)


DEFAULT_MODELS = {
    "fastembed": "BAAI/bge-small-en-v1.5",
    "model2vec": "minishlab/potion-base-8M",
    "st": "all-MiniLM-L6-v2",
}
PACKAGE_BY_EMBEDDER = {
    "fastembed": "fastembed",
    "model2vec": "model2vec",
    "st": "sentence-transformers",
}


def make_embedder(kind: str, model: str | None):
    if kind == "hashing":
        return HashingEmbedder(), None
    selected = model or DEFAULT_MODELS[kind]
    if kind == "fastembed":
        from continuityos.embedders import FastEmbedEmbedder

        return FastEmbedEmbedder(selected), selected
    if kind == "model2vec":
        from continuityos.embedders import Model2VecEmbedder

        return Model2VecEmbedder(selected), selected
    if kind == "st":
        from continuityos.embedders import SentenceTransformerEmbedder

        return SentenceTransformerEmbedder(selected), selected
    raise ValueError(f"unsupported embedder: {kind}")


def ranked_ids(mem: Memory, query: str, k: int) -> list[str | None]:
    return [getattr(item, "id", None) for item in mem.recall(query, k=k, namespace=NS)]


def run(embedder, model: dict[str, Any]) -> dict[str, Any]:
    with tempfile.TemporaryDirectory() as tmp:
        mem = Memory(os.path.join(tmp, "bench.db"), embedder=embedder)
        build_started = time.perf_counter()
        gold_ids, chains = build(mem)
        build_ms = (time.perf_counter() - build_started) * 1000

        keyword_hits = {1: 0, 3: 0, 5: 0}
        paraphrase_hits = {1: 0, 3: 0, 5: 0}
        latencies: list[float] = []
        recall_cases = []
        for index, (_fact, keyword, paraphrase) in enumerate(GOLD):
            target = gold_ids[index]
            keyword_ranked = ranked_ids(mem, keyword, 5)
            paraphrase_ranked = ranked_ids(mem, paraphrase, 5)
            keyword_case = {str(k): target in keyword_ranked[:k] for k in (1, 3, 5)}
            paraphrase_case = {str(k): target in paraphrase_ranked[:k] for k in (1, 3, 5)}
            for k in (1, 3, 5):
                keyword_hits[k] += int(keyword_case[str(k)])
                paraphrase_hits[k] += int(paraphrase_case[str(k)])
            started = time.perf_counter()
            mem.recall(keyword, k=5, namespace=NS)
            latencies.append((time.perf_counter() - started) * 1000)
            recall_cases.append(
                {
                    "case_id": f"recall-{index:03d}",
                    "keyword_query": keyword,
                    "paraphrase_query": paraphrase,
                    "keyword_hit_at": keyword_case,
                    "paraphrase_hit_at": paraphrase_case,
                }
            )

        current_ok = 0
        temporal_ok = 0
        update_cases = []
        for index, ((oid, _nid, t_old, _t_new), (original, updated, query)) in enumerate(
            zip(chains, UPDATES)
        ):
            current = mem.recall(query, k=5, namespace=NS, current_only=True)
            current_texts = [getattr(item, "text", "") for item in current]
            current_pass = updated in current_texts and original not in current_texts
            old = mem.recall(query, k=10, namespace=NS, as_of=t_old + 1)
            old_texts = [getattr(item, "text", "") for item in old]
            temporal_pass = original in old_texts and updated not in old_texts
            current_ok += int(current_pass)
            temporal_ok += int(temporal_pass)
            update_cases.append(
                {
                    "case_id": f"update-{index:03d}",
                    "query": query,
                    "current_only_pass": current_pass,
                    "as_of_old_pass": temporal_pass,
                    "superseded_id": oid,
                }
            )

    n = len(GOLD)
    updates = len(UPDATES)
    dataset_payload = {
        "gold": GOLD,
        "updates": UPDATES,
        "distractors": DISTRACTORS,
    }
    return {
        "schema": "continuityos-recall-sealed-result-v1",
        "benchmark": "recall-current-truth",
        "dataset": {
            "kind": "embedded-corpus",
            "sha256": canonical_sha256(dataset_payload),
            "gold_cases": n,
            "update_cases": updates,
            "distractors": len(DISTRACTORS),
        },
        "model": model,
        "metrics": {
            "total_memories": len(GOLD) + len(DISTRACTORS) + 2 * len(UPDATES),
            "build_ms": round(build_ms, 3),
            "recall_keyword": {
                f"@{k}": round(100 * keyword_hits[k] / n, 3) for k in (1, 3, 5)
            },
            "recall_paraphrase": {
                f"@{k}": round(100 * paraphrase_hits[k] / n, 3) for k in (1, 3, 5)
            },
            "knowledge_update_current_pct": round(100 * current_ok / updates, 3),
            "temporal_as_of_pct": round(100 * temporal_ok / updates, 3),
            "recall_latency_ms": {
                "p50": round(statistics.median(latencies), 3),
                "p95": round(sorted(latencies)[int(0.95 * len(latencies)) - 1], 3),
                "mean": round(statistics.mean(latencies), 3),
            },
            "external_tokens_per_query": 0,
            "external_api_calls": 0,
        },
        "cases": {
            "recall": recall_cases,
            "current_truth": update_cases,
        },
        "authority": {
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "provider_effects": False,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--embedder",
        choices=("hashing", "fastembed", "model2vec", "st"),
        default="hashing",
    )
    parser.add_argument("--model")
    parser.add_argument("--model-revision")
    parser.add_argument("--model-sha256")
    parser.add_argument("--json-out", required=True)
    parser.add_argument("--manifest-out", required=True)
    args = parser.parse_args(argv)

    embedder, selected_model = make_embedder(args.embedder, args.model)
    identity = model_identity(
        embedder=args.embedder,
        model_name=selected_model,
        model_revision=args.model_revision,
        model_sha256=args.model_sha256,
        package_name=PACKAGE_BY_EMBEDDER.get(args.embedder),
    )
    require_sealed_model(identity)

    report = run(embedder, identity)
    write_json(args.json_out, report)
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    manifest = build_manifest(
        benchmark_name="recall-current-truth",
        benchmark_source=Path(__file__),
        argv=effective_argv,
        result_path=args.json_out,
        dataset=report["dataset"],
        model=identity,
        extra_packages=[PACKAGE_BY_EMBEDDER[args.embedder]]
        if args.embedder in PACKAGE_BY_EMBEDDER
        else [],
    )
    write_json(args.manifest_out, manifest)
    print(
        json.dumps(
            {
                "status": "PASS",
                "result_sha256": sha256_file(args.json_out),
                "manifest_sha256": sha256_file(args.manifest_out),
                "model_identity_assurance": identity["identity_assurance"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
