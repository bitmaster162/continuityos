#!/usr/bin/env python3
"""Checksum-bound LoCoMo retrieval benchmark for ContinuityOS."""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from continuityos import Memory
from continuityos.embed import HashingEmbedder
from bench.locomo_bench import load_locomo
from bench.sealing import (
    build_manifest,
    model_identity,
    normalize_sha256,
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


def evaluate(embedder, samples, ks=(1, 3, 5, 10)) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    hits = {k: 0 for k in ks}
    reciprocal_rank = 0.0
    questions = 0
    rows: list[dict[str, Any]] = []
    started = time.perf_counter()

    for sample_index, sample in enumerate(samples):
        with tempfile.TemporaryDirectory() as tmp:
            memory = Memory(os.path.join(tmp, "locomo.db"), embedder=embedder)
            try:
                rid_by_dia: dict[str, str] = {}
                dia_by_rid: dict[str, str] = {}
                for turn in sample["turns"]:
                    rid = memory.remember(
                        turn["text"], namespace="facts", meta={"dia": turn["id"]}
                    )
                    rid_by_dia[turn["id"]] = rid
                    dia_by_rid[rid] = turn["id"]

                for question_index, qa in enumerate(sample["qa"]):
                    gold = {gold for gold in qa["gold"] if gold in rid_by_dia}
                    if not gold:
                        continue
                    questions += 1
                    ranked_rids = [
                        hit.id for hit in memory.recall(qa["q"], k=max(ks))
                    ]
                    ranked_dia = [dia_by_rid.get(rid) for rid in ranked_rids]
                    first_rank = next(
                        (index + 1 for index, dia in enumerate(ranked_dia) if dia in gold),
                        None,
                    )
                    if first_rank is not None:
                        reciprocal_rank += 1.0 / first_rank
                    hit_at = {}
                    for k in ks:
                        matched = bool(gold & set(ranked_dia[:k]))
                        hit_at[str(k)] = matched
                        hits[k] += int(matched)
                    rows.append(
                        {
                            "case_id": f"locomo-{sample_index:02d}-{question_index:04d}",
                            "question": qa["q"],
                            "gold_evidence_ids": sorted(gold),
                            "ranked_evidence_ids": ranked_dia,
                            "first_gold_rank": first_rank,
                            "hit_at": hit_at,
                        }
                    )
            finally:
                memory.store.con.close()

    elapsed = time.perf_counter() - started
    metrics = {
        **{
            f"recall@{k}": round(hits[k] / questions, 8) if questions else 0.0
            for k in ks
        },
        "MRR": round(reciprocal_rank / questions, 8) if questions else 0.0,
        "questions": questions,
        "seconds": round(elapsed, 3),
    }
    return metrics, rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", required=True)
    parser.add_argument("--expected-sha256", required=True)
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

    data_path = Path(args.data).resolve()
    if not data_path.is_file():
        parser.error(f"dataset not found: {data_path}")
    expected = normalize_sha256(args.expected_sha256, field="expected_sha256")
    actual = sha256_file(data_path)
    if actual != expected:
        parser.error(
            f"dataset SHA-256 mismatch: expected {expected}, observed {actual}"
        )

    embedder, selected_model = make_embedder(args.embedder, args.model)
    identity = model_identity(
        embedder=args.embedder,
        model_name=selected_model,
        model_revision=args.model_revision,
        model_sha256=args.model_sha256,
        package_name=PACKAGE_BY_EMBEDDER.get(args.embedder),
    )
    require_sealed_model(identity)

    samples = load_locomo(str(data_path))
    metrics, rows = evaluate(embedder, samples)
    dataset = {
        "kind": "locomo10-json",
        "path": data_path.name,
        "sha256": actual,
        "expected_sha256": expected,
        "sha256_match": True,
        "dialogues": len(samples),
        "turns": sum(len(sample["turns"]) for sample in samples),
        "qa_pairs_loaded": sum(len(sample["qa"]) for sample in samples),
    }
    report = {
        "schema": "continuityos-locomo-sealed-result-v1",
        "benchmark": "locomo-retrieval",
        "dataset": dataset,
        "model": identity,
        "metrics": metrics,
        "cases": rows,
        "authority": {
            "execution_authority": "NONE",
            "can_execute": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "provider_effects": False,
        },
    }
    write_json(args.json_out, report)
    effective_argv = list(argv) if argv is not None else sys.argv[1:]
    manifest = build_manifest(
        benchmark_name="locomo-retrieval",
        benchmark_source=Path(__file__),
        argv=effective_argv,
        result_path=args.json_out,
        dataset=dataset,
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
                "questions": metrics["questions"],
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
