from __future__ import annotations

import csv
import hashlib
import io
import json
import os
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from continuityos.gate.github_transition import (
    DEFAULT_TASK_ID,
    REQUIRED_WAVE_A,
    SLOTS,
    verify_github_transition_return,
)
from continuityos.gate.memory_promotion import evaluate_memory_promotion

TASK_SHA = "a" * 64
COMPLETE = "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_COMPLETE"
REVISE = "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_REVISE"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _repo_row(name: str) -> dict:
    oid = hashlib.sha1(name.encode()).hexdigest()
    tree = hashlib.sha1((name + "-tree").encode()).hexdigest()
    public = name == "continuityos"
    return {
        "name": name,
        "preexisting": True,
        "visibility_before": "PUBLIC" if public else "PRIVATE",
        "visibility_after": "PUBLIC" if public else "PRIVATE",
        "default_branch": "master" if public else "main",
        "default_branch_modified": False,
        "branch": "candidate/test",
        "local_head": oid,
        "remote_head": oid,
        "local_tree": tree,
        "remote_tree": tree,
        "force_push": False,
        "merged_into_existing_default": False,
        "secret_scan": "PASS",
    }


def _slot_rows() -> list[dict]:
    return [
        {
            "slot": slot,
            "physical_status": "BYTE_VERIFIED",
            "producer_terminal": "READY",
            "content_status": "UNREVIEWED",
            "apply_status": "NOT_APPLIED",
        }
        for slot in SLOTS
    ]


class TripletBuilder:
    def __init__(self, root: Path, terminal: str = COMPLETE):
        self.root = root
        self.terminal = terminal
        self.zip_path = root / "return.zip"
        self.sidecar_path = root / "return.zip.sha256"
        self.ready_path = root / "return.zip.READY_FOR_SYNC.json"
        self.files: dict[str, bytes] = {}
        self.repos = [_repo_row(name) for name in sorted(REQUIRED_WAVE_A)]
        self.slots = _slot_rows()
        self._populate()

    def _json(self, value: object) -> bytes:
        return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()

    def _populate(self) -> None:
        self.files = {
            "RETURN_ENVELOPE.json": self._json({
                "schema": "continuityos.github_transition.return_envelope/v1",
                "task_id": DEFAULT_TASK_ID,
                "task_body_sha256": TASK_SHA,
                "terminal": self.terminal,
            }),
            "TERMINAL_STATE.json": self._json({
                "schema": "continuityos.github_transition.terminal_state/v1",
                "task_id": DEFAULT_TASK_ID,
                "task_body_sha256": TASK_SHA,
                "terminal": self.terminal,
            }),
            "HOST_RETURN_RECOVERY_MATRIX.json": self._json({
                "schema": "continuityos.github_transition.host_return_recovery_matrix/v1",
                "slots": self.slots,
            }),
            "GITHUB_REPO_REGISTRY.json": self._json({
                "schema": "continuityos.github_transition.repo_registry/v1",
                "repositories": self.repos,
            }),
            "GITHUB_NO_SECRET_RECEIPT.json": self._json({"status": "PASS", "findings": 0}),
            "NO_EFFECT_RECEIPT.json": self._json({
                "registry_apply": False,
                "r63_apply": False,
                "current_state_apply": False,
                "deployment": False,
                "force_push": False,
                "existing_main_or_master_modified": False,
                "merged": False,
                "trade_wallet_order_or_capital_effect": False,
                "self_application": False,
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
            }),
            "TEARDOWN_RECEIPT.json": self._json({
                "temporary_workspace_removed": True,
                "active_processes_left": 0,
            }),
        }
        self._refresh_dynamic_files()

    def _refresh_dynamic_files(self) -> None:
        transport = io.StringIO()
        writer = csv.DictWriter(transport, fieldnames=[
            "name", "local_head", "remote_head", "local_tree", "remote_tree"
        ], lineterminator="\n")
        writer.writeheader()
        for row in self.repos:
            writer.writerow({key: row[key] for key in writer.fieldnames})
        self.files["GITHUB_TRANSPORT_MATRIX.csv"] = transport.getvalue().encode()
        self.files["HOST_RETURN_RECOVERY_MATRIX.json"] = self._json({
            "schema": "continuityos.github_transition.host_return_recovery_matrix/v1",
            "slots": self.slots,
        })
        self.files["GITHUB_REPO_REGISTRY.json"] = self._json({
            "schema": "continuityos.github_transition.repo_registry/v1",
            "repositories": self.repos,
        })

    def build(
        self,
        *,
        omit: set[str] | None = None,
        extras: list[tuple[str, bytes, int | None]] | None = None,
        manifest_omit: set[str] | None = None,
        manifest_bad_sha: str | None = None,
        ready_updates: dict | None = None,
        duplicate: tuple[str, bytes] | None = None,
    ) -> tuple[Path, Path, Path]:
        self._refresh_dynamic_files()
        omit = omit or set()
        manifest_omit = manifest_omit or set()
        payload = {k: v for k, v in self.files.items() if k not in omit}
        manifest_rows = []
        for name, data in sorted(payload.items()):
            if name in manifest_omit:
                continue
            digest = _sha(data)
            if name == manifest_bad_sha:
                digest = "0" * 64
            manifest_rows.append({"path": name, "bytes": len(data), "sha256": digest})
        payload["MANIFEST.json"] = self._json({
            "schema": "continuityos.github_transition.manifest/v1",
            "files": manifest_rows,
        })
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with zipfile.ZipFile(self.zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
                for name, data in payload.items():
                    zf.writestr(name, data)
                for name, data, mode in extras or []:
                    if mode is None:
                        zf.writestr(name, data)
                    else:
                        info = zipfile.ZipInfo(name)
                        info.create_system = 3
                        info.external_attr = mode << 16
                        zf.writestr(info, data)
                if duplicate:
                    zf.writestr(duplicate[0], duplicate[1])
        digest = hashlib.sha256(self.zip_path.read_bytes()).hexdigest()
        self.sidecar_path.write_text(f"{digest}  {self.zip_path.name}\n", encoding="utf-8")
        ready = {
            "schema": "READY_FOR_SYNC_V1",
            "artifact_zip": self.zip_path.name,
            "artifact_sha256": digest,
            "terminal_status": self.terminal,
            "written_last": True,
        }
        ready.update(ready_updates or {})
        self.ready_path.write_text(json.dumps(ready), encoding="utf-8")
        return self.zip_path, self.sidecar_path, self.ready_path


class GitHubTransitionTests(unittest.TestCase):
    def verify(self, builder: TripletBuilder, **kwargs):
        return verify_github_transition_return(
            *builder.build(**kwargs), expected_task_body_sha256=TASK_SHA
        )

    def test_valid_complete_return(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)))
            self.assertEqual(receipt["physical_status"], "BYTE_VERIFIED")
            self.assertEqual(receipt["terminal"], COMPLETE)
            self.assertEqual(len(receipt["slots"]), 9)

    def test_valid_revise_terminal_is_not_aliased(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td), REVISE))
            self.assertEqual(receipt["physical_status"], "BYTE_VERIFIED")
            self.assertEqual(receipt["terminal"], REVISE)

    def test_missing_zip_is_not_found(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            receipt = verify_github_transition_return(
                root / "missing.zip", root / "missing.sha", root / "missing.ready",
                expected_task_body_sha256=TASK_SHA,
            )
            self.assertEqual(receipt["physical_status"], "NOT_FOUND")

    def test_missing_sidecar_is_triplet_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); paths = b.build(); paths[1].unlink()
            receipt = verify_github_transition_return(*paths, expected_task_body_sha256=TASK_SHA)
            self.assertEqual(receipt["physical_status"], "TRIPLET_INCOMPLETE")

    def test_sidecar_mismatch_is_triplet_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); paths = b.build(); paths[1].write_text("0" * 64)
            receipt = verify_github_transition_return(*paths, expected_task_body_sha256=TASK_SHA)
            self.assertEqual(receipt["physical_status"], "TRIPLET_INCOMPLETE")

    def test_missing_ready_is_triplet_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); paths = b.build(); paths[2].unlink()
            receipt = verify_github_transition_return(*paths, expected_task_body_sha256=TASK_SHA)
            self.assertEqual(receipt["physical_status"], "TRIPLET_INCOMPLETE")

    def test_ready_terminal_alias_pass_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), ready_updates={"terminal_status": "PASS"})
            self.assertEqual(receipt["physical_status"], "TRIPLET_INCOMPLETE")

    def test_ready_must_claim_written_last(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), ready_updates={"written_last": False})
            self.assertEqual(receipt["physical_status"], "TRIPLET_INCOMPLETE")

    def test_zip_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), extras=[("../escape", b"x", None)])
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_backslash_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), extras=[("bad\\path", b"x", None)])
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_duplicate_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), duplicate=("RETURN_ENVELOPE.json", b"{}"))
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_case_fold_collision_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), extras=[("return_envelope.JSON", b"{}", None)])
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_symlink_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(
                TripletBuilder(Path(td)), extras=[("link", b"target", stat.S_IFLNK | 0o777)]
            )
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_high_compression_ratio_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), extras=[("bomb.bin", b"0" * 2_000_000, None)])
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_missing_required_member_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), omit={"TEARDOWN_RECEIPT.json"})
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_ambiguous_required_basename_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(
                TripletBuilder(Path(td)), extras=[("nested/RETURN_ENVELOPE.json", b"{}", None)]
            )
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_task_id_mismatch_is_binding_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td))
            obj = json.loads(b.files["RETURN_ENVELOPE.json"])
            obj["task_id"] = "WRONG"
            b.files["RETURN_ENVELOPE.json"] = b._json(obj)
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "TASK_BINDING_INCOMPLETE")

    def test_task_body_sha_mismatch_is_binding_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td))
            obj = json.loads(b.files["RETURN_ENVELOPE.json"])
            obj["task_body_sha256"] = "b" * 64
            b.files["RETURN_ENVELOPE.json"] = b._json(obj)
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "TASK_BINDING_INCOMPLETE")

    def test_terminal_conflict_is_binding_incomplete(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td))
            obj = json.loads(b.files["TERMINAL_STATE.json"])
            obj["terminal"] = REVISE
            b.files["TERMINAL_STATE.json"] = b._json(obj)
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "TASK_BINDING_INCOMPLETE")

    def test_manifest_sha_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), manifest_bad_sha="RETURN_ENVELOPE.json")
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_manifest_must_cover_required_evidence(self):
        with tempfile.TemporaryDirectory() as td:
            receipt = self.verify(TripletBuilder(Path(td)), manifest_omit={"GITHUB_NO_SECRET_RECEIPT.json"})
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_missing_slot_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); b.slots.pop()
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_slot_self_acceptance_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); b.slots[0]["content_status"] = "ACCEPTED"
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_repository_policy_violations_are_rejected(self):
        mutations = [
            lambda row: row.update(preexisting=False, visibility_before=None, visibility_after="PUBLIC"),
            lambda row: row.update(visibility_after="PRIVATE" if row["visibility_before"] == "PUBLIC" else "PUBLIC"),
            lambda row: row.update(remote_head="f" * 40),
            lambda row: row.update(remote_tree="f" * 40),
            lambda row: row.update(force_push=True),
            lambda row: row.update(merged_into_existing_default=True),
            lambda row: row.update(default_branch_modified=True),
            lambda row: row.update(secret_scan="FAIL"),
        ]
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as td:
                b = TripletBuilder(Path(td)); mutate(b.repos[0])
                receipt = self.verify(b)
                self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_complete_requires_all_wave_a_repositories(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); b.repos.pop()
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_secret_receipt_failure_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); b.files["GITHUB_NO_SECRET_RECEIPT.json"] = b._json({"status":"FAIL","findings":1})
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_effect_widening_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); obj=json.loads(b.files["NO_EFFECT_RECEIPT.json"]);obj["deployment"]=True;b.files["NO_EFFECT_RECEIPT.json"]=b._json(obj)
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")

    def test_teardown_failure_is_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            b = TripletBuilder(Path(td)); b.files["TEARDOWN_RECEIPT.json"] = b._json({"temporary_workspace_removed":False,"active_processes_left":1})
            receipt = self.verify(b)
            self.assertEqual(receipt["physical_status"], "INVALID_RETURN")


class MemoryPromotionTests(unittest.TestCase):
    def _closure(self, root: Path, *, physical="BYTE_VERIFIED", terminal=COMPLETE, nonbyte_slot=False) -> Path:
        repos = [_repo_row(name) for name in sorted(REQUIRED_WAVE_A)]
        slots = _slot_rows()
        if nonbyte_slot:
            slots[0]["physical_status"] = "TRIPLET_INCOMPLETE"
        path = root / "closure.json"
        path.write_text(json.dumps({
            "physical_status": physical,
            "terminal": terminal,
            "registry_apply": False,
            "r63_apply": False,
            "self_application": False,
            "slots": slots,
            "repositories": repos,
        }, sort_keys=True), encoding="utf-8")
        return path

    def _decisions(self, root: Path, closure: Path, **updates) -> Path:
        gates = {
            "no_self_acceptance": "PASS",
            "no_registry_apply": "PASS",
            "no_existing_main_merge": "PASS",
            "github_visibility_preserved": "PASS",
            "no_secret_or_raw_evidence_leak": "PASS",
            "memory_candidate_present": "PASS",
            "remote_readback_complete": "PASS",
        }
        obj = {
            "schema": "continuityos.memory_promotion.semantic_decisions/v1",
            "closure_receipt_sha256": hashlib.sha256(closure.read_bytes()).hexdigest(),
            "authority_generation": "R63",
            "memory_candidate_authority": "NON_AUTHORITATIVE_CANDIDATE",
            "promotion_decision": "APPROVE_PROMOTION_CANDIDATE",
            "human_irreversible_approval": False,
            "global_gates": gates,
            "slots": [{"slot": slot, "gpt_semantic_verdict": "ACCEPT"} for slot in SLOTS],
            "self_application": False,
        }
        obj.update(updates)
        path = root / "decisions.json"
        path.write_text(json.dumps(obj, sort_keys=True), encoding="utf-8")
        return path

    def test_eligible_candidate_is_proposal_only(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root); decisions=self._decisions(root,closure)
            receipt=evaluate_memory_promotion(closure,decisions)
            self.assertEqual(receipt["status"],"PROMOTION_CANDIDATE_ELIGIBLE")
            self.assertEqual(receipt["effect"],"PROPOSAL_ONLY_NO_APPLY")
            self.assertFalse(receipt["human_irreversible_approval"])

    def test_closure_hash_mismatch_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root); decisions=self._decisions(root,closure,closure_receipt_sha256="0"*64)
            self.assertEqual(evaluate_memory_promotion(closure,decisions)["status"],"PROMOTION_HOLD")

    def test_non_byte_verified_closure_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root,physical="INVALID_RETURN"); decisions=self._decisions(root,closure)
            self.assertEqual(evaluate_memory_promotion(closure,decisions)["status"],"PROMOTION_HOLD")

    def test_revise_terminal_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root,terminal=REVISE); decisions=self._decisions(root,closure)
            self.assertEqual(evaluate_memory_promotion(closure,decisions)["status"],"PROMOTION_HOLD")

    def test_missing_global_gate_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root); decisions=self._decisions(root,closure)
            obj=json.loads(decisions.read_text());obj["global_gates"].pop("remote_readback_complete");decisions.write_text(json.dumps(obj))
            self.assertEqual(evaluate_memory_promotion(closure,decisions)["status"],"PROMOTION_HOLD")

    def test_missing_slot_decision_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root); decisions=self._decisions(root,closure)
            obj=json.loads(decisions.read_text());obj["slots"].pop();decisions.write_text(json.dumps(obj))
            self.assertEqual(evaluate_memory_promotion(closure,decisions)["status"],"PROMOTION_HOLD")

    def test_accept_without_byte_verification_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root,nonbyte_slot=True); decisions=self._decisions(root,closure)
            receipt=evaluate_memory_promotion(closure,decisions)
            self.assertEqual(receipt["status"],"PROMOTION_HOLD")
            self.assertTrue(any("requires BYTE_VERIFIED" in reason for reason in receipt["reasons"]))

    def test_forged_human_approval_holds(self):
        with tempfile.TemporaryDirectory() as td:
            root=Path(td); closure=self._closure(root); decisions=self._decisions(root,closure,human_irreversible_approval=True)
            self.assertEqual(evaluate_memory_promotion(closure,decisions)["status"],"PROMOTION_HOLD")


if __name__ == "__main__":
    unittest.main()
