from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from continuityos.gate.completion_claim import HOLD, PASS, REVISE, evaluate_completion_claim
from continuityos.gate.evidence_common import fixed_effects, sha256_file


class CompletionFixture:
    def __init__(self, root: Path):
        self.root = root
        self.repo = root / "repo"
        self.repo.mkdir()
        self._run("git", "init", "-b", "main")
        self._run("git", "config", "user.name", "Test")
        self._run("git", "config", "user.email", "test@example.invalid")
        (self.repo / "README.md").write_text("baseline\n", encoding="utf-8")
        self._run("git", "add", "README.md")
        self._run("git", "commit", "-m", "baseline")
        self.base_head = self._git("rev-parse", "HEAD")
        self._run("git", "switch", "-c", "gpt/candidate")
        (self.repo / "feature.py").write_text("VALUE = 1\n", encoding="utf-8")
        self._run("git", "add", "feature.py")
        self._run("git", "commit", "-m", "candidate")
        self.head = self._git("rev-parse", "HEAD")
        self.tree = self._git("rev-parse", "HEAD^{tree}")

        self.design = root / "DESIGN.md"
        self.design.write_text("# Exact design\n", encoding="utf-8")
        self.focused_raw = root / "focused.raw.txt"
        self.full_raw = root / "full.raw.txt"
        self.focused_raw.write_text("5 passed\n", encoding="utf-8")
        self.full_raw.write_text("100 passed\n", encoding="utf-8")
        self.focused = root / "FOCUSED_TEST.json"
        self.full = root / "FULL_TEST.json"
        self._write_test(self.focused, "FOCUSED", self.focused_raw)
        self._write_test(self.full, "FULL", self.full_raw)

        self.bundle = root / "candidate.bundle"
        self._run(
            "git",
            "bundle",
            "create",
            str(self.bundle),
            "refs/heads/gpt/candidate",
        )
        self.fresh = root / "FRESH_CLONE.json"
        self.write_json(
            self.fresh,
            {
                "schema": "continuityos.completion_claim.fresh_clone_receipt/v1",
                "authority_generation": "R63",
                "bundle_sha256": sha256_file(self.bundle),
                "full_test_receipt_sha256": sha256_file(self.full),
                "candidate": {
                    "branch": "gpt/candidate",
                    "head": self.head,
                    "tree": self.tree,
                },
                "worktree_clean": True,
                "git_fsck": "PASS",
                "terminal": "FRESH_CLONE_PASS",
                "effects": fixed_effects(),
            },
        )

        self.package = root / "candidate.zip"
        self.sidecar = root / "candidate.zip.sha256"
        self.ready = root / "candidate.zip.READY_FOR_SYNC.json"
        self.build_package()

        self.exposure = root / "EXPOSURE.json"
        self.drive = root / "DRIVE.json"
        self.github = root / "GITHUB.json"
        self.ci = root / "CI.json"
        self.acceptance = root / "ACCEPTANCE.json"
        self.write_delivery_chain()

        self.request = root / "REQUEST.json"
        self.write_request()

    def _run(self, *argv: str) -> None:
        subprocess.run(argv, cwd=self.repo, check=True, text=True, capture_output=True)

    def _git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=self.repo, check=True, text=True, capture_output=True
        ).stdout.strip()

    @staticmethod
    def write_json(path: Path, value: dict) -> None:
        path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _write_test(self, path: Path, kind: str, raw: Path) -> None:
        self.write_json(
            path,
            {
                "schema": "continuityos.completion_claim.test_receipt/v1",
                "authority_generation": "R63",
                "kind": kind,
                "candidate": {
                    "branch": "gpt/candidate",
                    "head": self.head,
                    "tree": self.tree,
                },
                "terminal": "TESTS_PASS",
                "commands": [
                    {
                        "argv": ["python", "-m", "pytest", "-q"],
                        "cwd": str(self.repo),
                        "exit_code": 0,
                    }
                ],
                "evidence_files": [{"path": str(raw), "sha256": sha256_file(raw)}],
                "effects": fixed_effects(),
            },
        )

    def build_package(self, *, wrong_head: bool = False) -> None:
        payload = b"candidate source bytes\n"
        release = {
            "schema": "continuityos.completion_claim.release_receipt/v1",
            "authority_generation": "R63",
            "candidate": {
                "branch": "gpt/candidate",
                "head": "9" * 40 if wrong_head else self.head,
                "tree": self.tree,
            },
            "full_test_receipt_sha256": sha256_file(self.full),
            "bundle_sha256": sha256_file(self.bundle),
            "terminal": "RELEASE_READY",
            "effects": fixed_effects(),
        }
        release_bytes = (json.dumps(release, sort_keys=True) + "\n").encode()
        manifest = {
            "files": [
                {
                    "path": "RELEASE_RECEIPT.json",
                    "bytes": len(release_bytes),
                    "sha256": hashlib.sha256(release_bytes).hexdigest(),
                },
                {
                    "path": "SOURCE.txt",
                    "bytes": len(payload),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                },
            ]
        }
        with zipfile.ZipFile(self.package, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("RELEASE_RECEIPT.json", release_bytes)
            archive.writestr("SOURCE.txt", payload)
            archive.writestr("MANIFEST.json", json.dumps(manifest, sort_keys=True))
        digest = sha256_file(self.package)
        self.sidecar.write_text(f"{digest}  {self.package.name}\n", encoding="utf-8")
        time.sleep(0.002)
        self.write_json(
            self.ready,
            {
                "schema": "continuityos.completion_claim.package_ready/v1",
                "artifact_zip": self.package.name,
                "artifact_sha256": digest,
                "terminal": "PACKAGE_READY",
                "written_last": True,
                "candidate_head": self.head,
                "candidate_tree": self.tree,
            },
        )

    def write_delivery_chain(self) -> None:
        package_sha = sha256_file(self.package)
        self.write_json(
            self.exposure,
            {
                "schema": "continuityos.completion_claim.exposure_receipt/v1",
                "artifact_sha256": package_sha,
                "status": "USER_DOWNLOAD_EXPOSED",
                "external_readback": True,
                "channel": "CHAT_DOWNLOAD",
                "effects": fixed_effects(),
            },
        )
        self.write_json(
            self.drive,
            {
                "schema": "continuityos.completion_claim.drive_readback_receipt/v1",
                "provider": "GOOGLE_DRIVE",
                "readback": True,
                "artifact_sha256": package_sha,
                "provider_readback_sha256": package_sha,
                "provider_object_id": "drive-object-001",
                "effects": fixed_effects(),
            },
        )
        self.write_json(
            self.github,
            {
                "schema": "continuityos.completion_claim.github_readback_receipt/v1",
                "provider": "GITHUB",
                "readback": True,
                "repository": "bitmaster162/continuityos",
                "branch": "gpt/candidate",
                "remote_head": self.head,
                "remote_tree": self.tree,
                "visibility": "PUBLIC",
                "force_push": False,
                "merge": False,
                "effects": fixed_effects(),
            },
        )
        self.write_json(
            self.ci,
            {
                "schema": "continuityos.completion_claim.ci_receipt/v1",
                "provider": "GITHUB_ACTIONS",
                "github_readback_receipt_sha256": sha256_file(self.github),
                "repository": "bitmaster162/continuityos",
                "branch": "gpt/candidate",
                "head_sha": self.head,
                "required_runs": [
                    {
                        "name": "ubuntu / Python 3.11",
                        "head_sha": self.head,
                        "status": "completed",
                        "conclusion": "success",
                    },
                    {
                        "name": "windows / Python 3.11",
                        "head_sha": self.head,
                        "status": "completed",
                        "conclusion": "success",
                    },
                ],
                "effects": fixed_effects(),
            },
        )
        self.write_json(
            self.acceptance,
            {
                "schema": "continuityos.completion_claim.acceptance_receipt/v1",
                "ci_receipt_sha256": sha256_file(self.ci),
                "repository": "bitmaster162/continuityos",
                "branch": "gpt/candidate",
                "head": self.head,
                "tree": self.tree,
                "decision": "ACCEPT",
                "reviewer_role": "GPT_CONTROLLER",
                "apply_status": "NOT_APPLIED",
                "effects": fixed_effects(),
            },
        )

    def write_request(
        self,
        *,
        work_state: str = "TESTED_FULL",
        artifact_state: str = "READY_LAST_VERIFIED",
        git_state: str = "CI_VERIFIED",
        user_download_exposed: bool = True,
        drive_readback_verified: bool = True,
        accepted: bool = True,
        omit: set[str] | None = None,
    ) -> None:
        omit = omit or set()
        evidence = {
            "design": {"path": str(self.design), "sha256": sha256_file(self.design)},
            "repository": {"path": str(self.repo)},
            "focused_test_receipt": {
                "path": str(self.focused),
                "sha256": sha256_file(self.focused),
            },
            "full_test_receipt": {"path": str(self.full), "sha256": sha256_file(self.full)},
            "bundle": {
                "path": str(self.bundle),
                "sha256": sha256_file(self.bundle),
                "ref": "refs/heads/gpt/candidate",
            },
            "fresh_clone_receipt": {"path": str(self.fresh), "sha256": sha256_file(self.fresh)},
            "package": {
                "zip": str(self.package),
                "sidecar": str(self.sidecar),
                "ready": str(self.ready),
            },
            "user_exposure_receipt": {
                "path": str(self.exposure),
                "sha256": sha256_file(self.exposure),
            },
            "drive_readback_receipt": {"path": str(self.drive), "sha256": sha256_file(self.drive)},
            "github_readback_receipt": {
                "path": str(self.github),
                "sha256": sha256_file(self.github),
            },
            "ci_receipt": {"path": str(self.ci), "sha256": sha256_file(self.ci)},
            "acceptance_receipt": {
                "path": str(self.acceptance),
                "sha256": sha256_file(self.acceptance),
            },
        }
        for key in omit:
            evidence[key] = None
        self.write_json(
            self.request,
            {
                "schema": "continuityos.completion_claim.request/v1",
                "authority_generation": "R63",
                "claim_id": "CONTINUITYOS-R14-COMPLETION-CLAIM",
                "claim": {
                    "work_state": work_state,
                    "artifact_state": artifact_state,
                    "git_state": git_state,
                    "user_download_exposed": user_download_exposed,
                    "drive_readback_verified": drive_readback_verified,
                    "accepted": accepted,
                },
                "subject": {
                    "repository": "bitmaster162/continuityos",
                    "branch": "gpt/candidate",
                    "base_head": self.base_head,
                    "candidate_head": self.head,
                    "candidate_tree": self.tree,
                },
                "evidence": evidence,
                "effects": fixed_effects(),
            },
        )



class CompletionClaimTests(unittest.TestCase):
    def test_full_accepted_claim_passes(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], PASS)
            self.assertEqual(receipt["proven_state"]["work_state"], "TESTED_FULL")
            self.assertEqual(receipt["proven_state"]["artifact_state"], "READY_LAST_VERIFIED")
            self.assertEqual(receipt["proven_state"]["git_state"], "CI_VERIFIED")
            self.assertTrue(receipt["proven_state"]["accepted"])

    def test_packaged_claim_passes_without_delivery_or_github_claim(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            fx.write_request(
                artifact_state="READY_LAST_VERIFIED",
                git_state="UNPUBLISHED",
                user_download_exposed=False,
                drive_readback_verified=False,
                accepted=False,
                omit={
                    "user_exposure_receipt",
                    "drive_readback_receipt",
                    "github_readback_receipt",
                    "ci_receipt",
                    "acceptance_receipt",
                },
            )
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], PASS)
            self.assertEqual(receipt["proven_state"]["artifact_state"], "READY_LAST_VERIFIED")
            self.assertEqual(receipt["proven_state"]["git_state"], "UNPUBLISHED")

    def test_github_remote_claim_does_not_require_drive(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            fx.write_request(
                artifact_state="NONE",
                git_state="GITHUB_REMOTE_VERIFIED",
                user_download_exposed=False,
                drive_readback_verified=False,
                accepted=False,
                omit={
                    "bundle",
                    "fresh_clone_receipt",
                    "package",
                    "user_exposure_receipt",
                    "drive_readback_receipt",
                    "ci_receipt",
                    "acceptance_receipt",
                },
            )
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], PASS)
            self.assertEqual(receipt["proven_state"]["git_state"], "GITHUB_REMOTE_VERIFIED")
            self.assertFalse(receipt["proven_state"]["drive_readback_verified"])

    def test_claimed_drive_without_receipt_holds_only_delivery_dimension(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            fx.write_request(
                git_state="CI_VERIFIED",
                drive_readback_verified=True,
                accepted=False,
                omit={"drive_readback_receipt", "acceptance_receipt"},
            )
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], HOLD)
            self.assertIn("drive_readback_verified=true is not proven", receipt["unsupported_claims"])
            self.assertEqual(receipt["proven_state"]["git_state"], "CI_VERIFIED")

    def test_dirty_repository_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            (fx.repo / "README.md").write_text("dirty\n", encoding="utf-8")
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], REVISE)
            self.assertEqual(receipt["proven_state"]["work_state"], "DESIGNED")

    def test_package_wrong_head_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            fx.build_package(wrong_head=True)
            fx.write_delivery_chain()
            fx.write_request(artifact_state="PACKAGED", git_state="UNPUBLISHED", user_download_exposed=False, drive_readback_verified=False, accepted=False)
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], REVISE)
            self.assertEqual(receipt["proven_state"]["artifact_state"], "FRESH_CLONE_VERIFIED")

    def test_sidecar_mismatch_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            fx.sidecar.write_text(f"{'0' * 64}  {fx.package.name}\n", encoding="utf-8")
            fx.write_request(artifact_state="PACKAGED", git_state="UNPUBLISHED", user_download_exposed=False, drive_readback_verified=False, accepted=False)
            self.assertEqual(evaluate_completion_claim(fx.request)["status"], REVISE)

    def test_effect_widening_revises(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            request = json.loads(fx.request.read_text())
            request["effects"]["merge"] = True
            fx.write_json(fx.request, request)
            self.assertEqual(evaluate_completion_claim(fx.request)["status"], REVISE)

    def test_missing_ready_holds_artifact_dimension(self):
        with tempfile.TemporaryDirectory() as td:
            fx = CompletionFixture(Path(td))
            fx.ready.unlink()
            fx.write_request(artifact_state="READY_LAST_VERIFIED", git_state="UNPUBLISHED", user_download_exposed=False, drive_readback_verified=False, accepted=False)
            receipt = evaluate_completion_claim(fx.request)
            self.assertEqual(receipt["status"], HOLD)
            self.assertEqual(receipt["proven_state"]["artifact_state"], "PACKAGED")
            self.assertIn("artifact_state=READY_LAST_VERIFIED exceeds proven artifact state", receipt["unsupported_claims"])


if __name__ == "__main__":
    unittest.main()
