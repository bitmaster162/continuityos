"""Fail-closed verification of host-closure and GitHub transition returns.

The verifier is intentionally effect-free.  It verifies a strict ZIP/SHA/READY
triplet, exact task/terminal binding, a nine-slot recovery matrix, GitHub remote
readbacks, source-boundary receipts and manifest integrity.  It never applies a
registry delta, changes R63, pushes Git, merges, deploys or trades.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import stat
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA = "continuityos.github_transition.receipt/v1"
DEFAULT_TASK_ID = "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_R1"
ALLOWED_TERMINALS = {
    "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_COMPLETE",
    "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_REVISE",
}
PHYSICAL_STATUSES = {
    "BYTE_VERIFIED",
    "TRIPLET_INCOMPLETE",
    "TASK_BINDING_INCOMPLETE",
    "INVALID_RETURN",
    "NOT_FOUND",
}
SLOTS = tuple([f"CODEX-{i:02d}" for i in range(1, 9)] + ["WORK"])
SLOT_STATUSES = {
    "BYTE_VERIFIED",
    "TRIPLET_INCOMPLETE",
    "REPORTED_ONLY",
    "TASK_BINDING_INCOMPLETE",
    "INVALID_RETURN",
    "NOT_FOUND",
}
REQUIRED_MEMBERS = (
    "RETURN_ENVELOPE.json",
    "TERMINAL_STATE.json",
    "HOST_RETURN_RECOVERY_MATRIX.json",
    "GITHUB_REPO_REGISTRY.json",
    "GITHUB_TRANSPORT_MATRIX.csv",
    "GITHUB_NO_SECRET_RECEIPT.json",
    "NO_EFFECT_RECEIPT.json",
    "TEARDOWN_RECEIPT.json",
    "MANIFEST.json",
)
REQUIRED_WAVE_A = {
    "control-memory",
    "continuityos",
    "control-center",
    "control-return-broker",
    "agent-return-broker",
    "edge-desk-controller",
    "trading-edge-research",
    "tradingos-measurement",
}
MAX_MEMBERS = 2_000
MAX_MEMBER_BYTES = 256 * 1024 * 1024
MAX_TOTAL_BYTES = 1024 * 1024 * 1024
MAX_COMPRESSION_RATIO = 250.0
SHA_RE = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _check(checks: list[dict[str, Any]], check_id: str, status: str, detail: str, **evidence: Any) -> None:
    row: dict[str, Any] = {"id": check_id, "status": status, "detail": detail}
    if evidence:
        row["evidence"] = evidence
    checks.append(row)


def _parse_sidecar(path: Path) -> str | None:
    if not path.is_file():
        return None
    match = re.search(r"\b([0-9a-fA-F]{64})\b", path.read_text(encoding="utf-8", errors="replace"))
    return match.group(1).lower() if match else None


def _load_json_bytes(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8-sig"))
    except Exception as exc:  # pragma: no cover - message is tested indirectly
        raise ValueError(f"{label} is not valid UTF-8 JSON: {type(exc).__name__}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def _load_json_path(path: Path, label: str) -> dict[str, Any]:
    return _load_json_bytes(path.read_bytes(), label)


def _safe_member_name(name: str) -> bool:
    if not name or "\\" in name or "\x00" in name:
        return False
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in {"", ".", ".."} for part in p.parts):
        return False
    if re.match(r"^[A-Za-z]:", name):
        return False
    return True


def _is_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (info.external_attr >> 16) & 0o177777
    return stat.S_ISLNK(mode)


def _member_by_basename(names: Iterable[str], basename: str) -> str:
    matches = [name for name in names if PurePosixPath(name).name == basename]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {basename}, found {len(matches)}")
    return matches[0]


def _manifest_entries(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    value = manifest.get("files", manifest.get("manifest"))
    if not isinstance(value, list):
        raise ValueError("MANIFEST.json must contain a files list")
    out: list[dict[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, dict):
            raise ValueError(f"manifest entry {index} must be an object")
        rel = row.get("path", row.get("file"))
        digest = row.get("sha256")
        size = row.get("bytes", row.get("size_bytes"))
        if not isinstance(rel, str) or not _safe_member_name(rel):
            raise ValueError(f"manifest entry {index} has invalid path")
        if not isinstance(digest, str) or not SHA_RE.fullmatch(digest.lower()):
            raise ValueError(f"manifest entry {index} has invalid sha256")
        if not isinstance(size, int) or size < 0:
            raise ValueError(f"manifest entry {index} has invalid bytes")
        out.append({"path": rel, "sha256": digest.lower(), "bytes": size})
    return out


def _resolve_manifest_member(manifest_member: str, rel: str, names: set[str]) -> str:
    base = PurePosixPath(manifest_member).parent
    candidates = []
    for candidate in (str(base / rel), rel):
        if candidate in names and candidate not in candidates:
            candidates.append(candidate)
    if len(candidates) != 1:
        raise ValueError(f"manifest path {rel!r} resolves to {len(candidates)} members")
    return candidates[0]


def _normalize_repo_rows(registry: dict[str, Any]) -> list[dict[str, Any]]:
    value = registry.get("repositories", registry.get("repos"))
    if not isinstance(value, list):
        raise ValueError("GITHUB_REPO_REGISTRY.json must contain repositories")
    rows: list[dict[str, Any]] = []
    names: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"repository row {index} must be an object")
        name = raw.get("name", raw.get("repo"))
        if isinstance(name, str) and "/" in name:
            name = name.rsplit("/", 1)[-1]
        if not isinstance(name, str) or not name:
            raise ValueError(f"repository row {index} has no name")
        if name in names:
            raise ValueError(f"duplicate repository row: {name}")
        names.add(name)
        row = dict(raw)
        row["name"] = name
        rows.append(row)
    return rows


def _verify_repo_rows(rows: list[dict[str, Any]], terminal: str) -> list[str]:
    errors: list[str] = []
    present = {row["name"] for row in rows}
    if terminal == "FINAL_HOST_CLOSURE_AND_GITHUB_TRANSITION_COMPLETE":
        missing = sorted(REQUIRED_WAVE_A - present)
        if missing:
            errors.append("missing mandatory Wave A repositories: " + ", ".join(missing))
    for row in rows:
        name = row["name"]
        preexisting = row.get("preexisting")
        before = row.get("visibility_before")
        after = row.get("visibility_after", row.get("visibility"))
        if preexisting is True:
            if before not in {"PUBLIC", "PRIVATE"} or after != before:
                errors.append(f"{name}: existing repository visibility was not preserved")
            if row.get("default_branch_modified") is not False:
                errors.append(f"{name}: existing default branch modification is not denied")
        elif preexisting is False:
            if after != "PRIVATE":
                errors.append(f"{name}: newly created repository must be PRIVATE")
        else:
            errors.append(f"{name}: preexisting must be boolean")
        local_head = row.get("local_head")
        remote_head = row.get("remote_head")
        local_tree = row.get("local_tree")
        remote_tree = row.get("remote_tree")
        for label, value in (("local_head", local_head), ("remote_head", remote_head), ("local_tree", local_tree), ("remote_tree", remote_tree)):
            if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
                errors.append(f"{name}: invalid {label}")
        if local_head != remote_head:
            errors.append(f"{name}: remote HEAD does not equal local HEAD")
        if local_tree != remote_tree:
            errors.append(f"{name}: remote tree does not equal local tree")
        if row.get("force_push") is not False:
            errors.append(f"{name}: force_push must be false")
        if row.get("merged_into_existing_default") is not False:
            errors.append(f"{name}: merge into existing default must be false")
        if row.get("secret_scan") != "PASS":
            errors.append(f"{name}: secret_scan is not PASS")
    return errors


def _parse_transport_csv(data: bytes) -> dict[str, dict[str, str]]:
    text = data.decode("utf-8-sig", errors="strict")
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("GITHUB_TRANSPORT_MATRIX.csv has no header")
    result: dict[str, dict[str, str]] = {}
    for row in reader:
        name = row.get("name") or row.get("repo") or row.get("repository")
        if not name:
            raise ValueError("transport matrix row has no repository name")
        if "/" in name:
            name = name.rsplit("/", 1)[-1]
        if name in result:
            raise ValueError(f"duplicate transport matrix row: {name}")
        result[name] = {str(k): str(v) for k, v in row.items()}
    return result


def _verify_transport_crosscheck(repo_rows: list[dict[str, Any]], matrix: dict[str, dict[str, str]]) -> list[str]:
    errors: list[str] = []
    by_name = {row["name"]: row for row in repo_rows}
    if set(matrix) != set(by_name):
        errors.append("GitHub transport matrix repository set differs from registry")
        return errors
    for name, row in by_name.items():
        m = matrix[name]
        if m.get("local_head") != row.get("local_head"):
            errors.append(f"{name}: transport local_head differs from registry")
        if m.get("remote_head") != row.get("remote_head"):
            errors.append(f"{name}: transport remote_head differs from registry")
        if m.get("local_tree") != row.get("local_tree"):
            errors.append(f"{name}: transport local_tree differs from registry")
        if m.get("remote_tree") != row.get("remote_tree"):
            errors.append(f"{name}: transport remote_tree differs from registry")
    return errors


def _extract_slots(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    value = matrix.get("slots")
    if isinstance(value, dict):
        value = [{"slot": key, **(row if isinstance(row, dict) else {})} for key, row in value.items()]
    if not isinstance(value, list):
        raise ValueError("HOST_RETURN_RECOVERY_MATRIX.json must contain slots")
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ValueError(f"slot row {index} must be an object")
        slot = raw.get("slot")
        if slot not in SLOTS or slot in seen:
            raise ValueError(f"invalid or duplicate slot: {slot!r}")
        seen.add(slot)
        physical = raw.get("physical_status")
        if physical not in SLOT_STATUSES:
            raise ValueError(f"{slot}: invalid physical_status {physical!r}")
        if raw.get("content_status") != "UNREVIEWED":
            raise ValueError(f"{slot}: content_status must remain UNREVIEWED")
        if raw.get("apply_status") != "NOT_APPLIED":
            raise ValueError(f"{slot}: apply_status must remain NOT_APPLIED")
        rows.append(dict(raw))
    missing = sorted(set(SLOTS) - seen)
    if missing:
        raise ValueError("missing slots: " + ", ".join(missing))
    return rows


def _verify_no_effect(receipt: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    false_fields = (
        "registry_apply",
        "r63_apply",
        "current_state_apply",
        "deployment",
        "force_push",
        "existing_main_or_master_modified",
        "merged",
        "trade_wallet_order_or_capital_effect",
        "self_application",
    )
    for field in false_fields:
        if receipt.get(field) is not False:
            errors.append(f"NO_EFFECT_RECEIPT.json: {field} must be false")
    if receipt.get("can_trade") is not False:
        errors.append("NO_EFFECT_RECEIPT.json: can_trade must be false")
    if receipt.get("capital_permission") != "DENY":
        errors.append("NO_EFFECT_RECEIPT.json: capital_permission must be DENY")
    if receipt.get("deploy_permission") != "DENY":
        errors.append("NO_EFFECT_RECEIPT.json: deploy_permission must be DENY")
    return errors


def _classify(fail_classes: set[str], zip_exists: bool) -> str:
    if not zip_exists:
        return "NOT_FOUND"
    if "triplet" in fail_classes:
        return "TRIPLET_INCOMPLETE"
    # Structural/content corruption outranks a derived binding failure.  A
    # duplicate or ambiguous envelope must never be described as merely
    # incomplete task metadata.
    if "content" in fail_classes:
        return "INVALID_RETURN"
    if "binding" in fail_classes:
        return "TASK_BINDING_INCOMPLETE"
    if fail_classes:
        return "INVALID_RETURN"
    return "BYTE_VERIFIED"


def verify_github_transition_return(
    zip_path: Path,
    sidecar_path: Path,
    ready_path: Path,
    *,
    expected_task_body_sha256: str,
    expected_task_id: str = DEFAULT_TASK_ID,
) -> dict[str, Any]:
    """Verify one strict host-closure transition return without effects."""
    zip_path = Path(zip_path)
    sidecar_path = Path(sidecar_path)
    ready_path = Path(ready_path)
    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    fail_classes: set[str] = set()
    terminal: str | None = None
    slots: list[dict[str, Any]] = []
    repositories: list[dict[str, Any]] = []

    if not SHA_RE.fullmatch(str(expected_task_body_sha256).lower()):
        raise ValueError("expected_task_body_sha256 must be exactly 64 lowercase hex characters")
    expected_task_body_sha256 = expected_task_body_sha256.lower()

    if not zip_path.is_file():
        _check(checks, "ZIP_EXISTS", "FAIL", "return ZIP not found", path=str(zip_path))
        failures.append("return ZIP not found")
        return {
            "schema": SCHEMA,
            "generated_at_utc": datetime.now(timezone.utc).isoformat(),
            "physical_status": "NOT_FOUND",
            "terminal": None,
            "zip_sha256": None,
            "checks": checks,
            "failures": failures,
            "slots": slots,
            "repositories": repositories,
            "live_state_modified": False,
            "can_trade": False,
            "capital_permission": "DENY",
            "deploy_permission": "DENY",
            "self_application": False,
        }

    zip_sha = sha256_file(zip_path)
    _check(checks, "ZIP_EXISTS", "PASS", "return ZIP exists", bytes=zip_path.stat().st_size)
    sidecar_sha = _parse_sidecar(sidecar_path)
    if sidecar_sha != zip_sha:
        fail_classes.add("triplet")
        failures.append("sidecar SHA is absent or does not match the ZIP")
        _check(checks, "SIDECAR_SHA", "FAIL", failures[-1], observed=sidecar_sha, actual=zip_sha)
    else:
        _check(checks, "SIDECAR_SHA", "PASS", "sidecar SHA matches ZIP", sha256=zip_sha)

    ready: dict[str, Any] | None = None
    try:
        ready = _load_json_path(ready_path, "READY")
    except Exception as exc:
        fail_classes.add("triplet")
        failures.append(str(exc))
        _check(checks, "READY", "FAIL", str(exc))
    if ready is not None:
        ready_errors: list[str] = []
        if ready.get("artifact_zip") != zip_path.name:
            ready_errors.append("READY artifact_zip does not match ZIP filename")
        if str(ready.get("artifact_sha256", "")).lower() != zip_sha:
            ready_errors.append("READY artifact_sha256 does not match ZIP")
        terminal = ready.get("terminal_status", ready.get("terminal"))
        if terminal not in ALLOWED_TERMINALS:
            ready_errors.append("READY terminal is not an allowed exact terminal")
        if ready.get("written_last") is not True:
            ready_errors.append("READY written_last must be true")
        if ready_errors:
            fail_classes.add("triplet")
            failures.extend(ready_errors)
            _check(checks, "READY", "FAIL", "; ".join(ready_errors))
        else:
            _check(checks, "READY", "PASS", "READY identity, hash and terminal match")

    objects: dict[str, dict[str, Any]] = {}
    member_data: dict[str, bytes] = {}
    names: list[str] = []
    member_map: dict[str, str] = {}
    transport_matrix: dict[str, dict[str, str]] = {}

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            names = [info.filename for info in infos if not info.is_dir()]
            zip_errors: list[str] = []
            if len(infos) > MAX_MEMBERS:
                zip_errors.append(f"member count exceeds {MAX_MEMBERS}")
            seen: set[str] = set()
            folded: dict[str, str] = {}
            total = 0
            for info in infos:
                if info.is_dir():
                    continue
                if not _safe_member_name(info.filename):
                    zip_errors.append(f"unsafe member path: {info.filename}")
                if info.filename in seen:
                    zip_errors.append(f"duplicate member: {info.filename}")
                seen.add(info.filename)
                key = info.filename.casefold()
                if key in folded and folded[key] != info.filename:
                    zip_errors.append(f"case-fold collision: {folded[key]} vs {info.filename}")
                folded[key] = info.filename
                if _is_symlink(info):
                    zip_errors.append(f"symlink member denied: {info.filename}")
                if info.file_size > MAX_MEMBER_BYTES:
                    zip_errors.append(f"member too large: {info.filename}")
                total += info.file_size
                if info.file_size and info.compress_size == 0:
                    zip_errors.append(f"invalid zero compressed size: {info.filename}")
                elif info.compress_size:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO:
                        zip_errors.append(f"compression ratio too high: {info.filename}")
            if total > MAX_TOTAL_BYTES:
                zip_errors.append(f"total uncompressed bytes exceed {MAX_TOTAL_BYTES}")
            # Do not decompress attacker-controlled members until metadata-only
            # path/type/size/ratio gates have passed.  This ordering is part of
            # the bomb-resistance contract, not an optimization.
            if not zip_errors and zf.testzip() is not None:
                zip_errors.append("ZIP CRC check failed")
            if zip_errors:
                fail_classes.add("content")
                failures.extend(zip_errors)
                _check(checks, "ZIP_SAFETY", "FAIL", "; ".join(zip_errors[:20]))
            else:
                _check(checks, "ZIP_SAFETY", "PASS", "CRC, paths, links and size ceilings pass", members=len(names), uncompressed_bytes=total)

            for basename in REQUIRED_MEMBERS:
                try:
                    member_map[basename] = _member_by_basename(names, basename)
                except ValueError as exc:
                    fail_classes.add("content")
                    failures.append(str(exc))
            if len(member_map) == len(REQUIRED_MEMBERS):
                _check(checks, "REQUIRED_MEMBERS", "PASS", "all required members are present exactly once")
            else:
                _check(checks, "REQUIRED_MEMBERS", "FAIL", "required members are missing or ambiguous")

            for basename, member in member_map.items():
                member_data[basename] = zf.read(member)
                if basename.endswith(".json"):
                    try:
                        objects[basename] = _load_json_bytes(member_data[basename], basename)
                    except ValueError as exc:
                        fail_classes.add("content")
                        failures.append(str(exc))

            if "GITHUB_TRANSPORT_MATRIX.csv" in member_data:
                try:
                    transport_matrix = _parse_transport_csv(member_data["GITHUB_TRANSPORT_MATRIX.csv"])
                except Exception as exc:
                    fail_classes.add("content")
                    failures.append(str(exc))

            manifest = objects.get("MANIFEST.json")
            if manifest is not None:
                try:
                    entries = _manifest_entries(manifest)
                    all_names = set(names)
                    covered: set[str] = set()
                    manifest_member = member_map["MANIFEST.json"]
                    for entry in entries:
                        resolved = _resolve_manifest_member(manifest_member, entry["path"], all_names)
                        data = zf.read(resolved)
                        if len(data) != entry["bytes"]:
                            raise ValueError(f"manifest size mismatch: {entry['path']}")
                        if sha256_bytes(data) != entry["sha256"]:
                            raise ValueError(f"manifest SHA mismatch: {entry['path']}")
                        covered.add(resolved)
                    required_coverage = {member for base, member in member_map.items() if base != "MANIFEST.json"}
                    missing_coverage = sorted(required_coverage - covered)
                    if missing_coverage:
                        raise ValueError("manifest omits required evidence: " + ", ".join(missing_coverage))
                    _check(checks, "MANIFEST", "PASS", "manifest hashes, sizes and required coverage pass", entries=len(entries))
                except Exception as exc:
                    fail_classes.add("content")
                    failures.append(str(exc))
                    _check(checks, "MANIFEST", "FAIL", str(exc))
    except zipfile.BadZipFile as exc:
        fail_classes.add("content")
        failures.append(f"bad ZIP: {exc}")
        _check(checks, "ZIP_OPEN", "FAIL", failures[-1])

    envelope = objects.get("RETURN_ENVELOPE.json")
    terminal_state = objects.get("TERMINAL_STATE.json")
    binding_errors: list[str] = []
    if envelope is not None:
        if envelope.get("task_id") != expected_task_id:
            binding_errors.append("RETURN_ENVELOPE task_id mismatch")
        if str(envelope.get("task_body_sha256", "")).lower() != expected_task_body_sha256:
            binding_errors.append("RETURN_ENVELOPE task_body_sha256 mismatch")
        envelope_terminal = envelope.get("terminal")
        if terminal is not None and envelope_terminal != terminal:
            binding_errors.append("RETURN_ENVELOPE terminal differs from READY")
    else:
        binding_errors.append("RETURN_ENVELOPE.json could not be parsed")
    if terminal_state is not None:
        state_terminal = terminal_state.get("terminal")
        if state_terminal != terminal:
            binding_errors.append("TERMINAL_STATE terminal differs from READY")
        if terminal_state.get("task_id") != expected_task_id:
            binding_errors.append("TERMINAL_STATE task_id mismatch")
        if str(terminal_state.get("task_body_sha256", "")).lower() != expected_task_body_sha256:
            binding_errors.append("TERMINAL_STATE task_body_sha256 mismatch")
    else:
        binding_errors.append("TERMINAL_STATE.json could not be parsed")
    if binding_errors:
        fail_classes.add("binding")
        failures.extend(binding_errors)
        _check(checks, "TASK_AND_TERMINAL_BINDING", "FAIL", "; ".join(binding_errors))
    else:
        _check(checks, "TASK_AND_TERMINAL_BINDING", "PASS", "task body and exact terminal agree across triplet")

    matrix = objects.get("HOST_RETURN_RECOVERY_MATRIX.json")
    if matrix is not None:
        try:
            slots = _extract_slots(matrix)
            _check(checks, "SLOT_MATRIX", "PASS", "all nine slots are present with non-applied content", slots=len(slots))
        except Exception as exc:
            fail_classes.add("content")
            failures.append(str(exc))
            _check(checks, "SLOT_MATRIX", "FAIL", str(exc))

    registry = objects.get("GITHUB_REPO_REGISTRY.json")
    if registry is not None:
        try:
            repositories = _normalize_repo_rows(registry)
            repo_errors = _verify_repo_rows(repositories, terminal or "")
            repo_errors.extend(_verify_transport_crosscheck(repositories, transport_matrix))
            if repo_errors:
                raise ValueError("; ".join(repo_errors))
            _check(checks, "GITHUB_READBACK", "PASS", "visibility, branch and remote HEAD/tree readbacks pass", repositories=len(repositories))
        except Exception as exc:
            fail_classes.add("content")
            failures.append(str(exc))
            _check(checks, "GITHUB_READBACK", "FAIL", str(exc))

    secret_receipt = objects.get("GITHUB_NO_SECRET_RECEIPT.json")
    if secret_receipt is not None:
        if secret_receipt.get("status") == "PASS" and secret_receipt.get("findings") == 0:
            _check(checks, "SECRET_BOUNDARY", "PASS", "no-secret/raw-evidence receipt passes")
        else:
            fail_classes.add("content")
            failures.append("GITHUB_NO_SECRET_RECEIPT.json is not PASS with zero findings")
            _check(checks, "SECRET_BOUNDARY", "FAIL", failures[-1])

    no_effect = objects.get("NO_EFFECT_RECEIPT.json")
    if no_effect is not None:
        effect_errors = _verify_no_effect(no_effect)
        if effect_errors:
            fail_classes.add("content")
            failures.extend(effect_errors)
            _check(checks, "NO_EFFECT", "FAIL", "; ".join(effect_errors))
        else:
            _check(checks, "NO_EFFECT", "PASS", "no apply, merge, deployment or financial effect")

    teardown = objects.get("TEARDOWN_RECEIPT.json")
    if teardown is not None:
        if teardown.get("temporary_workspace_removed") is True and teardown.get("active_processes_left") == 0:
            _check(checks, "TEARDOWN", "PASS", "temporary workspace and child processes were cleaned")
        else:
            fail_classes.add("content")
            failures.append("TEARDOWN_RECEIPT.json does not prove cleanup")
            _check(checks, "TEARDOWN", "FAIL", failures[-1])

    physical = _classify(fail_classes, True)
    return {
        "schema": SCHEMA,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "physical_status": physical,
        "terminal": terminal,
        "zip_path": str(zip_path),
        "zip_sha256": zip_sha,
        "expected_task_id": expected_task_id,
        "expected_task_body_sha256": expected_task_body_sha256,
        "checks": checks,
        "failures": failures,
        "slots": slots,
        "repositories": repositories,
        "effect": "VERIFY_ONLY_NO_APPLY",
        "live_state_modified": False,
        "registry_apply": False,
        "r63_apply": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
        "self_application": False,
    }


def exit_code_for_github_transition(receipt: dict[str, Any]) -> int:
    return 0 if receipt.get("physical_status") == "BYTE_VERIFIED" else 2
