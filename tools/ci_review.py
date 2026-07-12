"""Stdlib-only helpers for the local-only review CI workflow.

The helpers deliberately avoid shells and never print credential-like matches.  The
index scanner reads Git blobs by object id, so its manifest and scan describe the
exact index rather than a potentially different working-tree file.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import sysconfig
import time
import venv
from pathlib import Path


SECRET_PATTERNS = {
    "private_key": re.compile(
        rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"
    ),
    "aws_access_key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "github_token": re.compile(
        rb"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})"
    ),
    "openai_key": re.compile(rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}"),
    "anthropic_key": re.compile(rb"sk-ant-[A-Za-z0-9_-]{32,}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
    "google_api_key": re.compile(rb"AIza[0-9A-Za-z_-]{35}"),
    "stripe_live_key": re.compile(rb"[rs]k_live_[0-9A-Za-z]{20,}"),
}


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None):
    started = time.time()
    completed = subprocess.run(
        command,
        cwd=str(cwd),
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    return completed, round(time.time() - started, 3)


def _emit_completed(completed: subprocess.CompletedProcess[str]) -> None:
    if completed.stdout:
        print(completed.stdout, end="" if completed.stdout.endswith("\n") else "\n")
    if completed.stderr:
        print(
            completed.stderr,
            end="" if completed.stderr.endswith("\n") else "\n",
            file=sys.stderr,
        )


def command_receipt(args: argparse.Namespace) -> int:
    command = list(args.command)
    if command and command[0] == "--":
        command.pop(0)
    if not command:
        raise SystemExit("run requires a command after --")
    completed, duration = _run(command, cwd=Path.cwd())
    _emit_completed(completed)
    _write_json(
        Path(args.output),
        {
            "schema": "continuityos-ci-command-receipt-v1",
            "command": command,
            "cwd": str(Path.cwd().resolve()),
            "duration_seconds": duration,
            "exit_code": completed.returncode,
            "platform": platform.platform(),
            "python": sys.version,
            "status": "PASS" if completed.returncode == 0 else "FAIL",
            "stderr": completed.stderr,
            "stdout": completed.stdout,
        },
    )
    return completed.returncode


def metadata_receipt(args: argparse.Namespace) -> int:
    output = Path(args.output)
    source_root = Path(args.source_root).resolve()
    try:
        distribution = importlib.metadata.distribution("continuityos")
    except importlib.metadata.PackageNotFoundError:
        distribution = None

    package_path = None
    failure = ""
    if args.mode == "absent":
        if distribution is not None:
            failure = "continuityos distribution metadata is installed"
        else:
            source_text = str(source_root)
            if source_text not in sys.path:
                sys.path.insert(0, source_text)
            try:
                import continuityos
            except Exception as exc:
                failure = (
                    "clean source import failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                package_path = Path(continuityos.__file__).resolve()
                if source_root not in package_path.parents:
                    failure = "source import did not resolve inside the checkout"
    else:
        if distribution is None:
            failure = "continuityos distribution metadata is absent"
        else:
            try:
                import continuityos
            except Exception as exc:
                failure = (
                    "editable import failed: "
                    f"{type(exc).__name__}: {exc}"
                )
            else:
                package_path = Path(continuityos.__file__).resolve()
                if source_root not in package_path.parents:
                    failure = "editable import did not resolve inside the checkout"

    payload = {
        "schema": "continuityos-ci-metadata-receipt-v1",
        "mode": args.mode,
        "metadata_present": distribution is not None,
        "metadata_version": distribution.version if distribution is not None else None,
        "package_path": str(package_path) if package_path is not None else None,
        "source_root": str(source_root),
        "status": "FAIL" if failure else "PASS",
        "failure": failure,
    }
    _write_json(output, payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 1 if failure else 0


def _git(root: Path, *arguments: str, text: bool = False):
    return subprocess.run(
        ["git", *arguments],
        cwd=str(root),
        check=True,
        capture_output=True,
        text=text,
        encoding="utf-8" if text else None,
    ).stdout


def exact_index(args: argparse.Namespace) -> int:
    root = Path(
        _git(Path.cwd(), "rev-parse", "--show-toplevel", text=True).strip()
    ).resolve()
    raw_entries = _git(root, "ls-files", "--stage", "-z")
    entries = []
    findings = []
    allowlisted_fixtures = []
    seen_paths = set()

    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        metadata, raw_path = raw_entry.split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        path = raw_path.decode("utf-8", errors="surrogateescape")
        if stage != "0":
            raise SystemExit(f"unmerged index entry is not reviewable: {path}")
        if mode == "160000":
            raise SystemExit(f"gitlink content is not covered by the exact scan: {path}")
        if path in seen_paths:
            raise SystemExit(f"duplicate index entry: {path}")
        seen_paths.add(path)
        content = _git(root, "cat-file", "blob", object_id)
        entries.append(
            {
                "mode": mode,
                "object_id": object_id,
                "path": path,
                "sha256": _sha256(content),
                "size": len(content),
            }
        )

        name = Path(path).name.lower()
        if name == ".env" or name.startswith(".env."):
            findings.append({"path": path, "pattern": "tracked_dotenv", "offset": 0})
        for pattern_name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(content):
                # AWS publishes this suffix as a non-secret documentation example;
                # retain a precise, auditable exception for the governance corpus.
                if pattern_name == "aws_access_key" and match.group().endswith(b"EXAMPLE"):
                    allowlisted_fixtures.append(
                        {"path": path, "pattern": pattern_name, "offset": match.start()}
                    )
                    continue
                findings.append(
                    {"path": path, "pattern": pattern_name, "offset": match.start()}
                )

    entries.sort(key=lambda item: item["path"])
    findings.sort(key=lambda item: (item["path"], item["offset"], item["pattern"]))
    allowlisted_fixtures.sort(
        key=lambda item: (item["path"], item["offset"], item["pattern"])
    )
    head = _git(root, "rev-parse", "HEAD", text=True).strip()
    manifest_path = Path(args.manifest)
    manifest = {
        "schema": "continuityos-exact-git-index-manifest-v1",
        "head": head,
        "entry_count": len(entries),
        "entries": entries,
    }
    _write_json(manifest_path, manifest)
    manifest_sha = _sha256_file(manifest_path)
    manifest_path.with_name(manifest_path.name + ".sha256").write_text(
        f"{manifest_sha}  {manifest_path.name}\n", encoding="ascii", newline="\n"
    )

    scan = {
        "schema": "continuityos-exact-index-secret-scan-v1",
        "exact_index_manifest_sha256": manifest_sha,
        "patterns": sorted([*SECRET_PATTERNS, "tracked_dotenv"]),
        "scanned_entries": len(entries),
        "allowlisted_fixture_count": len(allowlisted_fixtures),
        "allowlisted_fixtures": allowlisted_fixtures,
        "finding_count": len(findings),
        "findings": findings,
        "status": "PASS" if not findings else "FAIL",
    }
    _write_json(Path(args.scan_output), scan)
    print(json.dumps(scan, ensure_ascii=False, sort_keys=True))
    return 1 if findings else 0


def collect_nodeids(args: argparse.Namespace) -> int:
    command = [sys.executable, "-m", "pytest", "--collect-only", "-q"]
    completed, duration = _run(command, cwd=Path.cwd())
    _emit_completed(completed)
    nodeids = sorted(
        line.strip()
        for line in completed.stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    )
    serialized = "".join(f"{nodeid}\n" for nodeid in nodeids).encode("utf-8")
    failure = ""
    if completed.returncode != 0:
        failure = "pytest collection failed"
    elif not nodeids:
        failure = "pytest returned no parseable node IDs"
    payload = {
        "schema": "continuityos-pytest-nodeids-v1",
        "command": command,
        "duration_seconds": duration,
        "exit_code": completed.returncode,
        "node_count": len(nodeids),
        "nodeids_sha256": _sha256(serialized),
        "nodeids": nodeids,
        "status": "FAIL" if failure else "PASS",
        "failure": failure,
        "stderr": completed.stderr,
    }
    _write_json(Path(args.output), payload)
    print(
        json.dumps(
            {key: payload[key] for key in ("status", "node_count", "nodeids_sha256")},
            sort_keys=True,
        )
    )
    return 1 if failure else 0


def wheel_test(args: argparse.Namespace) -> int:
    source_root = Path(args.source_root).resolve()
    wheel_dir = Path(args.wheel_dir).resolve()
    test_wheel_dir = Path(args.test_wheel_dir).resolve()
    wheels = sorted(wheel_dir.glob("*.whl"))
    if len(wheels) != 1:
        raise SystemExit(f"expected exactly one wheel in {wheel_dir}, found {len(wheels)}")
    wheel = wheels[0]
    workspace = Path(args.workspace).resolve()
    if source_root == workspace or source_root in workspace.parents:
        raise SystemExit("wheel workspace must be outside the checkout")
    if workspace.exists() and any(workspace.iterdir()):
        raise SystemExit(f"wheel workspace is not empty: {workspace}")
    workspace.mkdir(parents=True, exist_ok=True)

    suite = workspace / "suite"
    shutil.copytree(source_root / "tests", suite / "tests")
    shutil.copy2(source_root / "gate_hook.py", suite / "gate_hook.py")
    venv_dir = workspace / "venv"
    venv.EnvBuilder(with_pip=True, system_site_packages=False).create(venv_dir)
    python = venv_dir / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    child_env = dict(os.environ)
    child_env.pop("PYTHONPATH", None)
    child_env["PYTHONNOUSERSITE"] = "1"
    child_env["PYTHONUTF8"] = "1"

    commands = []
    tooling_command = [
        str(python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--find-links",
        str(test_wheel_dir),
        "pytest==9.1.1",
    ]
    tooled, tooling_duration = _run(tooling_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "install_isolated_test_tooling",
            "command": tooling_command,
            "duration_seconds": tooling_duration,
            "exit_code": tooled.returncode,
            "stdout": tooled.stdout,
            "stderr": tooled.stderr,
        }
    )
    _emit_completed(tooled)

    install_command = [
        str(python),
        "-m",
        "pip",
        "install",
        "--no-index",
        "--no-deps",
        "--force-reinstall",
        str(wheel),
    ]
    installed, install_duration = _run(install_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "install_wheel",
            "command": install_command,
            "duration_seconds": install_duration,
            "exit_code": installed.returncode,
            "stdout": installed.stdout,
            "stderr": installed.stderr,
        }
    )
    _emit_completed(installed)

    probe_code = f"""
import importlib.metadata, json, pathlib, sys, sysconfig
import continuityos
package_path = pathlib.Path(continuityos.__file__).resolve()
purelib = pathlib.Path(sysconfig.get_paths()["purelib"]).resolve()
source_root = pathlib.Path({str(source_root)!r}).resolve()
resolved_sys_path = []
for entry in sys.path:
    try:
        resolved_sys_path.append(str(pathlib.Path(entry or '.').resolve()))
    except OSError:
        resolved_sys_path.append(entry)
if str(source_root) in resolved_sys_path:
    raise SystemExit(f"source checkout leaked into wheel sys.path: {{source_root}}")
if purelib not in package_path.parents:
    raise SystemExit(f"wheel import is not under site-packages: {{package_path}}")
metadata_version = importlib.metadata.version("continuityos")
if continuityos.__version__ != metadata_version:
    raise SystemExit("wheel package and distribution versions disagree")
print(json.dumps({{"package_path": str(package_path), "purelib": str(purelib),
                  "package_version": continuityos.__version__,
                  "metadata_version": metadata_version,
                  "sys_path": resolved_sys_path}}, sort_keys=True))
"""
    probe_command = [str(python), "-c", probe_code]
    probed, probe_duration = _run(probe_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "site_packages_probe",
            "command": [str(python), "-c", "<site-packages assertion>"],
            "duration_seconds": probe_duration,
            "exit_code": probed.returncode,
            "stdout": probed.stdout,
            "stderr": probed.stderr,
        }
    )
    _emit_completed(probed)

    test_command = [
        str(python),
        "-m",
        "pytest",
        "-q",
        "--import-mode=importlib",
        "tests",
        "--ignore=tests/test_ci_review_tool.py",
        "--ignore=tests/test_version_consistency.py",
        "--ignore=tests/test_packaging_hygiene.py",
    ]
    tested, test_duration = _run(test_command, cwd=suite, env=child_env)
    commands.append(
        {
            "name": "wheel_only_tests",
            "command": test_command,
            "duration_seconds": test_duration,
            "exit_code": tested.returncode,
            "stdout": tested.stdout,
            "stderr": tested.stderr,
        }
    )
    _emit_completed(tested)

    probe_payload = None
    if probed.returncode == 0 and probed.stdout.strip():
        try:
            probe_payload = json.loads(probed.stdout.strip().splitlines()[-1])
        except json.JSONDecodeError:
            pass
    source_root_excluded = bool(
        probe_payload
        and str(source_root) not in probe_payload.get("sys_path", [])
    )
    passed = (
        all(item["exit_code"] == 0 for item in commands)
        and source_root_excluded
    )
    _write_json(
        Path(args.output),
        {
            "schema": "continuityos-wheel-only-test-receipt-v1",
            "source_root_excluded": source_root_excluded,
            "site_packages_probe": probe_payload,
            "status": "PASS" if passed else "FAIL",
            "wheel": str(wheel),
            "wheel_sha256": _sha256_file(wheel),
            "workspace": str(workspace),
            "commands": commands,
        },
    )
    return 0 if passed else 1


def workflow_policy(args: argparse.Namespace) -> int:
    workflow = Path(args.workflow).resolve()
    text = workflow.read_text(encoding="utf-8")
    lowered = text.lower()
    forbidden = {
        "secrets expression": "secrets.",
        "deployment trigger": "deployment",
        "release trigger": "release:",
        "schedule trigger": "schedule:",
        "tag trigger": "tags:",
        "privileged PR trigger": "pull_request_target:",
        "GitHub environment": "environment:",
    }
    findings = [name for name, token in forbidden.items() if token in lowered]
    if re.search(r"(?mi)^\s+[a-z][a-z-]*:\s*write\s*$", text):
        findings.append("write permission")
    required = [
        "pull_request:",
        "review/**",
        "ubuntu-latest",
        "windows-latest",
        "persist-credentials: false",
        "exact-index",
        "wheel-test",
        "compileall",
        "release_hardening_probes.py",
        "bench.continuitybench",
        "test_ci_linux_symlink_realpath.py",
        "actions/upload-artifact@v4",
    ]
    missing = [token for token in required if token not in text]
    payload = {
        "schema": "continuityos-review-workflow-policy-v1",
        "workflow": str(workflow),
        "workflow_sha256": _sha256_file(workflow),
        "forbidden_findings": findings,
        "missing_required_tokens": missing,
        "status": "PASS" if not findings and not missing else "FAIL",
    }
    _write_json(Path(args.output), payload)
    print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
    return 0 if payload["status"] == "PASS" else 1


def receipt_manifest(args: argparse.Namespace) -> int:
    directory = Path(args.directory).resolve()
    output = Path(args.output).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    records = []
    for path in sorted(item for item in directory.rglob("*") if item.is_file()):
        if path == output:
            continue
        records.append((_sha256_file(path), path.relative_to(directory).as_posix()))
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        "".join(f"{digest}  {name}\n" for digest, name in records),
        encoding="ascii",
        newline="\n",
    )
    print(f"{len(records)} receipt files; manifest_sha256={_sha256_file(output)}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="subcommand", required=True)

    run = commands.add_parser("run")
    run.add_argument("--output", required=True)
    run.add_argument("command", nargs=argparse.REMAINDER)
    run.set_defaults(func=command_receipt)

    metadata = commands.add_parser("metadata")
    metadata.add_argument("--mode", choices=("absent", "editable"), required=True)
    metadata.add_argument("--source-root", default=".")
    metadata.add_argument("--output", required=True)
    metadata.set_defaults(func=metadata_receipt)

    index = commands.add_parser("exact-index")
    index.add_argument("--manifest", required=True)
    index.add_argument("--scan-output", required=True)
    index.set_defaults(func=exact_index)

    nodes = commands.add_parser("collect-nodeids")
    nodes.add_argument("--output", required=True)
    nodes.set_defaults(func=collect_nodeids)

    wheel = commands.add_parser("wheel-test")
    wheel.add_argument("--wheel-dir", required=True)
    wheel.add_argument("--test-wheel-dir", required=True)
    wheel.add_argument("--workspace", required=True)
    wheel.add_argument("--source-root", default=".")
    wheel.add_argument("--output", required=True)
    wheel.set_defaults(func=wheel_test)

    policy = commands.add_parser("validate-workflow")
    policy.add_argument("--workflow", required=True)
    policy.add_argument("--output", required=True)
    policy.set_defaults(func=workflow_policy)

    manifest = commands.add_parser("receipt-manifest")
    manifest.add_argument("--directory", required=True)
    manifest.add_argument("--output", required=True)
    manifest.set_defaults(func=receipt_manifest)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
