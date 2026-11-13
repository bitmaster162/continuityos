"""R25 real PostgreSQL + external witness qualification harness."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from continuityos.witnessed_approval_replay import (
    ALREADY_CONSUMED,
    CLAIMED,
    PostgresWitnessedApprovalReplayAuthority,
    WITNESS_SCOPE,
)

RECEIPT_SCHEMA = "continuityos.r25.replay_production_qualification/v1"
GREEN_STATUS = "LOCAL_CONTAINER_QUALIFICATION_GREEN"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("ascii")).hexdigest()


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run(
    args: list[str],
    *,
    check: bool = True,
    input_bytes: bytes | None = None,
    text: bool = True,
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if os.name == "nt":
        env.setdefault("ProgramData", r"C:\ProgramData")
    result = subprocess.run(
        args,
        input=input_bytes if not text else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=text,
        env=env,
        check=False,
    )
    if check and result.returncode != 0:
        stdout = result.stdout if text else result.stdout.decode("utf-8", "replace")
        stderr = result.stderr if text else result.stderr.decode("utf-8", "replace")
        raise RuntimeError(
            f"command failed ({result.returncode}): {args!r}\n"
            f"stdout={stdout}\nstderr={stderr}"
        )
    return result


def _docker(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return _run(["docker", *args], check=check)


def _wait_http(url: str, timeout: float = 30.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as response:
                value = json.loads(response.read().decode("ascii"))
                if type(value) is dict:
                    return value
        except Exception as exc:
            last = exc
        time.sleep(0.2)
    raise RuntimeError(f"HTTP endpoint not ready: {url}: {last}")


def _wait_pg(container: str, timeout: float = 45.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = _docker(
            "exec", container, "pg_isready", "-U", "postgres",
            "-d", "continuityos_r25", check=False,
        )
        if result.returncode == 0:
            return
        time.sleep(0.5)
    raise RuntimeError("PostgreSQL did not become ready")


class HttpWitness:
    witness_scope = WITNESS_SCOPE

    def __init__(self, base_url: str, *, timeout: float = 2.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def _get(self, path: str, query: dict[str, object]) -> Any:
        encoded = urllib.parse.urlencode(query)
        request = urllib.request.Request(
            f"{self.base_url}{path}?{encoded}", method="GET"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("ascii"))
        except Exception as exc:
            raise RuntimeError(f"qualification witness unavailable: {exc}") from exc

    def current_state(self, namespace: str) -> dict:
        value = self._get("/state", {"namespace": namespace})
        if type(value) is not dict:
            raise RuntimeError("qualification witness state invalid")
        return value

    def records_after(self, namespace: str, generation: int) -> list[dict]:
        value = self._get("/records", {"namespace": namespace, "after": generation})
        if type(value) is not list:
            raise RuntimeError("qualification witness history invalid")
        return value

    def append_record(
        self, namespace: str, expected_generation: int,
        expected_head_sha256: str, record: dict,
    ) -> dict:
        payload = _canonical_json({
            "namespace": namespace,
            "expected_generation": expected_generation,
            "expected_head_sha256": expected_head_sha256,
            "record": record,
        }).encode("ascii")
        request = urllib.request.Request(
            f"{self.base_url}/append", data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                value = json.loads(response.read().decode("ascii"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("ascii", "replace")
            raise RuntimeError(
                f"qualification witness append rejected: {exc.code}: {body}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(
                f"qualification witness append unavailable: {exc}"
            ) from exc
        if type(value) is not dict:
            raise RuntimeError("qualification witness append response invalid")
        return value


def _claim_values(case: str) -> tuple[str, dict, str, str]:
    return (
        "hap_" + _hash(f"approval:{case}"),
        {
            "repository": "bitmaster162/continuityos",
            "baseline_sha": _hash(f"base:{case}")[:40],
            "candidate_sha": _hash(f"head:{case}")[:40],
            "candidate_tree_sha": _hash(f"tree:{case}")[:40],
            "qualification_case": case,
        },
        _hash(f"nonce:{case}"),
        _hash(f"digest:{case}"),
    )


def _authority(
    dsn: str, witness_url: str, namespace: str
) -> PostgresWitnessedApprovalReplayAuthority:
    return PostgresWitnessedApprovalReplayAuthority(
        dsn, witness=HttpWitness(witness_url), namespace=namespace
    )


def _worker_sync(args: argparse.Namespace) -> int:
    try:
        state = _authority(args.dsn, args.witness_url, args.namespace).synchronize()
        print(_canonical_json({"ok": True, "state": state}))
        return 0
    except Exception as exc:
        print(_canonical_json({
            "ok": False,
            "error": type(exc).__name__,
            "detail": str(exc),
        }))
        return 2


def _worker_claim(args: argparse.Namespace) -> int:
    try:
        approval_id, subject, nonce, digest = _claim_values(args.case)
        receipt = _authority(
            args.dsn, args.witness_url, args.namespace
        ).claim_once(
            approval_id=approval_id,
            subject=subject,
            nonce=nonce,
            digest_sha256=digest,
        )
        print(_canonical_json({"ok": True, "receipt": receipt}))
        return 0
    except Exception as exc:
        print(_canonical_json({
            "ok": False,
            "error": type(exc).__name__,
            "detail": str(exc),
        }))
        return 2


def _worker_command(
    python: str,
    script: Path,
    *,
    mode: str,
    dsn: str,
    witness_url: str,
    namespace: str,
    case: str | None = None,
) -> list[str]:
    command = [
        python,
        str(script),
        mode,
        "--dsn",
        dsn,
        "--witness-url",
        witness_url,
        "--namespace",
        namespace,
    ]
    if case is not None:
        command.extend(["--case", case])
    return command


def _worker_run(
    python: str,
    script: Path,
    *,
    mode: str,
    dsn: str,
    witness_url: str,
    namespace: str,
    case: str | None = None,
) -> tuple[int, dict]:
    command = _worker_command(
        python,
        script,
        mode=mode,
        dsn=dsn,
        witness_url=witness_url,
        namespace=namespace,
        case=case,
    )
    result = _run(command, check=False)
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return result.returncode, {
            "ok": False,
            "error": "NoWorkerReceipt",
            "detail": result.stderr.strip(),
        }
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError:
        value = {
            "ok": False,
            "error": "InvalidWorkerReceipt",
            "detail": result.stdout[-2000:],
        }
    return result.returncode, value


def _spawn_worker(
    python: str,
    script: Path,
    *,
    mode: str,
    dsn: str,
    witness_url: str,
    namespace: str,
    case: str | None = None,
) -> subprocess.Popen:
    command = _worker_command(
        python,
        script,
        mode=mode,
        dsn=dsn,
        witness_url=witness_url,
        namespace=namespace,
        case=case,
    )
    env = dict(os.environ)
    if os.name == "nt":
        env.setdefault("ProgramData", r"C:\ProgramData")
    return subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )


def _collect_worker(
    process: subprocess.Popen, timeout: float = 45.0
) -> tuple[int, dict]:
    stdout, stderr = process.communicate(timeout=timeout)
    lines = [line for line in stdout.splitlines() if line.strip()]
    if not lines:
        return process.returncode or 0, {
            "ok": False,
            "error": "NoWorkerReceipt",
            "detail": stderr.strip(),
        }
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError:
        value = {
            "ok": False,
            "error": "InvalidWorkerReceipt",
            "detail": stdout[-2000:],
        }
    return process.returncode or 0, value


def _status(receipt: dict) -> str | None:
    if receipt.get("ok") is not True:
        return None
    inner = receipt.get("receipt")
    return inner.get("status") if type(inner) is dict else None


def _db_namespace_state(dsn: str, namespace: str) -> dict[str, Any]:
    import psycopg

    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT generation, head_sha256 "
                "FROM continuityos_replay_witness_state WHERE namespace=%s",
                (namespace,),
            )
            row = cursor.fetchone()
            cursor.execute(
                "SELECT COUNT(*) FROM continuityos_approval_claims "
                "WHERE namespace=%s",
                (namespace,),
            )
            count = cursor.fetchone()[0]
    return {
        "generation": None if row is None else int(row[0]),
        "head_sha256": None if row is None else str(row[1]),
        "claim_count": int(count),
    }


def _tamper_digest(dsn: str, namespace: str) -> None:
    import psycopg

    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "UPDATE continuityos_approval_claims "
                "SET digest_sha256=%s WHERE namespace=%s",
                ("f" * 64, namespace),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("expected exactly one claim row to tamper")
        connection.commit()


def _pg_version(dsn: str) -> str:
    import psycopg

    with psycopg.connect(dsn) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT version()")
            return str(cursor.fetchone()[0])


def _snapshot_database(container: str) -> bytes:
    result = _run(
        [
            "docker",
            "exec",
            container,
            "pg_dump",
            "-U",
            "postgres",
            "-d",
            "continuityos_r25",
            "-Fc",
        ],
        text=False,
    )
    return bytes(result.stdout)


def _restore_database(container: str, dump: bytes) -> None:
    _docker(
        "exec",
        container,
        "psql",
        "-U",
        "postgres",
        "-d",
        "postgres",
        "-c",
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
        "WHERE datname='continuityos_r25' AND pid <> pg_backend_pid();",
    )
    _docker(
        "exec",
        container,
        "dropdb",
        "-U",
        "postgres",
        "--if-exists",
        "continuityos_r25",
    )
    _docker("exec", container, "createdb", "-U", "postgres", "continuityos_r25")
    result = _run(
        [
            "docker",
            "exec",
            "-i",
            container,
            "pg_restore",
            "-U",
            "postgres",
            "-d",
            "continuityos_r25",
        ],
        input_bytes=dump,
        text=False,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "pg_restore failed: "
            + result.stderr.decode("utf-8", "replace")[-4000:]
        )


def _volume_bytes(volume: str) -> bytes:
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{volume}:/data",
            "python:3.13-alpine",
            "sh",
            "-c",
            "cat /data/witness.jsonl 2>/dev/null || true",
        ],
        text=False,
    )
    return bytes(result.stdout)


def _restore_volume_bytes(volume: str, content: bytes) -> None:
    result = _run(
        [
            "docker",
            "run",
            "--rm",
            "-i",
            "-v",
            f"{volume}:/data",
            "python:3.13-alpine",
            "sh",
            "-c",
            "cat > /data/witness.jsonl",
        ],
        input_bytes=content,
        text=False,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "witness volume restore failed: "
            + result.stderr.decode("utf-8", "replace")[-4000:]
        )


def _assert_worker_failure(code: int, value: dict, label: str) -> dict:
    if code == 0 or value.get("ok") is not False:
        raise AssertionError(
            f"{label} did not fail closed: code={code} value={value}"
        )
    return {
        "status": "PASS",
        "worker_exit": code,
        "error": value.get("error"),
        "detail": str(value.get("detail", ""))[:1000],
    }


def _qualify(args: argparse.Namespace) -> int:
    import psycopg

    repo = Path(args.repo_root).resolve()
    script = Path(__file__).resolve()
    witness_script = repo / "tools" / "r25_witness_service.py"
    head = _run(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    tree = _run(
        ["git", "-C", str(repo), "rev-parse", "HEAD^{tree}"]
    ).stdout.strip()
    dirty = _run(
        ["git", "-C", str(repo), "status", "--porcelain"]
    ).stdout.strip()
    if dirty and not args.allow_dirty:
        raise RuntimeError("R25 qualification requires a clean Git worktree")
    if args.expected_head and head != args.expected_head:
        raise RuntimeError("Git HEAD does not match --expected-head")

    docker_version = _docker(
        "version", "--format", "{{.Server.Version}}"
    ).stdout.strip()
    postgres_image = json.loads(
        _docker("image", "inspect", "postgres:17-alpine").stdout
    )[0]
    witness_image = json.loads(
        _docker("image", "inspect", "python:3.13-alpine").stdout
    )[0]
    harness_sha256 = hashlib.sha256(script.read_bytes()).hexdigest()
    witness_fixture_sha256 = hashlib.sha256(
        witness_script.read_bytes()
    ).hexdigest()
    run_id = f"{os.getpid()}-{int(time.time())}"
    pg_name = f"continuityos-r25-pg-{run_id}"
    witness_name = f"continuityos-r25-witness-{run_id}"
    pg_volume = f"continuityos-r25-pg-{run_id}"
    witness_volume = f"continuityos-r25-witness-{run_id}"
    pg_port = _free_port()
    witness_port = _free_port()
    dsn = (
        f"postgresql://postgres@127.0.0.1:{pg_port}/continuityos_r25?connect_timeout=3"
    )
    witness_url = f"http://127.0.0.1:{witness_port}"
    work = (
        Path(args.work_dir).resolve()
        if args.work_dir
        else Path(tempfile.mkdtemp(prefix="continuityos-r25-"))
    )
    work.mkdir(parents=True, exist_ok=True)
    control = work / "control"
    control.mkdir(parents=True, exist_ok=True)
    pause_marker = control / "crash.marker"
    release_marker = control / "crash.release"
    crash_namespace = f"r25-crash-{run_id}"
    cases: dict[str, Any] = {}
    started_pg = False
    started_witness = False

    def start_witness() -> None:
        nonlocal started_witness
        inspect = _docker("container", "inspect", witness_name, check=False)
        if inspect.returncode == 0:
            _docker("start", witness_name)
        else:
            _docker(
                "run",
                "-d",
                "--name",
                witness_name,
                "-p",
                f"127.0.0.1:{witness_port}:8080",
                "-v",
                f"{witness_volume}:/data",
                "-v",
                f"{witness_script}:/app/witness.py:ro",
                "-v",
                f"{control}:/control",
                "python:3.13-alpine",
                "python",
                "/app/witness.py",
                "--host",
                "0.0.0.0",
                "--port",
                "8080",
                "--data-file",
                "/data/witness.jsonl",
                "--pause-namespace",
                crash_namespace,
                "--pause-generation",
                "1",
                "--pause-marker",
                "/control/crash.marker",
                "--release-marker",
                "/control/crash.release",
                "--pause-timeout",
                "60",
            )
        started_witness = True
        _wait_http(f"{witness_url}/health")

    def sync_namespace(namespace: str) -> dict:
        code, value = _worker_run(
            args.python,
            script,
            mode="sync",
            dsn=dsn,
            witness_url=witness_url,
            namespace=namespace,
        )
        if code != 0 or value.get("ok") is not True:
            raise AssertionError(f"sync failed for {namespace}: {value}")
        return value

    def claim_namespace(namespace: str, case: str) -> tuple[int, dict]:
        return _worker_run(
            args.python,
            script,
            mode="claim",
            dsn=dsn,
            witness_url=witness_url,
            namespace=namespace,
            case=case,
        )

    try:
        _docker("volume", "create", pg_volume)
        _docker("volume", "create", witness_volume)
        _docker(
            "run",
            "-d",
            "--name",
            pg_name,
            "-e",
            "POSTGRES_HOST_AUTH_METHOD=trust",
            "-e",
            "POSTGRES_DB=continuityos_r25",
            "-p",
            f"127.0.0.1:{pg_port}:5432",
            "-v",
            f"{pg_volume}:/var/lib/postgresql/data",
            "postgres:17-alpine",
        )
        started_pg = True
        _wait_pg(pg_name)
        start_witness()

        postgres_version = _pg_version(dsn)
        cases["preflight"] = {
            "status": "PASS",
            "docker_server": docker_version,
            "postgres": postgres_version,
            "psycopg": psycopg.__version__,
            "witness_health": _wait_http(f"{witness_url}/health"),
        }

        concurrency_ns = f"r25-concurrency-{run_id}"
        sync_namespace(concurrency_ns)
        worker_count = 8
        workers = [
            _spawn_worker(
                args.python,
                script,
                mode="claim",
                dsn=dsn,
                witness_url=witness_url,
                namespace=concurrency_ns,
                case="concurrent",
            )
            for _index in range(worker_count)
        ]
        results = [_collect_worker(worker) for worker in workers]
        statuses = [_status(value) for _code, value in results]
        if (
            statuses.count(CLAIMED) != 1
            or statuses.count(ALREADY_CONSUMED) != worker_count - 1
        ):
            raise AssertionError(
                f"concurrent claim invariant failed: {results}"
            )
        cases["concurrent_double_claim"] = {
            "status": "PASS",
            "worker_processes": worker_count,
            "claim_statuses": sorted(str(item) for item in statuses),
            "db_state": _db_namespace_state(dsn, concurrency_ns),
        }


        snapshot_ns = f"r25-snapshot-{run_id}"
        sync_namespace(snapshot_ns)
        db_dump = _snapshot_database(pg_name)
        code, first = claim_namespace(snapshot_ns, "snapshot")
        if code != 0 or _status(first) != CLAIMED:
            raise AssertionError(f"snapshot initial claim failed: {first}")
        claimed_state = _db_namespace_state(dsn, snapshot_ns)
        _restore_database(pg_name, db_dump)
        restored_state = _db_namespace_state(dsn, snapshot_ns)
        code, recovered = claim_namespace(snapshot_ns, "snapshot")
        if code != 0 or _status(recovered) != ALREADY_CONSUMED:
            raise AssertionError(f"snapshot recovery failed: {recovered}")
        cases["postgres_snapshot_rollback"] = {
            "status": "PASS",
            "claimed_state": claimed_state,
            "restored_pre_recovery_state": restored_state,
            "recovered_status": _status(recovered),
            "post_recovery_state": _db_namespace_state(dsn, snapshot_ns),
        }

        sync_namespace(crash_namespace)
        pause_marker.unlink(missing_ok=True)
        release_marker.unlink(missing_ok=True)
        crash_worker = _spawn_worker(
            args.python,
            script,
            mode="claim",
            dsn=dsn,
            witness_url=witness_url,
            namespace=crash_namespace,
            case="crash-after-witness",
        )
        deadline = time.monotonic() + 30.0
        while time.monotonic() < deadline and not pause_marker.exists():
            if crash_worker.poll() is not None:
                raise AssertionError(
                    "crash worker exited before durable witness barrier"
                )
            time.sleep(0.05)
        if not pause_marker.exists():
            crash_worker.kill()
            raise AssertionError("durable witness barrier was not reached")
        crash_worker.kill()
        crash_worker.wait(timeout=5)
        pre_recovery_crash_state = _db_namespace_state(
            dsn, crash_namespace
        )
        release_marker.write_text("release", encoding="utf-8")
        code, crash_recovered = claim_namespace(
            crash_namespace, "crash-after-witness"
        )
        if (
            code != 0
            or _status(crash_recovered) != ALREADY_CONSUMED
        ):
            raise AssertionError(
                f"crash recovery failed: {crash_recovered}"
            )
        cases["crash_after_witness_append"] = {
            "status": "PASS",
            "worker_killed_after_witness_fsync": True,
            "db_before_recovery": pre_recovery_crash_state,
            "recovered_status": _status(crash_recovered),
            "db_after_recovery": _db_namespace_state(
                dsn, crash_namespace
            ),
        }

        witness_outage_ns = f"r25-witness-outage-{run_id}"
        sync_namespace(witness_outage_ns)
        _docker("stop", witness_name)
        started_witness = False
        code, outage = claim_namespace(
            witness_outage_ns, "witness-outage"
        )
        cases["witness_outage_fail_closed"] = _assert_worker_failure(
            code, outage, "witness outage"
        )
        _docker("start", witness_name)
        started_witness = True
        _wait_http(f"{witness_url}/health")
        code, after_outage = claim_namespace(
            witness_outage_ns, "witness-outage"
        )
        if code != 0 or _status(after_outage) != CLAIMED:
            raise AssertionError(
                f"post-witness-outage recovery failed: {after_outage}"
            )
        cases["witness_outage_fail_closed"][
            "post_recovery_status"
        ] = _status(after_outage)

        pg_outage_ns = f"r25-pg-outage-{run_id}"
        sync_namespace(pg_outage_ns)
        _docker("stop", pg_name)
        started_pg = False
        code, pg_outage = claim_namespace(pg_outage_ns, "pg-outage")
        cases["postgres_outage_fail_closed"] = _assert_worker_failure(
            code, pg_outage, "PostgreSQL outage"
        )
        _docker("start", pg_name)
        started_pg = True
        _wait_pg(pg_name)
        code, pg_after = claim_namespace(pg_outage_ns, "pg-outage")
        if code != 0 or _status(pg_after) != CLAIMED:
            raise AssertionError(
                f"post-PostgreSQL-outage recovery failed: {pg_after}"
            )
        cases["postgres_outage_fail_closed"][
            "post_recovery_status"
        ] = _status(pg_after)


        rollback_ns = f"r25-witness-rollback-{run_id}"
        sync_namespace(rollback_ns)
        witness_before = _volume_bytes(witness_volume)
        code, rollback_claim = claim_namespace(
            rollback_ns, "witness-rollback"
        )
        if code != 0 or _status(rollback_claim) != CLAIMED:
            raise AssertionError(
                f"witness rollback setup failed: {rollback_claim}"
            )
        _docker("stop", witness_name)
        started_witness = False
        _restore_volume_bytes(witness_volume, witness_before)
        _docker("start", witness_name)
        started_witness = True
        _wait_http(f"{witness_url}/health")
        code, rollback_detected = _worker_run(
            args.python,
            script,
            mode="sync",
            dsn=dsn,
            witness_url=witness_url,
            namespace=rollback_ns,
        )
        cases["witness_rollback_fail_closed"] = _assert_worker_failure(
            code, rollback_detected, "witness rollback"
        )

        tamper_ns = f"r25-db-tamper-{run_id}"
        sync_namespace(tamper_ns)
        code, tamper_claim = claim_namespace(tamper_ns, "db-tamper")
        if code != 0 or _status(tamper_claim) != CLAIMED:
            raise AssertionError(
                f"tamper setup claim failed: {tamper_claim}"
            )
        _tamper_digest(dsn, tamper_ns)
        code, tamper_detected = _worker_run(
            args.python,
            script,
            mode="sync",
            dsn=dsn,
            witness_url=witness_url,
            namespace=tamper_ns,
        )
        cases["postgres_row_tamper_fail_closed"] = _assert_worker_failure(
            code, tamper_detected, "PostgreSQL row tamper"
        )

        receipt = {
            "schema": RECEIPT_SCHEMA,
            "status": GREEN_STATUS,
            "git_head": head,
            "git_tree": tree,
            "environment": {
                "docker_server": docker_version,
                "postgres_image": "postgres:17-alpine",
                "postgres_image_id": postgres_image["Id"],
                "postgres_repo_digests": postgres_image.get("RepoDigests", []),
                "python_witness_image": "python:3.13-alpine",
                "python_witness_image_id": witness_image["Id"],
                "python_witness_repo_digests": witness_image.get("RepoDigests", []),
                "postgres_version": postgres_version,
                "psycopg_version": psycopg.__version__,
                "qualification_harness_sha256": harness_sha256,
                "witness_fixture_sha256": witness_fixture_sha256,
                "postgres_container_domain": True,
                "witness_container_domain": True,
                "worker_subprocess_domains": worker_count,
                "separate_named_volumes": True,
                "host_loopback_only_ports": True,
                "same_physical_host": True,
            },
            "cases": cases,
            "authority": {
                "merge": False,
                "deploy": False,
                "runtime_execution": False,
                "can_trade": False,
                "capital_permission": "DENY",
            },
            "qualification_boundary": {
                "production_qualified_multi_host": False,
                "reasons": [
                    "PostgreSQL, witness, and workers share one physical host",
                    "qualification witness is unauthenticated loopback HTTP",
                    "service-stop outage is not packet-level network partition",
                    "Docker-host rollback could correlate both named volumes",
                ],
                "required_next": [
                    "independent physical or failure-domain witness",
                    "at least two physical or VM execution hosts",
                    "authenticated and encrypted witness transport",
                    "packet-level network partition injection",
                    "operator witness rotation and recovery drill",
                ],
            },
        }
        receipt_path = Path(args.receipt).resolve()
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(_canonical_json(receipt))
        return 0
    finally:
        if not args.keep:
            if (
                started_witness
                or _docker(
                    "container", "inspect", witness_name, check=False
                ).returncode == 0
            ):
                _docker("rm", "-f", witness_name, check=False)
            if (
                started_pg
                or _docker("container", "inspect", pg_name, check=False).returncode == 0
            ):
                _docker("rm", "-f", pg_name, check=False)
            _docker("volume", "rm", "-f", witness_volume, check=False)
            _docker("volume", "rm", "-f", pg_volume, check=False)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)

    sync = sub.add_parser("sync")
    sync.add_argument("--dsn", required=True)
    sync.add_argument("--witness-url", required=True)
    sync.add_argument("--namespace", required=True)

    claim = sub.add_parser("claim")
    claim.add_argument("--dsn", required=True)
    claim.add_argument("--witness-url", required=True)
    claim.add_argument("--namespace", required=True)
    claim.add_argument("--case", required=True)

    qualify = sub.add_parser("qualify")
    qualify.add_argument("--repo-root", default=".")
    qualify.add_argument("--python", default=sys.executable)
    qualify.add_argument("--expected-head")
    qualify.add_argument("--receipt", required=True)
    qualify.add_argument("--work-dir")
    qualify.add_argument("--allow-dirty", action="store_true")
    qualify.add_argument("--keep", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    if args.mode == "sync":
        return _worker_sync(args)
    if args.mode == "claim":
        return _worker_claim(args)
    if args.mode == "qualify":
        return _qualify(args)
    raise AssertionError(args.mode)


if __name__ == "__main__":
    raise SystemExit(main())
