"""R25 qualification-only append-only witness service.

This service is intentionally not a production witness implementation. It is a
loopback-published Docker qualification fixture with durable JSONL append+fsync
semantics and a deterministic post-append barrier for crash injection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

STATE_SCHEMA = "continuityos.replay_witness_state/v1"
GENESIS_DOMAIN = "continuityos.replay_witness_genesis/v1"


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _genesis_head(namespace: str) -> str:
    return _sha256_text(
        _canonical_json({"schema": GENESIS_DOMAIN, "namespace": namespace})
    )


def _state(namespace: str, generation: int, head_sha256: str) -> dict:
    return {
        "schema": STATE_SCHEMA,
        "namespace": namespace,
        "generation": generation,
        "head_sha256": head_sha256,
    }


class Store:
    def __init__(
        self,
        path: Path,
        *,
        pause_namespace: str | None,
        pause_generation: int | None,
        pause_marker: Path | None,
        release_marker: Path | None,
        pause_timeout: float,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.records: dict[str, list[dict]] = {}
        self.pause_namespace = pause_namespace
        self.pause_generation = pause_generation
        self.pause_marker = pause_marker
        self.release_marker = release_marker
        self.pause_timeout = pause_timeout
        self._pause_used = False
        if self.path.exists():
            with self.path.open("r", encoding="utf-8") as handle:
                for lineno, raw in enumerate(handle, start=1):
                    raw = raw.strip()
                    if not raw:
                        continue
                    item = json.loads(raw)
                    if (
                        type(item) is not dict
                        or set(item) != {"namespace", "record"}
                        or type(item["namespace"]) is not str
                        or type(item["record"]) is not dict
                    ):
                        raise RuntimeError(
                            f"invalid witness log entry at line {lineno}"
                        )
                    self.records.setdefault(item["namespace"], []).append(
                        item["record"]
                    )

    def current_state(self, namespace: str) -> dict:
        with self.lock:
            rows = self.records.get(namespace, [])
            if not rows:
                return _state(namespace, 0, _genesis_head(namespace))
            last = rows[-1]
            return _state(
                namespace, int(last["generation"]), str(last["head_sha256"])
            )

    def records_after(self, namespace: str, generation: int) -> list[dict]:
        with self.lock:
            return [
                json.loads(_canonical_json(row))
                for row in self.records.get(namespace, [])[generation:]
            ]

    def append(
        self,
        *,
        namespace: str,
        expected_generation: int,
        expected_head_sha256: str,
        record: dict,
    ) -> tuple[bool, dict]:
        with self.lock:
            current = self.current_state(namespace)
            if (
                current["generation"] != expected_generation
                or current["head_sha256"] != expected_head_sha256
            ):
                return False, current
            if (
                record.get("namespace") != namespace
                or record.get("generation") != expected_generation + 1
                or record.get("previous_head_sha256") != expected_head_sha256
            ):
                raise ValueError("record does not extend expected witness state")

            item = {"namespace": namespace, "record": record}
            encoded = (_canonical_json(item) + "\n").encode("ascii")
            with self.path.open("ab", buffering=0) as handle:
                handle.write(encoded)
                os.fsync(handle.fileno())
            self.records.setdefault(namespace, []).append(
                json.loads(_canonical_json(record))
            )

            should_pause = (
                not self._pause_used
                and self.pause_namespace == namespace
                and self.pause_generation == record.get("generation")
            )
            if should_pause:
                self._pause_used = True
                if self.pause_marker is not None:
                    self.pause_marker.parent.mkdir(parents=True, exist_ok=True)
                    self.pause_marker.write_text(
                        str(record.get("record_id", "")), encoding="utf-8"
                    )

        if should_pause:
            deadline = time.monotonic() + self.pause_timeout
            while time.monotonic() < deadline:
                if self.release_marker is not None and self.release_marker.exists():
                    break
                time.sleep(0.05)

        return True, json.loads(_canonical_json(record))


class Handler(BaseHTTPRequestHandler):
    server_version = "ContinuityOSR25Witness/1"

    @property
    def store(self) -> Store:
        return self.server.store  # type: ignore[attr-defined]

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _send(self, status: int, value: object) -> None:
        payload = (_canonical_json(value) + "\n").encode("ascii")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _query(self) -> tuple[str, dict[str, list[str]]]:
        parsed = urlparse(self.path)
        return parsed.path, parse_qs(parsed.query, strict_parsing=True)

    def do_GET(self) -> None:
        try:
            path, query = self._query()
            if path == "/health":
                self._send(
                    HTTPStatus.OK,
                    {
                        "ok": True,
                        "service": "continuityos-r25-qualification-witness",
                        "durability": "jsonl_fsync",
                        "production_ready": False,
                    },
                )
                return
            if path == "/state":
                namespace = query["namespace"][0]
                self._send(HTTPStatus.OK, self.store.current_state(namespace))
                return
            if path == "/records":
                namespace = query["namespace"][0]
                after = int(query["after"][0])
                if after < 0:
                    raise ValueError("after must be non-negative")
                self._send(
                    HTTPStatus.OK, self.store.records_after(namespace, after)
                )
                return
            self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
        except Exception as exc:
            self._send(
                HTTPStatus.BAD_REQUEST,
                {"error": type(exc).__name__, "detail": str(exc)},
            )

    def do_POST(self) -> None:
        try:
            path, _query = self._query()
            if path != "/append":
                self._send(HTTPStatus.NOT_FOUND, {"error": "not found"})
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                raise ValueError("invalid content length")
            body = json.loads(self.rfile.read(length).decode("ascii"))
            if type(body) is not dict:
                raise ValueError("body must be an object")
            ok, value = self.store.append(
                namespace=str(body["namespace"]),
                expected_generation=int(body["expected_generation"]),
                expected_head_sha256=str(body["expected_head_sha256"]),
                record=dict(body["record"]),
            )
            if not ok:
                self._send(HTTPStatus.CONFLICT, value)
                return
            self._send(HTTPStatus.OK, value)
        except Exception as exc:
            self._send(
                HTTPStatus.BAD_REQUEST,
                {"error": type(exc).__name__, "detail": str(exc)},
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-file", required=True)
    parser.add_argument("--pause-namespace")
    parser.add_argument("--pause-generation", type=int)
    parser.add_argument("--pause-marker")
    parser.add_argument("--release-marker")
    parser.add_argument("--pause-timeout", type=float, default=60.0)
    args = parser.parse_args()

    store = Store(
        Path(args.data_file),
        pause_namespace=args.pause_namespace,
        pause_generation=args.pause_generation,
        pause_marker=Path(args.pause_marker) if args.pause_marker else None,
        release_marker=Path(args.release_marker) if args.release_marker else None,
        pause_timeout=args.pause_timeout,
    )
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    server.store = store  # type: ignore[attr-defined]
    try:
        server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
