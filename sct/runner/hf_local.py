from __future__ import annotations

import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from pathlib import Path
import sys
from typing import Any, Mapping
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from ..canon import canonical_json, sha256_obj
from ..errors import EvidenceError
from ..r13 import R13_CHOICE_PREFIX
from ..r13_manifest_guard import validate_model_manifest_for_seal

R13_HF_RUNTIME_SCHEMA = "sct.r13-hf-local-logit-runtime/v2"


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_manifest(path: str | Path) -> dict[str, Any]:
    value = json.loads(Path(path).expanduser().read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise EvidenceError("R13 HF runtime model manifest must be a JSON object")
    return validate_model_manifest_for_seal(value)


def _require_exact_file_hashes(snapshot: Path, mapping: Mapping[str, Any], *, label: str) -> dict[str, str]:
    verified: dict[str, str] = {}
    for name, expected in mapping.items():
        if not isinstance(name, str) or not name or not isinstance(expected, str):
            raise EvidenceError(f"invalid {label} hash mapping")
        path = snapshot / name
        if not path.is_file():
            raise EvidenceError(f"R13 HF runtime missing {label} file: {name}")
        actual = _sha256_file(path)
        if actual.lower() != expected.lower():
            raise EvidenceError(f"R13 HF runtime {label} SHA-256 mismatch: {name}")
        verified[name] = actual.lower()
    return verified


def verify_alias_tokens(tokenizer, manifest: Mapping[str, Any]) -> dict[str, int]:
    rows = manifest.get("alias_tokens")
    if not isinstance(rows, list):
        raise EvidenceError("R13 HF runtime requires sealed alias_tokens")
    prefix_ids = tokenizer.encode(R13_CHOICE_PREFIX, add_special_tokens=False)
    out: dict[str, int] = {}
    for row in rows:
        if not isinstance(row, Mapping):
            raise EvidenceError("R13 HF runtime alias row invalid")
        alias = str(row.get("alias", ""))
        token_id = row.get("token_id")
        if isinstance(token_id, bool) or not isinstance(token_id, int):
            raise EvidenceError("R13 HF runtime alias token ID invalid")
        ids = tokenizer.encode(alias, add_special_tokens=False)
        if ids != [token_id]:
            raise EvidenceError(f"R13 HF runtime alias is not exact one-token encoding: {alias}")
        decoded = tokenizer.decode(
            [token_id],
            skip_special_tokens=False,
            clean_up_tokenization_spaces=False,
        )
        if decoded != alias:
            raise EvidenceError(f"R13 HF runtime alias token decode mismatch: {alias}")
        reconstructed = tokenizer.decode(
            prefix_ids + [token_id],
            skip_special_tokens=False,
            clean_up_tokenization_spaces=False,
        )
        if reconstructed != R13_CHOICE_PREFIX + alias:
            raise EvidenceError(f"R13 HF runtime choice-prefix reconstruction mismatch: {alias}")
        out[alias] = token_id
    if len(out) < 15:
        raise EvidenceError("R13 HF runtime requires at least 15 verified aliases")
    return out


def render_model_visible_prompt(tokenizer, messages) -> str:
    """Render the frozen R13 v2 assistant-prefill prompt without closing the final message."""
    if not isinstance(messages, list) or len(messages) < 3:
        raise EvidenceError("R13 HF runtime messages missing")
    final = messages[-1]
    if not isinstance(final, Mapping) or final.get("role") != "assistant" or final.get("content") != R13_CHOICE_PREFIX:
        raise EvidenceError("R13 v2 requires exact final assistant choice-prefix prefill")
    rendered = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        continue_final_message=True,
        add_generation_prompt=False,
    )
    if not isinstance(rendered, str) or not rendered.endswith(R13_CHOICE_PREFIX):
        raise EvidenceError("R13 v2 model-visible prompt must end exactly at assistant choice prefix")
    return rendered


class HFLocalLogitRuntime:
    """Persistent CPU runtime. Loading/health performs no model forward pass."""

    def __init__(self, manifest: Mapping[str, Any], *, cache_dir: str | Path | None = None):
        self.manifest = validate_model_manifest_for_seal(manifest)
        try:
            import torch
            import transformers
            from huggingface_hub import snapshot_download
            from transformers import AutoModelForCausalLM, AutoTokenizer
        except ImportError as exc:
            raise EvidenceError("R13 HF runtime dependencies are not installed") from exc

        self.torch = torch
        self.transformers_version = transformers.__version__
        repo = self.manifest["model_repo_or_provider_id"]
        revision = self.manifest["model_revision"]
        snapshot = Path(snapshot_download(
            repo_id=repo,
            revision=revision,
            cache_dir=None if cache_dir is None else str(Path(cache_dir).expanduser()),
        ))
        self.snapshot = snapshot
        self.weight_hashes = _require_exact_file_hashes(
            snapshot, self.manifest["weight_hashes"], label="weight"
        )
        self.tokenizer_hashes = _require_exact_file_hashes(
            snapshot, self.manifest["tokenizer_hashes"], label="tokenizer"
        )

        self.tokenizer = AutoTokenizer.from_pretrained(
            str(snapshot), local_files_only=True, use_fast=True
        )
        self.alias_token_ids = verify_alias_tokens(self.tokenizer, self.manifest)

        # Float32 CPU is chosen prospectively for portability/repeatability, not to tune R13 outcomes.
        torch.set_grad_enabled(False)
        torch.set_num_threads(4)
        try:
            torch.set_num_interop_threads(1)
        except RuntimeError:
            pass
        torch.use_deterministic_algorithms(True)
        self.model = AutoModelForCausalLM.from_pretrained(
            str(snapshot),
            local_files_only=True,
            torch_dtype=torch.float32,
            low_cpu_mem_usage=False,
        )
        self.model.to("cpu")
        self.model.eval()
        self.forward_calls = 0
        self.identity = {
            "schema": R13_HF_RUNTIME_SCHEMA,
            "model_repo_or_provider_id": repo,
            "model_revision": revision,
            "model_manifest_sha256": self.manifest["manifest_sha256"],
            "weight_hashes": self.weight_hashes,
            "tokenizer_hashes": self.tokenizer_hashes,
            "alias_token_ids": self.alias_token_ids,
            "python": sys.version.split()[0],
            "torch": torch.__version__,
            "transformers": self.transformers_version,
            "device": "cpu",
            "dtype": "float32",
            "torch_num_threads": torch.get_num_threads(),
            "torch_num_interop_threads": torch.get_num_interop_threads(),
            "deterministic_algorithms": torch.are_deterministic_algorithms_enabled(),
            "model_forward_calls_at_ready": 0,
            "execution_authority": "NONE",
            "can_execute": False,
        }
        self.identity["runtime_identity_sha256"] = sha256_obj(self.identity)

    def health(self) -> dict[str, Any]:
        return {
            "ok": True,
            "runtime": self.identity,
            "model_forward_calls": self.forward_calls,
            "model_inference_executed": self.forward_calls > 0,
            "execution_authority": "NONE",
        }

    def allowed_token_logits(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        if payload.get("mode") != "allowed_token_logits":
            raise EvidenceError("R13 HF runtime requires allowed_token_logits mode")
        request = payload.get("request")
        aliases = payload.get("allowed_aliases")
        supplied_ids = payload.get("allowed_alias_token_ids")
        if not isinstance(request, Mapping):
            raise EvidenceError("R13 HF runtime request missing")
        if not isinstance(aliases, list) or len(aliases) < 2:
            raise EvidenceError("R13 HF runtime allowed aliases invalid")
        aliases = [str(x) for x in aliases]
        if len(set(aliases)) != len(aliases):
            raise EvidenceError("R13 HF runtime allowed aliases must be unique")
        if not isinstance(supplied_ids, Mapping):
            raise EvidenceError("R13 HF runtime token IDs missing")
        exact_ids = {}
        for alias in aliases:
            if alias not in self.alias_token_ids:
                raise EvidenceError("R13 HF runtime alias outside sealed manifest")
            exact_ids[alias] = self.alias_token_ids[alias]
        if dict(supplied_ids) != exact_ids:
            raise EvidenceError("R13 HF runtime supplied token IDs differ from sealed tokenizer")
        if request.get("model") != self.manifest["model_repo_or_provider_id"]:
            raise EvidenceError("R13 HF runtime model identity mismatch")
        if request.get("model_version") != self.manifest["model_revision"]:
            raise EvidenceError("R13 HF runtime model revision mismatch")
        if request.get("execution_authority") != "NONE" or request.get("can_execute") is not False:
            raise EvidenceError("R13 HF runtime request may not grant execution authority")

        messages = request.get("messages")
        rendered = render_model_visible_prompt(self.tokenizer, messages)
        model_inputs = self.tokenizer(
            rendered,
            return_tensors="pt",
            add_special_tokens=False,
        )
        input_ids = model_inputs["input_ids"].to("cpu")
        attention_mask = model_inputs.get("attention_mask")
        if attention_mask is not None:
            attention_mask = attention_mask.to("cpu")

        with self.torch.inference_mode():
            outputs = self.model(input_ids=input_ids, attention_mask=attention_mask, use_cache=False)
            final = outputs.logits[0, -1, :].detach().to(dtype=self.torch.float64, device="cpu")
        self.forward_calls += 1
        logits = {alias: float(final[token_id].item()) for alias, token_id in exact_ids.items()}
        return {
            "schema": R13_HF_RUNTIME_SCHEMA,
            "allowed_token_logits": logits,
            "used_alias_token_ids": exact_ids,
            "request_sha256": sha256_obj(dict(request)),
            "runtime_identity_sha256": self.identity["runtime_identity_sha256"],
            "model_forward_call_ordinal": self.forward_calls,
            "execution_authority": "NONE",
            "can_execute": False,
        }


class _RuntimeHandler(BaseHTTPRequestHandler):
    runtime: HFLocalLogitRuntime | None = None

    def log_message(self, fmt, *args):
        return

    def _send(self, status: int, body: Mapping[str, Any]):
        data = canonical_json(dict(body)).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/health" or self.runtime is None:
            self._send(404, {"ok": False, "execution_authority": "NONE"})
            return
        self._send(200, self.runtime.health())

    def do_POST(self):
        if self.path != "/logits" or self.runtime is None:
            self._send(404, {"ok": False, "execution_authority": "NONE"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise EvidenceError("R13 HF runtime request body size invalid")
            raw = self.rfile.read(length)
            value = json.loads(raw.decode("utf-8"))
            if not isinstance(value, Mapping):
                raise EvidenceError("R13 HF runtime body must be JSON object")
            out = self.runtime.allowed_token_logits(value)
        except Exception as exc:
            self._send(400, {
                "ok": False,
                "error_class": type(exc).__name__,
                "error": str(exc)[:300],
                "execution_authority": "NONE",
            })
            return
        self._send(200, out)


def serve(*, manifest_path: str, host: str, port: int, cache_dir: str | None) -> None:
    if host not in {"127.0.0.1", "localhost"}:
        raise EvidenceError("R13 HF runtime must bind loopback only")
    runtime = HFLocalLogitRuntime(_load_manifest(manifest_path), cache_dir=cache_dir)
    _RuntimeHandler.runtime = runtime
    server = HTTPServer((host, port), _RuntimeHandler)
    print(canonical_json({"status": "READY", **runtime.health()}), flush=True)
    server.serve_forever()


def _post_json(url: str, value: Mapping[str, Any], *, timeout: float) -> Mapping[str, Any]:
    data = canonical_json(dict(value)).encode("utf-8")
    request = Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except (HTTPError, URLError, TimeoutError) as exc:
        raise EvidenceError(f"R13 local HF runtime transport failure: {type(exc).__name__}") from exc
    try:
        value = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise EvidenceError("R13 local HF runtime response is not JSON") from exc
    if not isinstance(value, Mapping):
        raise EvidenceError("R13 local HF runtime response must be object")
    return value


def client(*, url: str, timeout: float) -> int:
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, Mapping):
            raise EvidenceError("R13 HF client stdin must be JSON object")
        out = _post_json(url.rstrip("/") + "/logits", payload, timeout=timeout)
        if "allowed_token_logits" not in out or "used_alias_token_ids" not in out:
            raise EvidenceError(str(out.get("error") or "R13 local HF runtime rejected request"))
        sys.stdout.write(canonical_json({
            "allowed_token_logits": out["allowed_token_logits"],
            "used_alias_token_ids": out["used_alias_token_ids"],
        }))
        return 0
    except Exception as exc:
        sys.stderr.write(f"SCT_PROVIDER_ERROR: provider transport failure: {type(exc).__name__}\n")
        return 2


def health(*, url: str, timeout: float) -> int:
    try:
        with urlopen(url.rstrip("/") + "/health", timeout=timeout) as response:
            value = json.loads(response.read().decode("utf-8"))
        if not isinstance(value, Mapping) or value.get("ok") is not True:
            raise EvidenceError("R13 local HF runtime health failed")
        print(canonical_json(value))
        return 0
    except Exception as exc:
        sys.stderr.write(f"R13_HF_HEALTH_ERROR:{type(exc).__name__}\n")
        return 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m sct.runner.hf_local")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--model-manifest", required=True)
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8765)
    s.add_argument("--cache-dir")
    c = sub.add_parser("client")
    c.add_argument("--url", default="http://127.0.0.1:8765")
    c.add_argument("--timeout", type=float, default=120.0)
    h = sub.add_parser("health")
    h.add_argument("--url", default="http://127.0.0.1:8765")
    h.add_argument("--timeout", type=float, default=5.0)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "serve":
        serve(manifest_path=args.model_manifest, host=args.host, port=args.port, cache_dir=args.cache_dir)
        return 0
    if args.cmd == "client":
        return client(url=args.url, timeout=args.timeout)
    if args.cmd == "health":
        return health(url=args.url, timeout=args.timeout)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
