from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request
from typing import Any, Mapping


class ProviderContractError(RuntimeError):
    pass


def _env(name: str, *, required: bool = False, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if required and (value is None or not value.strip()):
        raise ProviderContractError(f"missing required environment variable: {name}")
    return "" if value is None else value.strip()


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content.strip()
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, Mapping) and isinstance(item.get("text"), str):
                parts.append(item["text"])
        return "".join(parts).strip()
    raise ProviderContractError("provider message content is not text")


def _strip_fence(text: str) -> str:
    text = text.strip()
    if text.startswith("```") and text.endswith("```"):
        lines = text.splitlines()
        if lines and lines[0].lstrip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        return "\n".join(lines).strip()
    return text


def call_openai_compatible(request_obj: Mapping[str, Any]) -> Mapping[str, Any]:
    api_key = _env("SCT_OPENAI_COMPAT_API_KEY", required=True)
    pre_call_delay = float(_env("SCT_OPENAI_COMPAT_PRECALL_DELAY_SECONDS", default="0"))
    base_url = _env("SCT_OPENAI_COMPAT_BASE_URL", default="https://api.openai.com/v1").rstrip("/")
    timeout = float(_env("SCT_OPENAI_COMPAT_TIMEOUT_SECONDS", default="120"))
    model = request_obj.get("model")
    messages = request_obj.get("messages")
    if not isinstance(model, str) or not model.strip():
        raise ProviderContractError("request model missing")
    if not isinstance(messages, list) or not messages:
        raise ProviderContractError("request messages missing")

    body: dict[str, Any] = {
        "model": model,
        "messages": messages,
    }
    temperature = request_obj.get("temperature")
    if temperature is not None:
        body["temperature"] = temperature
    token_budget = request_obj.get("token_budget")
    if isinstance(token_budget, int) and token_budget > 0:
        body["max_tokens"] = min(token_budget, 1024)
    if _env("SCT_OPENAI_COMPAT_JSON_MODE", default="1") not in {"0", "false", "False"}:
        body["response_format"] = {"type": "json_object"}

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "sct-openai-compat/1",
    }
    referer = _env("SCT_OPENAI_COMPAT_HTTP_REFERER")
    title = _env("SCT_OPENAI_COMPAT_X_TITLE")
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title

    http_req = urllib.request.Request(
        base_url + "/chat/completions",
        data=json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    # Explicit fixed pacing is allowed; it is not a retry. This keeps one-shot calls
    # under provider free-tier RPM limits without wrapping the runner in PowerShell.
    if pre_call_delay > 0:
        time.sleep(pre_call_delay)

    try:
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        # Never echo request headers or secrets. Provider body is truncated and may still
        # contain provider diagnostics, not SCT personal context.
        provider_body = exc.read().decode("utf-8", "replace")[:500]
        raise ProviderContractError(f"provider HTTP {exc.code}: {provider_body}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise ProviderContractError(f"provider transport failure: {exc}") from exc

    try:
        envelope = json.loads(raw.decode("utf-8"))
        content = envelope["choices"][0]["message"]["content"]
        text = _strip_fence(_content_text(content))
        result = json.loads(text)
    except (KeyError, IndexError, TypeError, json.JSONDecodeError) as exc:
        raise ProviderContractError("provider response did not contain one JSON prediction object") from exc
    if not isinstance(result, Mapping):
        raise ProviderContractError("provider prediction is not a JSON object")
    return result


def main() -> int:
    try:
        raw = sys.stdin.read()
        request_obj = json.loads(raw)
        if not isinstance(request_obj, Mapping):
            raise ProviderContractError("stdin request must be a JSON object")
        result = call_openai_compatible(request_obj)
        # ASCII escaping keeps stdout safe across Windows code pages; json.loads restores
        # the original Unicode values in the SCT parent process.
        sys.stdout.write(json.dumps(result, ensure_ascii=True, sort_keys=True))
        return 0
    except Exception as exc:
        # Generic subprocess contract: errors on stderr, never secret values.
        sys.stderr.write(f"SCT_PROVIDER_ERROR: {exc}\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
