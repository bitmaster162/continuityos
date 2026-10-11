"""Offline read-only wire v3 for a hypothetical isolated ContinuityOS broker.

Pure bounded JSON validation and synthetic response shaping ONLY.
No transport, signatures, verified identity, DB reads, keys, witness or IPC.

v3 deliberately breaks the unshipped v1/v2 prototypes: responses carry
SHA-256 of the full canonical request, as well as request identifiers.
A plain digest is NOT message authentication; a hostile sender can forge it.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

PROTOCOL = "continuityos.h3.ipc/v3"
_REQUEST_DIGEST_DOMAIN = b"continuityos.h3.canonical-request.v3\x00"
MAX_REQUEST_BYTES = 16 * 1024
MAX_RESPONSE_BYTES = 8 * 1024
MAX_RESULTS = 10
READ_ONLY_METHODS = frozenset(
    {"memory_status", "list_namespaces", "find", "recall", "context"}
)
_MUTATING_METHODS = frozenset(
    {"remember", "forget", "upsert", "checkpoint", "execute_preflight",
     "preflight_exec", "memory_write_checked", "raw_sql", "dump_db"}
)

_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_NONCE = re.compile(r"[0-9a-f]{32,64}\Z")
_REQUIRED_PARAMS = {
    "memory_status": frozenset(),
    "list_namespaces": frozenset(),
    "find": frozenset({"namespace", "key"}),
    "recall": frozenset({"namespace", "query"}),
    "context": frozenset({"namespace", "query"}),
}
_OPTIONAL_PARAMS = {
    "memory_status": frozenset(),
    "list_namespaces": frozenset(),
    "find": frozenset(),
    "recall": frozenset({"k"}),
    "context": frozenset({"k"}),
}


class ContractError(ValueError):
    """A value violates the strictly bounded, synthetic read-only contract."""


def _invalid(_: str) -> None:
    raise ContractError("non-JSON numeric constant")


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise ContractError("duplicate JSON field")
        result[name] = value
    return result


def _decode(data: bytes, maximum: int) -> Any:
    if type(data) is not bytes or not data or len(data) > maximum:
        raise ContractError("invalid or over-limit payload")
    try:
        return json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicates,
            parse_constant=_invalid,
        )
    except (ValueError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ContractError("malformed payload") from exc


def _exact_keys(
    value: Any,
    required: set[str] | frozenset[str],
    optional: set[str] | frozenset[str] = frozenset(),
) -> dict[str, Any]:
    if type(value) is not dict:
        raise ContractError("expected JSON object")
    if set(value) - set(required) - set(optional) or set(required) - set(value):
        raise ContractError("unknown or missing fields")
    return value


def _bounded_str(
    value: Any, label: str, *, maxlen: int,
    minlen: int = 1, pattern: re.Pattern[str] | None = None,
    newlines: bool = False,
) -> str:
    if type(value) is not str or not minlen <= len(value) <= maxlen:
        raise ContractError(f"{label} must be a bounded string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise ContractError(f"{label} has invalid characters")
    # Exclude control/display-spoofing code points without excluding
    # multilingual letters, combining marks, ZWJ or ZWNJ.
    if any(
        (ord(c) < 32 and not (newlines and c in "\t\n"))
        or 0x7F <= ord(c) <= 0x9F
        or ord(c) in (0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF)
        or 0x202A <= ord(c) <= 0x202E
        or 0x2066 <= ord(c) <= 0x206F
        or 0xD800 <= ord(c) <= 0xDFFF
        for c in value
    ):
        raise ContractError(f"{label} contains an invalid code point")
    if minlen > 0 and not value.strip():
        raise ContractError(f"{label} is blank")
    return value


def _namespace(value: Any) -> str:
    return _bounded_str(value, "namespace", maxlen=64, pattern=_NAMESPACE)


def _count(value: Any, label: str, lower: int, upper: int) -> int:
    if type(value) is not int or not lower <= value <= upper:
        raise ContractError(f"{label} outside integer bounds")
    return value


def _validated_params(method: str, raw: Any) -> tuple[tuple[str, str | int], ...]:
    params = _exact_keys(raw, _REQUIRED_PARAMS[method], _OPTIONAL_PARAMS[method])
    clean: list[tuple[str, str | int]] = []
    for field, value in sorted(params.items()):
        if field == "namespace":
            clean.append((field, _namespace(value)))
        elif field == "key":
            clean.append((field, _bounded_str(value, "key", maxlen=128)))
        elif field == "query":
            clean.append((field, _bounded_str(value, "query", maxlen=2048)))
        elif field == "k":
            clean.append((field, _count(value, "k", 1, MAX_RESULTS)))
        else:
            raise ContractError("unexpected parameter")
    return tuple(clean)


@dataclass(frozen=True, slots=True)
class ReadonlyRequest:
    protocol: str
    request_id: str
    session_id: str
    nonce: str
    method: str
    params: tuple[tuple[str, str | int], ...]

    def __post_init__(self) -> None:
        # Dataclass construction is publicly available: never assume parsing
        # occurred merely because an object has this class.
        validate_request(self)

    def param(self, key: str, default: Any = None) -> Any:
        for name, value in self.params:
            if name == key:
                return value
        return default

    @property
    def namespace(self) -> str | None:
        return self.param("namespace")


@dataclass(frozen=True, slots=True)
class ReadonlyResponse:
    """Status remains explicit so DENIED never resembles NOT_FOUND."""
    status: str
    result: Any


def validate_request(request: ReadonlyRequest) -> None:
    """Check *all* invariants again, including on post-construction mutation."""
    if type(request) is not ReadonlyRequest:
        raise ContractError("validated request required")
    try:
        if type(request.protocol) is not str or request.protocol != PROTOCOL:
            raise ContractError("protocol mismatch")
        _bounded_str(request.request_id, "request_id", maxlen=64, pattern=_ID)
        _bounded_str(request.session_id, "session_id", maxlen=64, pattern=_ID)
        _bounded_str(request.nonce, "nonce", maxlen=64, minlen=32, pattern=_NONCE)
        if type(request.method) is not str or request.method not in READ_ONLY_METHODS:
            raise ContractError("method not in read-only allowlist")
        if type(request.params) is not tuple or len(request.params) > 3:
            raise ContractError("malformed parameter tuple")
        received: dict[str, Any] = {}
        for pair in request.params:
            if type(pair) is not tuple or len(pair) != 2 or type(pair[0]) is not str:
                raise ContractError("malformed parameter pair")
            if pair[0] in received:
                raise ContractError("duplicate parameter")
            received[pair[0]] = pair[1]
        expected = _validated_params(request.method, received)
        if type(request.params) is not tuple or request.params != expected:
            raise ContractError("parameters must be canonical")
    except (AttributeError, TypeError, RecursionError, OverflowError) as exc:
        raise ContractError("invalid request fields") from exc


def canonical_request_bytes(request: ReadonlyRequest) -> bytes:
    """Canonicalize *all* validated request fields, including every param.

    UTF-8, sorted JSON object keys, no whitespace, no NaN; do not perform
    Unicode normalization. Canonicalization does not establish authenticity.
    """
    validate_request(request)
    obj = {
        "protocol": request.protocol,
        "request_id": request.request_id,
        "session_id": request.session_id,
        "nonce": request.nonce,
        "method": request.method,
        "params": dict(request.params),
    }
    try:
        encoded = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ContractError("request cannot be canonicalized") from exc
    if len(encoded) > MAX_REQUEST_BYTES:
        raise ContractError("canonical request exceeds limit")
    return encoded


def request_sha256(request: ReadonlyRequest) -> str:
    """Domain-separated SHA-256 of the *entire* canonical v3 request.

    Public integrity binding only; there is NO MAC, signature, or
    server proof, and this does not prevent replay of the same request.
    """
    return hashlib.sha256(
        _REQUEST_DIGEST_DOMAIN + canonical_request_bytes(request)
    ).hexdigest()


def parse_request(data: bytes) -> ReadonlyRequest:
    raw = _exact_keys(
        _decode(data, MAX_REQUEST_BYTES),
        {"protocol", "request_id", "session_id", "nonce", "method", "params"},
    )
    # The constructor rejects untrusted fields even when passed directly.
    if type(raw["method"]) is not str or raw["method"] not in READ_ONLY_METHODS:
        raise ContractError("method not in read-only allowlist")
    return ReadonlyRequest(
        raw["protocol"], raw["request_id"], raw["session_id"], raw["nonce"],
        raw["method"], _validated_params(raw["method"], raw["params"]),
    )


def make_request(
    *, request_id: str, session_id: str, nonce: str, method: str,
    params: dict[str, Any],
) -> bytes:
    """Serialize a synthetic request. No nonce generation or IPC performed."""
    obj = {
        "protocol": PROTOCOL, "request_id": request_id,
        "session_id": session_id, "nonce": nonce,
        "method": method, "params": params,
    }
    try:
        raw = json.dumps(
            obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ContractError("request cannot be serialized") from exc
    parse_request(raw)
    return raw


def _allowed_namespaces(value: tuple[str, ...]) -> frozenset[str]:
    if type(value) is not tuple or not value or len(value) > 32:
        raise ContractError("verified namespace scope is required")
    result = tuple(_namespace(item) for item in value)
    if len(result) != len(set(result)):
        raise ContractError("duplicate namespace in scope")
    return frozenset(result)


def _memory_record(
    value: Any, request: ReadonlyRequest,
    allowed: frozenset[str], *, exact_key: bool,
) -> dict[str, Any]:
    item = _exact_keys(value, {"namespace", "key", "text"})
    namespace = _namespace(item["namespace"])
    if namespace not in allowed or namespace != request.namespace:
        raise ContractError("record exceeds authorized namespace")
    key = _bounded_str(item["key"], "key", maxlen=128)
    if exact_key and key != request.param("key"):
        raise ContractError("record key mismatches request")
    text = _bounded_str(item["text"], "text", maxlen=2048,
                        minlen=0, newlines=True)
    return {"namespace": namespace, "key": key, "text": text}


def _validate_result(
    request: ReadonlyRequest, result: Any, allowed: frozenset[str],
) -> Any:
    method = request.method
    if method == "memory_status":
        item = _exact_keys(result, {"available"})
        if type(item["available"]) is not bool:
            raise ContractError("availability must be boolean")
        return {"available": item["available"]}
    if method == "list_namespaces":
        if type(result) is not list or len(result) > 32:
            raise ContractError("namespace listing exceeds bounds")
        seen: set[str] = set()
        clean: list[dict[str, Any]] = []
        for entry in result:
            item = _exact_keys(entry, {"namespace", "count"})
            namespace = _namespace(item["namespace"])
            if namespace not in allowed or namespace in seen:
                raise ContractError("namespace listing outside scope or duplicate")
            seen.add(namespace)
            clean.append({
                "namespace": namespace,
                "count": _count(item["count"], "count", 0, 10**7),
            })
        return clean
    if method == "find":
        if result is None:
            raise ContractError("missing key must use not_found status")
        return _memory_record(result, request, allowed, exact_key=True)
    if method == "recall":
        if type(result) is not list or len(result) > request.param("k", 5):
            raise ContractError("recall exceeds result bound")
        return [
            _memory_record(item, request, allowed, exact_key=False)
            for item in result
        ]
    if method == "context":
        if result is None:
            raise ContractError("missing context must use not_found status")
        item = _exact_keys(result, {"namespace", "text"})
        namespace = _namespace(item["namespace"])
        if namespace not in allowed or namespace != request.namespace:
            raise ContractError("context outside scope")
        text = _bounded_str(item["text"], "context", maxlen=4096,
                            minlen=0, newlines=True)
        return {"namespace": namespace, "text": text}
    raise ContractError("method not supported")


def _status_and_result(
    request: ReadonlyRequest, obj: dict[str, Any],
    authorized_namespaces: tuple[str, ...],
) -> ReadonlyResponse:
    status = obj["status"]
    if type(status) is not str:
        raise ContractError("response status invalid")
    result = obj["result"]
    if status == "denied":
        if result is not None:
            raise ContractError("denial must not disclose a result")
        # Denial must always be representable, even with no owner grant,
        # no witness, or an unavailable verified namespace scope.
        return ReadonlyResponse("denied", None)

    allowed = _allowed_namespaces(authorized_namespaces)
    if status == "not_found":
        if request.method not in {"find", "context"}:
            raise ContractError("not_found method invalid")
        if result is not None or request.namespace not in allowed:
            raise ContractError("not_found outside authorized namespace")
        return ReadonlyResponse("not_found", None)
    if status != "ok":
        raise ContractError("response status invalid")
    return ReadonlyResponse("ok", _validate_result(request, result, allowed))


def _response_envelope(request: ReadonlyRequest, status: str, result: Any) -> dict:
    return {
        "protocol": PROTOCOL, "request_id": request.request_id,
        "session_id": request.session_id, "nonce": request.nonce,
        "method": request.method,
        "request_sha256": request_sha256(request),
        "status": status, "result": result,
    }


def parse_response(
    data: bytes, *, request: ReadonlyRequest,
    authorized_namespaces: tuple[str, ...],
) -> ReadonlyResponse:
    """Bind a *synthetic* response envelope; no cryptographic server proof."""
    validate_request(request)
    obj = _exact_keys(
        _decode(data, MAX_RESPONSE_BYTES),
        {"protocol", "request_id", "session_id", "nonce",
         "method", "request_sha256", "status", "result"},
    )
    bound_digest = obj["request_sha256"]
    if (type(bound_digest) is not str or len(bound_digest) != 64
            or any(char not in "0123456789abcdef" for char in bound_digest)
            or bound_digest != request_sha256(request)):
        raise ContractError("canonical request digest mismatch")
    if any(
        type(obj[field]) is not str or obj[field] != getattr(request, field)
        for field in ("protocol", "request_id", "session_id", "nonce", "method")
    ):
        raise ContractError("response binding mismatch")
    return _status_and_result(request, obj, authorized_namespaces)


def make_response(
    *, request: ReadonlyRequest, result: Any,
    authorized_namespaces: tuple[str, ...],
    denied: bool = False, not_found: bool = False,
) -> bytes:
    """Build a bounded v3 fixture result; never authorize a real disclosure."""
    validate_request(request)
    if type(denied) is not bool or type(not_found) is not bool:
        raise ContractError("status flags must be booleans")
    if denied and not_found:
        raise ContractError("conflicting response statuses")
    status = "denied" if denied else ("not_found" if not_found else "ok")
    parsed = _status_and_result(
        request, {"status": status, "result": result},
        authorized_namespaces,
    )
    try:
        raw = json.dumps(
            _response_envelope(request, parsed.status, parsed.result),
            sort_keys=True, separators=(",", ":"), ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError) as exc:
        raise ContractError("result cannot be serialized") from exc
    parse_response(raw, request=request, authorized_namespaces=authorized_namespaces)
    return raw
