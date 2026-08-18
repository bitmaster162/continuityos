from __future__ import annotations

from typing import Any, Mapping, Sequence

from .baseline_r13 import baseline_policy_hashes
from .errors import EvidenceError
from .r13 import validate_baseline_spec, validate_model_selection_manifest


def _walk(value: Any, path: str = "$"):
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")
    else:
        yield path, value


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdefABCDEF" for ch in value)


def reject_template_placeholders(value: Any, *, label: str) -> None:
    for path, item in _walk(value):
        if isinstance(item, str):
            stripped = item.strip()
            if stripped.startswith("__") or "__FILL" in stripped or "__SHA256" in stripped:
                raise EvidenceError(f"{label} contains unresolved template placeholder at {path}")


def _require_hash_mapping(value: Any, field: str) -> None:
    if not isinstance(value, Mapping) or not value:
        raise EvidenceError(f"R13 model manifest requires non-empty {field}")
    for name, digest in value.items():
        if not isinstance(name, str) or not name.strip() or not _is_sha256(digest):
            raise EvidenceError(f"R13 model manifest requires exact SHA-256 values in {field}")


def validate_model_manifest_for_seal(manifest: Mapping[str, Any]) -> dict[str, Any]:
    reject_template_placeholders(manifest, label="R13 model manifest")
    validated = validate_model_selection_manifest(manifest)
    _require_hash_mapping(validated.get("weight_hashes"), "weight_hashes")
    _require_hash_mapping(validated.get("tokenizer_hashes"), "tokenizer_hashes")
    return validated


def validate_baseline_for_seal(spec: Mapping[str, Any]) -> dict[str, Any]:
    reject_template_placeholders(spec, label="R13 Arm B baseline")
    validated = validate_baseline_spec(spec)
    expected = baseline_policy_hashes()
    for field, digest in expected.items():
        if not _is_sha256(validated.get(field)):
            raise EvidenceError(f"R13 Arm B baseline requires exact {field}")
        if validated.get(field) != digest:
            raise EvidenceError(f"R13 Arm B baseline {field} does not match frozen implementation policy")
    return validated
