from __future__ import annotations

from typing import Any, Mapping, Sequence

from .errors import EvidenceError
from .r13 import validate_baseline_spec, validate_model_selection_manifest


def _walk(value: Any, path: str = "$" ):
    if isinstance(value, Mapping):
        for key, child in value.items():
            yield from _walk(child, f"{path}.{key}")
    elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        for index, child in enumerate(value):
            yield from _walk(child, f"{path}[{index}]")
    else:
        yield path, value


def reject_template_placeholders(value: Any, *, label: str) -> None:
    for path, item in _walk(value):
        if isinstance(item, str):
            stripped = item.strip()
            if stripped.startswith("__") or "__FILL" in stripped or "__SHA256" in stripped:
                raise EvidenceError(f"{label} contains unresolved template placeholder at {path}")


def validate_model_manifest_for_seal(manifest: Mapping[str, Any]) -> dict[str, Any]:
    reject_template_placeholders(manifest, label="R13 model manifest")
    return validate_model_selection_manifest(manifest)


def validate_baseline_for_seal(spec: Mapping[str, Any]) -> dict[str, Any]:
    reject_template_placeholders(spec, label="R13 Arm B baseline")
    validated = validate_baseline_spec(spec)
    required_hash_fields = (
        "profile_builder_sha256",
        "retrieval_policy_sha256",
        "source_cutoff_sha256",
        "context_selection_policy_sha256",
    )
    for field in required_hash_fields:
        value = validated.get(field)
        if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdefABCDEF" for ch in value):
            raise EvidenceError(f"R13 Arm B baseline requires exact {field}")
    return validated
