"""Pure consumer-side acceptance for verified Cross-AI RUAP transport receipts.

This module accepts only a supplied public transport receipt that first passes the
standalone Cross-AI RUAP transport verifier. It copies only bounded evidence and
governance metadata into a deterministic in-process acceptance record.

Acceptance here means closed-shape and self-consistency validation only. It does
not prove cryptographic authenticity, trusted provenance, or signer identity, and
it does not promote the receipt into current truth. No provider, network,
credential, connector configuration, filesystem, environment, runtime, pointer,
memory, subprocess, deployment, trading, or capital effects are performed.
"""
from __future__ import annotations

from typing import Any

from .cross_ai_ruap_transport_verifier import (
    require_valid_cross_ai_ruap_transport_receipt,
)


SCHEMA = "continuityos.cross_ai_ruap_receipt_acceptance/v1"
MODE = "EVIDENCE_ONLY"
ACCEPTANCE_CLASS = "STRUCTURAL_SELF_CONSISTENCY_ONLY"


def accept_cross_ai_ruap_transport_receipt(receipt: Any) -> dict[str, Any]:
    """Accept one verified public transport receipt into a bounded evidence record."""
    verified = require_valid_cross_ai_ruap_transport_receipt(receipt)
    evidence = verified["ruap_evidence"]

    return {
        "schema": SCHEMA,
        "mode": MODE,
        "acceptance_class": ACCEPTANCE_CLASS,
        "transport_id": verified["transport_id"],
        "source_client": verified["source_client"],
        "target_client": verified["target_client"],
        "ruap_evidence": {
            "schema": evidence["schema"],
            "snapshot_sha256": evidence["snapshot_sha256"],
            "source_count": evidence["source_count"],
            "observation_count": evidence["observation_count"],
            "freshness_required": evidence["freshness_required"],
            "authority_ceiling": evidence["authority_ceiling"],
            "authority_class": evidence["authority_class"],
        },
        "verification": {
            "shape_verified": True,
            "integrity_checked": True,
            "authenticity_verified": False,
            "provenance_verified": False,
            "signer_identity_verified": False,
            "current_truth_promoted": False,
        },
        "execution_authority": "NONE",
        "can_execute": False,
        "can_trade": False,
        "capital_permission": "DENY",
        "deploy_permission": "DENY",
    }
