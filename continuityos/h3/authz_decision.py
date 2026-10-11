"""Fail-closed, in-memory H3 admission decision model.

All evidence is an explicit *assumption* supplied by a synthetic fixture.
This module does NOT verify Windows tokens, RPC authentication, owner
signatures, trusted broker identity, witness freshness, or nonce persistence.
It does NOT confer runtime authority and has no side effects.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .readonly_contract import (
    READ_ONLY_METHODS, ContractError, ReadonlyRequest, validate_request,
)

_USER_SID = re.compile(r"S-1-5-21-(?:[0-9]+-){3}[0-9]+\Z")
_PACKAGE_SID = re.compile(r"S-1-15-2-(?:[0-9]+-){6}[0-9]+\Z")
_NAMESPACE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
_INSTALLATION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
LOW_IL_SID = "S-1-16-4096"


class PolicyError(ValueError):
    """A pinned policy is absent, invalid or broader than H3 read-only scope."""


def _bounded_tuple(value: object, kind: str, limit: int = 32) -> tuple[str, ...]:
    if type(value) is not tuple or not value or len(value) > limit:
        raise PolicyError(f"{kind} must be a nonempty bounded tuple")
    if any(type(s) is not str for s in value) or len(set(value)) != len(value):
        raise PolicyError(f"{kind} must have unique string members")
    return value


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    """Owner-pinned expected IDs/scope. Construction is not owner approval."""

    expected_user_sid: str
    expected_appcontainer_sid: str
    installation_id: str
    permitted_methods: tuple[str, ...]
    permitted_namespaces: tuple[str, ...]

    def __post_init__(self) -> None:
        if type(self.expected_user_sid) is not str or not _USER_SID.fullmatch(
            self.expected_user_sid
        ):
            raise PolicyError("expected user SID missing or invalid")
        if type(self.expected_appcontainer_sid) is not str or not _PACKAGE_SID.fullmatch(
            self.expected_appcontainer_sid
        ):
            raise PolicyError("expected AppContainer SID missing or invalid")
        if type(self.installation_id) is not str or not _INSTALLATION.fullmatch(
            self.installation_id
        ):
            raise PolicyError("installation ID missing or invalid")
        methods = _bounded_tuple(self.permitted_methods, "methods")
        namespaces = _bounded_tuple(self.permitted_namespaces, "namespaces")
        if any(method not in READ_ONLY_METHODS for method in methods):
            raise PolicyError("mutation/unknown method prohibited")
        if any(_NAMESPACE.fullmatch(ns) is None for ns in namespaces):
            raise PolicyError("invalid namespace scope")


@dataclass(frozen=True, slots=True)
class BrokerEvidence:
    origin: str
    principal_separate: bool
    trusted_service_token: bool
    owner_pin_verified: bool
    signing_key_use_exclusive: bool
    endpoint_proof_verified: bool
    trust_epoch_current: bool


@dataclass(frozen=True, slots=True)
class TransportEvidence:
    protocol: str
    local_only: bool
    secure_only: bool
    packet_privacy: bool
    interface_acl_passed: bool
    security_callback_per_call: bool
    callback_not_cached: bool
    call_bound: bool


@dataclass(frozen=True, slots=True)
class ClientEvidence:
    origin: str
    token_user_sid: str
    token_package_sid: str
    token_is_appcontainer: bool
    integrity_sid: str
    capability_sids: tuple[str, ...]
    impersonation_succeeded: bool
    impersonation_level: str
    revert_to_self_succeeded: bool


@dataclass(frozen=True, slots=True)
class GrantEvidence:
    origin: str
    signature_verified: bool
    active: bool
    user_sid: str
    package_sid: str
    installation_id: str
    permitted_methods: tuple[str, ...]
    permitted_namespaces: tuple[str, ...]
    session_id: str
    bound_to_session: bool


@dataclass(frozen=True, slots=True)
class WitnessEvidence:
    origin: str
    current: bool
    epoch_matches: bool
    revoked: bool
    rechecked_before_disclosure: bool


@dataclass(frozen=True, slots=True)
class ReplayEvidence:
    origin: str
    session_id: str
    request_id: str
    nonce: str
    fresh: bool
    atomic_committed: bool


@dataclass(frozen=True, slots=True)
class AdmissionEvidence:
    broker: BrokerEvidence
    transport: TransportEvidence
    client: ClientEvidence
    grant: GrantEvidence
    witness: WitnessEvidence
    replay: ReplayEvidence


@dataclass(frozen=True, slots=True)
class AdmissionResult:
    verdict: str  # MODEL_ALLOW or DENY; MODEL_ALLOW is NOT a runtime capability.
    reason: str
    visible_namespaces: tuple[str, ...] = ()

    @property
    def model_allowed(self) -> bool:
        return self.verdict == "MODEL_ALLOW"


def _deny(reason: str) -> AdmissionResult:
    return AdmissionResult("DENY", reason, ())


def _exact_evidence_fields(
    value: object, *,
    strings: tuple[str, ...] = (),
    flags: tuple[str, ...] = (),
    tuples: tuple[str, ...] = (),
) -> bool:
    """Check plain primitive field types before any attacker-defined equality.

    Evidence objects are synthetic and publicly constructible. A forged
    AlwaysEqual/raises-on-comparison object must never reach ==, !=, set,
    regex, or an authorization predicate. This checks shape, NOT provenance.
    """
    try:
        return (
            all(type(getattr(value, name)) is str for name in strings)
            and all(type(getattr(value, name)) is bool for name in flags)
            and all(type(getattr(value, name)) is tuple for name in tuples)
        )
    except Exception:
        return False


def decide(request: ReadonlyRequest, policy: AdmissionPolicy,
           evidence: AdmissionEvidence) -> AdmissionResult:
    """Evaluate synthetic facts; UNKNOWN, malformed or failed gates -> DENY.

    Do not call from a real transport as an authentication replacement:
    Python callers can construct/falsify these evidence objects. The
    producer/provenance of each evidence field must be separately implemented
    and independently audited at the OS/cryptographic boundary.
    """
    if (type(request) is not ReadonlyRequest
            or type(policy) is not AdmissionPolicy
            or type(evidence) is not AdmissionEvidence):
        return _deny("UNVERIFIED_INPUT")

    # Publicly constructed/mutated dataclasses do not prove that a trusted
    # parser or policy verifier ran; revalidate at the admission boundary.
    try:
        validate_request(request)
        policy.__post_init__()
    except Exception:
        return _deny("REQUEST_OR_POLICY_INVALID")

    # Dataclasses can also be allocated without __init__; missing attributes
    # must produce a deterministic DENY rather than an AttributeError.
    try:
        typed_evidence = (
            type(evidence.broker) is BrokerEvidence
            and type(evidence.transport) is TransportEvidence
            and type(evidence.client) is ClientEvidence
            and type(evidence.grant) is GrantEvidence
            and type(evidence.witness) is WitnessEvidence
            and type(evidence.replay) is ReplayEvidence
        )
    except Exception:
        return _deny("UNVERIFIED_EVIDENCE_TYPE")
    if not typed_evidence:
        return _deny("UNVERIFIED_EVIDENCE_TYPE")

    b = evidence.broker
    if (not _exact_evidence_fields(
            b, strings=("origin",),
            flags=("principal_separate", "trusted_service_token",
                   "owner_pin_verified", "signing_key_use_exclusive",
                   "endpoint_proof_verified", "trust_epoch_current"))
            or b.origin != "owner_pinned_broker_trust"
            or b.principal_separate is not True
            or b.trusted_service_token is not True
            or b.owner_pin_verified is not True
            or b.signing_key_use_exclusive is not True
            or b.endpoint_proof_verified is not True
            or b.trust_epoch_current is not True):
        return _deny("BROKER_TRUST_UNVERIFIED")

    t = evidence.transport
    if (not _exact_evidence_fields(
            t, strings=("protocol",),
            flags=("local_only", "secure_only", "packet_privacy",
                   "interface_acl_passed", "security_callback_per_call",
                   "callback_not_cached", "call_bound"))
            or t.protocol != "ncalrpc" or t.local_only is not True
            or t.secure_only is not True or t.packet_privacy is not True
            or t.interface_acl_passed is not True
            or t.security_callback_per_call is not True
            or t.callback_not_cached is not True or t.call_bound is not True):
        return _deny("RPC_BOUNDARY_UNVERIFIED")

    c = evidence.client
    if (not _exact_evidence_fields(
            c,
            strings=("origin", "token_user_sid", "token_package_sid",
                     "integrity_sid", "impersonation_level"),
            flags=("token_is_appcontainer", "impersonation_succeeded",
                   "revert_to_self_succeeded"),
            tuples=("capability_sids",))
            or c.origin != "active_rpc_call_os_token"
            or c.token_is_appcontainer is not True
            or c.token_user_sid != policy.expected_user_sid
            or c.token_package_sid != policy.expected_appcontainer_sid
            or c.integrity_sid != LOW_IL_SID
            or type(c.capability_sids) is not tuple
            or c.capability_sids != ()
            or c.impersonation_succeeded is not True
            or c.impersonation_level != "Impersonation"
            or c.revert_to_self_succeeded is not True):
        return _deny("CLIENT_OS_IDENTITY_UNVERIFIED")

    g = evidence.grant
    if (not _exact_evidence_fields(
            g, strings=("origin", "user_sid", "package_sid",
                        "installation_id", "session_id"),
            flags=("signature_verified", "active", "bound_to_session"),
            tuples=("permitted_methods", "permitted_namespaces"))
            or g.origin != "owner_signature_verifier"
            or g.signature_verified is not True or g.active is not True
            or g.user_sid != policy.expected_user_sid
            or g.package_sid != policy.expected_appcontainer_sid
            or g.installation_id != policy.installation_id
            or g.session_id != request.session_id
            or g.bound_to_session is not True
            or type(g.permitted_methods) is not tuple
            or type(g.permitted_namespaces) is not tuple
            or not 0 < len(g.permitted_methods) <= len(READ_ONLY_METHODS)
            or not 0 < len(g.permitted_namespaces) <= 32
            or any(type(item) is not str or item not in READ_ONLY_METHODS
                   for item in g.permitted_methods)
            or any(type(item) is not str or _NAMESPACE.fullmatch(item) is None
                   for item in g.permitted_namespaces)
            or len(set(g.permitted_methods)) != len(g.permitted_methods)
            or len(set(g.permitted_namespaces)) != len(g.permitted_namespaces)):
        return _deny("OWNER_GRANT_UNVERIFIED")

    if (request.method not in READ_ONLY_METHODS
            or request.method not in policy.permitted_methods
            or request.method not in g.permitted_methods):
        return _deny("METHOD_DENIED")

    visible = tuple(sorted(set(policy.permitted_namespaces) & set(g.permitted_namespaces)))
    if not visible:
        return _deny("NO_PERMITTED_NAMESPACES")
    if request.namespace is not None and request.namespace not in visible:
        return _deny("NAMESPACE_DENIED")
    if (request.method in {"find", "recall", "context"}
            and request.namespace is None):
        return _deny("UNSCOPED_READ_DENIED")

    w = evidence.witness
    if (not _exact_evidence_fields(
            w, strings=("origin",),
            flags=("current", "epoch_matches", "revoked",
                   "rechecked_before_disclosure"))
            or w.origin != "independent_witness"
            or w.current is not True or w.epoch_matches is not True
            or w.revoked is not False
            or w.rechecked_before_disclosure is not True):
        return _deny("WITNESS_UNVERIFIED_OR_REVOKED")

    rp = evidence.replay
    if (not _exact_evidence_fields(
            rp, strings=("origin", "session_id", "request_id", "nonce"),
            flags=("fresh", "atomic_committed"))
            or rp.origin != "atomic_replay_store"
            or rp.session_id != request.session_id
            or rp.request_id != request.request_id
            or rp.nonce != request.nonce
            or rp.fresh is not True or rp.atomic_committed is not True):
        return _deny("REPLAY_OR_SESSION_UNVERIFIED")
    return AdmissionResult("MODEL_ALLOW", "ALL_SYNTHETIC_GATES_ASSUMED", visible)
