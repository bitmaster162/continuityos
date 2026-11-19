"""Deterministic H3 admission model tests; all security evidence is simulated."""
from __future__ import annotations

import unittest
from dataclasses import replace

from continuityos.h3.readonly_contract import (
    ContractError, ReadonlyRequest, make_request, parse_request,
    READ_ONLY_METHODS,
)
from continuityos.h3.authz_decision import (
    AdmissionEvidence, AdmissionPolicy, AdmissionResult,
    BrokerEvidence, ClientEvidence, GrantEvidence, PolicyError, ReplayEvidence,
    TransportEvidence, WitnessEvidence, decide, LOW_IL_SID,
)

USER = "S-1-5-21-100-200-300-1001"
PACKAGE = "S-1-15-2-11-22-33-44-55-66-77"
NONCE = "0123456789abcdef0123456789abcdef"
INSTALLATION = "synthetic-h3-installation"


def policy():
    return AdmissionPolicy(
        expected_user_sid=USER,
        expected_appcontainer_sid=PACKAGE,
        installation_id=INSTALLATION,
        permitted_methods=("memory_status", "list_namespaces", "find",
                           "recall", "context"),
        permitted_namespaces=("research", "notes"),
    )


def request(method="find", namespace="research"):
    params = {
        "memory_status": {},
        "list_namespaces": {},
        "find": {"namespace": namespace, "key": "item-1"},
        "recall": {"namespace": namespace, "query": "synthetic"},
        "context": {"namespace": namespace, "query": "synthetic"},
    }[method]
    return parse_request(
        make_request(
            request_id="request-001", session_id="session-001", nonce=NONCE,
            method=method, params=params,
        )
    )


def evidence():
    """Fixture assertions; these are not genuine OS, signature or witness proofs."""
    return AdmissionEvidence(
        broker=BrokerEvidence(
            origin="owner_pinned_broker_trust",
            principal_separate=True,
            trusted_service_token=True,
            owner_pin_verified=True,
            signing_key_use_exclusive=True,
            endpoint_proof_verified=True,
            trust_epoch_current=True,
        ),
        transport=TransportEvidence(
            protocol="ncalrpc",
            local_only=True,
            secure_only=True,
            packet_privacy=True,
            interface_acl_passed=True,
            security_callback_per_call=True,
            callback_not_cached=True,
            call_bound=True,
        ),
        client=ClientEvidence(
            origin="active_rpc_call_os_token",
            token_user_sid=USER,
            token_package_sid=PACKAGE,
            token_is_appcontainer=True,
            integrity_sid=LOW_IL_SID,
            capability_sids=(),
            impersonation_succeeded=True,
            impersonation_level="Impersonation",
            revert_to_self_succeeded=True,
        ),
        grant=GrantEvidence(
            origin="owner_signature_verifier",
            signature_verified=True,
            active=True,
            user_sid=USER,
            package_sid=PACKAGE,
            installation_id=INSTALLATION,
            permitted_methods=("find", "recall", "context",
                               "memory_status", "list_namespaces"),
            permitted_namespaces=("research",),
            session_id="session-001",
            bound_to_session=True,
        ),
        witness=WitnessEvidence(
            origin="independent_witness",
            current=True,
            epoch_matches=True,
            revoked=False,
            rechecked_before_disclosure=True,
        ),
        replay=ReplayEvidence(
            origin="atomic_replay_store",
            session_id="session-001",
            request_id="request-001",
            nonce=NONCE,
            fresh=True,
            atomic_committed=True,
        ),
    )


def with_change(original: AdmissionEvidence, area: str, **fields):
    return replace(original, **{
        area: replace(getattr(original, area), **fields)
    })


class PolicyValidationTests(unittest.TestCase):
    def test_expected_pinned_policy_accepts_synthetic_sids(self):
        p = policy()
        self.assertEqual(p.expected_user_sid, USER)
        self.assertEqual(p.expected_appcontainer_sid, PACKAGE)

    def test_missing_or_malformed_user_sid_refused(self):
        for value in ("", "S-1-5-18", "S-1-5-21-100", "guest", 123):
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    replace(policy(), expected_user_sid=value)

    def test_invalid_appcontainer_sid_refused(self):
        for value in ("S-1-5-21-100-200-300-1001", "S-1-15-2-11", "x", None):
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    replace(policy(), expected_appcontainer_sid=value)

    def test_invalid_installation_id_refused(self):
        for value in ("", "with spaces", "x" * 65, None):
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    replace(policy(), installation_id=value)

    def test_mutating_methods_cannot_enter_policy(self):
        for method in ("remember", "forget", "upsert", "execute_preflight",
                       "preflight_exec", "raw_sql"):
            with self.subTest(method=method):
                with self.assertRaises(PolicyError):
                    replace(policy(), permitted_methods=("find", method))

    def test_empty_or_duplicate_scopes_refused(self):
        for value in ((), ("research", "research"), ("secrets/",),
                      ("bad name",), ("research", 12)):
            with self.subTest(value=value):
                with self.assertRaises(PolicyError):
                    replace(policy(), permitted_namespaces=value)

    def test_methods_are_bounded(self):
        with self.assertRaises(PolicyError):
            replace(policy(), permitted_methods=())


class AdmissionModelTests(unittest.TestCase):
    def setUp(self):
        self.p = policy()
        self.ev = evidence()
        self.req = request()

    def assertDenied(self, r, reason=None):
        self.assertEqual("DENY", r.verdict)
        self.assertEqual((), r.visible_namespaces)
        self.assertFalse(r.model_allowed)
        if reason is not None:
            self.assertEqual(reason, r.reason)

    def test_positive_is_model_allow_not_runtime_permission(self):
        result = decide(self.req, self.p, self.ev)
        self.assertEqual("MODEL_ALLOW", result.verdict)
        self.assertEqual(("research",), result.visible_namespaces)
        self.assertTrue(result.model_allowed)
        self.assertIn("SYNTHETIC", result.reason)

    def test_approved_metadata_methods_remain_scoped(self):
        for method in ("memory_status", "list_namespaces", "find",
                       "recall", "context"):
            with self.subTest(method=method):
                result = decide(request(method), self.p, self.ev)
                self.assertEqual("MODEL_ALLOW", result.verdict)
                self.assertEqual(("research",), result.visible_namespaces)

    def test_unapproved_namespace_denied_even_if_policy_lists_it(self):
        self.assertDenied(
            decide(request("find", "notes"), self.p, self.ev),
            "NAMESPACE_DENIED"
        )

    def test_replay_nonce_must_match_entire_envelope(self):
        for field, value in (("nonce", "f" * 32),
                             ("request_id", "request-002"),
                             ("session_id", "session-002")):
            with self.subTest(field=field):
                changed = with_change(self.ev, "replay", **{field: value})
                self.assertDenied(
                    decide(self.req, self.p, changed),
                    "REPLAY_OR_SESSION_UNVERIFIED"
                )

    def test_grant_method_cannot_be_broadened(self):
        changed = with_change(
            self.ev, "grant", permitted_methods=("recall", "context")
        )
        self.assertDenied(decide(self.req, self.p, changed), "METHOD_DENIED")

    def test_policy_method_cannot_be_broadened(self):
        changed = replace(self.p, permitted_methods=("memory_status",))
        self.assertDenied(decide(self.req, changed, self.ev), "METHOD_DENIED")

    def test_denies_unverified_types(self):
        for p, ev, req in ((None, self.ev, self.req),
                           (self.p, None, self.req),
                           (self.p, self.ev, None),
                           (self.p, "dict source", self.req)):
            with self.subTest(kind=str(type(ev))):
                self.assertDenied(decide(req, p, ev), "UNVERIFIED_INPUT")

    def test_unknown_client_evidence_instance_refused(self):
        changed = replace(self.ev, client={"token_is_appcontainer": True})
        self.assertDenied(
            decide(self.req, self.p, changed),
            "UNVERIFIED_EVIDENCE_TYPE"
        )

    def test_minimal_denial_reason_has_no_private_evidence(self):
        result = decide(self.req, self.p, with_change(
            self.ev, "client", token_package_sid="S-1-15-2-1-2-3-4-5-6-7"
        ))
        self.assertNotIn("S-1-", result.reason)
        self.assertEqual((), result.visible_namespaces)

    def test_forged_caller_os_fields_refused_by_wire_contract(self):
        with self.assertRaises(ContractError):
            make_request(
                request_id="request-001", session_id="session-001",
                nonce=NONCE, method="find",
                params={"namespace": "research", "key": "item-1",
                        "token_user_sid": USER},
            )

    def test_malformed_grant_scopes_fail_closed_without_exception(self):
        for value in ((["research"],), ("research", ["unexpected"]),
                      ({"namespace": "research"},), ("research", None)):
            with self.subTest(value=value):
                changed = with_change(
                    self.ev, "grant", permitted_namespaces=value
                )
                self.assertDenied(
                    decide(self.req, self.p, changed),
                    "OWNER_GRANT_UNVERIFIED"
                )

    def test_malformed_grant_methods_fail_closed_without_exception(self):
        for value in ((["find"],), ("find", None), ("find", True)):
            with self.subTest(value=value):
                changed = with_change(
                    self.ev, "grant", permitted_methods=value
                )
                self.assertDenied(
                    decide(self.req, self.p, changed),
                    "OWNER_GRANT_UNVERIFIED"
                )

    def test_no_mutating_method_in_readonly_methods(self):
        self.assertTrue(set(READ_ONLY_METHODS).isdisjoint(
            {"remember", "forget", "upsert", "execute_preflight"}
        ))

    def test_40_broker_transport_client_grant_witness_replay_denials(self):
        """Every mutation below is a separate negative case in the subtest matrix."""
        mutations = (
            ("broker", "origin", "untrusted"),
            ("broker", "principal_separate", False),
            ("broker", "trusted_service_token", False),
            ("broker", "owner_pin_verified", False),
            ("broker", "signing_key_use_exclusive", False),
            ("broker", "endpoint_proof_verified", False),
            ("broker", "trust_epoch_current", False),
            ("transport", "protocol", "ncacn_np"),
            ("transport", "local_only", False),
            ("transport", "secure_only", False),
            ("transport", "packet_privacy", False),
            ("transport", "interface_acl_passed", False),
            ("transport", "security_callback_per_call", False),
            ("transport", "callback_not_cached", False),
            ("transport", "call_bound", False),
            ("client", "origin", "caller_json"),
            ("client", "token_user_sid", "S-1-5-21-1-2-3-4"),
            ("client", "token_package_sid", "S-1-15-2-1-2-3-4-5-6-7"),
            ("client", "token_is_appcontainer", False),
            ("client", "integrity_sid", "S-1-16-8192"),
            ("client", "capability_sids", ("unexpected",)),
            ("client", "impersonation_succeeded", False),
            ("client", "impersonation_level", "Identification"),
            ("client", "revert_to_self_succeeded", False),
            ("grant", "origin", "client_payload"),
            ("grant", "signature_verified", False),
            ("grant", "active", False),
            ("grant", "user_sid", "S-1-5-21-1-2-3-4"),
            ("grant", "package_sid", "S-1-15-2-1-2-3-4-5-6-7"),
            ("grant", "installation_id", "another-install"),
            ("grant", "session_id", "different-session"),
            ("grant", "bound_to_session", False),
            ("witness", "origin", "local_untrusted"),
            ("witness", "current", False),
            ("witness", "epoch_matches", False),
            ("witness", "revoked", True),
            ("witness", "rechecked_before_disclosure", False),
            ("replay", "origin", "caller_flag"),
            ("replay", "fresh", False),
            ("replay", "atomic_committed", False),
        )
        for area, field, value in mutations:
            with self.subTest(area=area, field=field):
                mutated = with_change(self.ev, area, **{field: value})
                decision = decide(self.req, self.p, mutated)
                self.assertDenied(decision, {
                    "broker": "BROKER_TRUST_UNVERIFIED",
                    "transport": "RPC_BOUNDARY_UNVERIFIED",
                    "client": "CLIENT_OS_IDENTITY_UNVERIFIED",
                    "grant": "OWNER_GRANT_UNVERIFIED",
                    "witness": "WITNESS_UNVERIFIED_OR_REVOKED",
                    "replay": "REPLAY_OR_SESSION_UNVERIFIED",
                }[area])

    def test_non_boolean_truthy_markers_denied(self):
        cases = (
            ("broker", "principal_separate", 1),
            ("client", "token_is_appcontainer", 1),
            ("grant", "signature_verified", 1),
            ("witness", "revoked", 0),
            ("replay", "atomic_committed", 1),
        )
        for area, field, value in cases:
            with self.subTest(area=area, field=field):
                changed = with_change(self.ev, area, **{field: value})
                self.assertDenied(decide(self.req, self.p, changed))

    def test_readonly_grant_scopes_intersect_pinned_policy(self):
        grant = replace(self.ev.grant, permitted_namespaces=("research", "other"))
        result = decide(self.req, self.p, replace(self.ev, grant=grant))
        self.assertEqual(("research",), result.visible_namespaces)

    def test_empty_namespace_intersection_denied(self):
        changed = with_change(self.ev, "grant",
                              permitted_namespaces=("unknown",))
        self.assertDenied(decide(self.req, self.p, changed),
                          "NO_PERMITTED_NAMESPACES")

    def test_replay_unknown_not_assumed_fresh(self):
        changed = with_change(self.ev, "replay", fresh=None)
        self.assertDenied(decide(self.req, self.p, changed),
                          "REPLAY_OR_SESSION_UNVERIFIED")


class V2AdmissionHardeningTests(unittest.TestCase):
    """Adversarial checks remain synthetic: no verified identity producer."""

    def setUp(self):
        self.p = policy()
        self.req = request()
        self.ev = evidence()

    def assertDenied(self, outcome, reason=None):
        self.assertEqual(outcome.verdict, "DENY")
        self.assertFalse(outcome.model_allowed)
        self.assertEqual(outcome.visible_namespaces, ())
        if reason:
            self.assertEqual(outcome.reason, reason)

    def test_grant_session_identifier_compared_not_only_boolean(self):
        altered = with_change(self.ev, "grant", session_id="other-session")
        self.assertDenied(
            decide(self.req, self.p, altered),
            "OWNER_GRANT_UNVERIFIED",
        )

    def test_grant_session_reuse_with_fresh_matching_replay_denied(self):
        other_req = parse_request(make_request(
            request_id=self.req.request_id, session_id="session-002",
            nonce=self.req.nonce, method="find",
            params={"namespace": "research", "key": "item-1"},
        ))
        new_replay = with_change(
            self.ev, "replay", session_id="session-002",
        )
        self.assertDenied(
            decide(other_req, self.p, new_replay),
            "OWNER_GRANT_UNVERIFIED",
        )

    def test_matching_grant_session_allows_only_synthetic_predicate(self):
        outcome = decide(self.req, self.p, self.ev)
        self.assertEqual(outcome.verdict, "MODEL_ALLOW")
        self.assertIn("SYNTHETIC", outcome.reason)

    def test_direct_ctor_rejects_missing_or_invalid_parameters(self):
        base = self.req
        for method, params in (
            ("find", (("namespace", "research"),)),
            ("find", None),
            (["find"], base.params),
            ("find", (("namespace", "research"), ("key", "item-1"),
                       ("key", "other"))),
        ):
            with self.subTest(method=str(method), params=str(params)):
                with self.assertRaises(ContractError):
                    ReadonlyRequest(
                        base.protocol, base.request_id, base.session_id,
                        base.nonce, method, params,
                    )

    def test_object_setattr_bypass_rechecked_on_every_admission(self):
        for field, invalid in (
            ("protocol", "continuityos.h3.ipc/v1"),
            ("method", ["find"]),
            ("params", None),
            ("nonce", "wrong"),
            ("request_id", []),
            ("session_id", None),
            ("params", (("namespace", "research"),)),
        ):
            with self.subTest(field=field, invalid=str(invalid)):
                item = request()
                object.__setattr__(item, field, invalid)
                self.assertDenied(
                    decide(item, self.p, self.ev),
                    "REQUEST_OR_POLICY_INVALID",
                )

    def test_missing_attrs_fail_closed(self):
        item = object.__new__(ReadonlyRequest)
        self.assertDenied(
            decide(item, self.p, self.ev),
            "REQUEST_OR_POLICY_INVALID",
        )

    def test_mutated_policy_fails_closed(self):
        for field, invalid in (
            ("permitted_methods", ("find", "upsert")),
            ("permitted_namespaces", ("research", ["other"])),
            ("expected_appcontainer_sid", "malformed"),
            ("expected_user_sid", None),
        ):
            with self.subTest(field=field):
                p = policy()
                object.__setattr__(p, field, invalid)
                self.assertDenied(
                    decide(self.req, p, self.ev),
                    "REQUEST_OR_POLICY_INVALID",
                )

    def test_owner_grant_scope_values_bounded_and_unique(self):
        for fields in (
            {"permitted_methods": ("find", "find")},
            {"permitted_methods": ("find", "upsert")},
            {"permitted_methods": ()},
            {"permitted_namespaces": ()},
            {"permitted_namespaces": ("research", "research")},
            {"permitted_namespaces": ("research", "bad/name")},
            {"permitted_namespaces": tuple("ns%d" % i for i in range(34))},
        ):
            with self.subTest(fields=fields):
                altered = with_change(self.ev, "grant", **fields)
                self.assertDenied(
                    decide(self.req, self.p, altered),
                    "OWNER_GRANT_UNVERIFIED",
                )

    def test_forged_evidence_remains_only_a_synthetic_allow(self):
        # This demonstrates the boundary that still needs a real OS/crypto
        # evidence producer. A caller can manufacture this entire structure.
        forged = evidence()
        outcome = decide(self.req, self.p, forged)
        self.assertEqual(outcome.verdict, "MODEL_ALLOW")
        self.assertEqual(outcome.reason, "ALL_SYNTHETIC_GATES_ASSUMED")
        self.assertIsInstance(outcome, AdmissionResult)

    def test_nonce_replay_still_requires_external_atomic_producer(self):
        altered = with_change(self.ev, "replay", atomic_committed=False)
        self.assertDenied(
            decide(self.req, self.p, altered),
            "REPLAY_OR_SESSION_UNVERIFIED",
        )


class R6B5EvidenceTypeHardeningTests(unittest.TestCase):
    """Malicious Python values must DENY, never compare as proof or escape."""

    _STRINGS = {
        "broker": ("origin",),
        "transport": ("protocol",),
        "client": ("origin", "token_user_sid", "token_package_sid",
                   "integrity_sid", "impersonation_level"),
        "grant": ("origin", "user_sid", "package_sid",
                  "installation_id", "session_id"),
        "witness": ("origin",),
        "replay": ("origin", "session_id", "request_id", "nonce"),
    }
    _FLAGS = {
        "broker": ("principal_separate", "trusted_service_token",
                   "owner_pin_verified", "signing_key_use_exclusive",
                   "endpoint_proof_verified", "trust_epoch_current"),
        "transport": ("local_only", "secure_only", "packet_privacy",
                      "interface_acl_passed", "security_callback_per_call",
                      "callback_not_cached", "call_bound"),
        "client": ("token_is_appcontainer", "impersonation_succeeded",
                   "revert_to_self_succeeded"),
        "grant": ("signature_verified", "active", "bound_to_session"),
        "witness": ("current", "epoch_matches", "revoked",
                    "rechecked_before_disclosure"),
        "replay": ("fresh", "atomic_committed"),
    }
    _TUPLES = {
        "client": ("capability_sids",),
        "grant": ("permitted_methods", "permitted_namespaces"),
    }
    _REASONS = {
        "broker": "BROKER_TRUST_UNVERIFIED",
        "transport": "RPC_BOUNDARY_UNVERIFIED",
        "client": "CLIENT_OS_IDENTITY_UNVERIFIED",
        "grant": "OWNER_GRANT_UNVERIFIED",
        "witness": "WITNESS_UNVERIFIED_OR_REVOKED",
        "replay": "REPLAY_OR_SESSION_UNVERIFIED",
    }

    class AlwaysEqual:
        def __eq__(self, other):
            return True

        def __ne__(self, other):
            return False

        def __hash__(self):
            return 0

    class RaisesOnComparison:
        def __eq__(self, other):
            raise RuntimeError("synthetic attacker equality failure")

        def __ne__(self, other):
            raise RuntimeError("synthetic attacker inequality failure")

        def __hash__(self):
            raise RuntimeError("synthetic attacker hash failure")

    class EvilStrSubclass(str):
        def __eq__(self, other):
            return True

        def __ne__(self, other):
            return False

    def setUp(self):
        self.req = request()
        self.p = policy()
        self.ev = evidence()

    def assertDenied(self, outcome, reason):
        self.assertIsInstance(outcome, AdmissionResult)
        self.assertEqual("DENY", outcome.verdict)
        self.assertFalse(outcome.model_allowed)
        self.assertEqual((), outcome.visible_namespaces)
        self.assertEqual(reason, outcome.reason)

    def test_all_17_string_identity_fields_reject_comparison_attacks(self):
        fields = [(area, field) for area, attrs in self._STRINGS.items()
                  for field in attrs]
        self.assertEqual(17, len(fields))
        for area, field in fields:
            for kind in (self.AlwaysEqual, self.RaisesOnComparison,
                         self.EvilStrSubclass):
                with self.subTest(area=area, field=field, attack=kind.__name__):
                    val = kind("malicious") if kind is self.EvilStrSubclass else kind()
                    forged = with_change(self.ev, area, **{field: val})
                    # An exception here is a FAIL, not a successful denial.
                    self.assertDenied(
                        decide(self.req, self.p, forged), self._REASONS[area]
                    )

    def test_all_boolean_evidence_fields_reject_tricky_nonbooleans(self):
        fields = [(area, field) for area, attrs in self._FLAGS.items()
                  for field in attrs]
        self.assertEqual(25, len(fields))
        for area, field in fields:
            for kind in (self.AlwaysEqual, self.RaisesOnComparison):
                with self.subTest(area=area, field=field, attack=kind.__name__):
                    forged = with_change(self.ev, area, **{field: kind()})
                    self.assertDenied(
                        decide(self.req, self.p, forged), self._REASONS[area]
                    )

    def test_all_tuple_evidence_fields_reject_malicious_values(self):
        fields = [(area, field) for area, attrs in self._TUPLES.items()
                  for field in attrs]
        self.assertEqual(3, len(fields))
        for area, field in fields:
            for kind in (self.AlwaysEqual, self.RaisesOnComparison):
                with self.subTest(area=area, field=field, attack=kind.__name__):
                    forged = with_change(self.ev, area, **{field: kind()})
                    self.assertDenied(
                        decide(self.req, self.p, forged), self._REASONS[area]
                    )

    def test_incomplete_top_level_evidence_denies_not_attribute_error(self):
        incomplete = object.__new__(AdmissionEvidence)
        self.assertDenied(
            decide(self.req, self.p, incomplete),
            "UNVERIFIED_EVIDENCE_TYPE",
        )

    def test_incomplete_nested_instances_denied_without_crash(self):
        nested_types = {
            "broker": BrokerEvidence,
            "transport": TransportEvidence,
            "client": ClientEvidence,
            "grant": GrantEvidence,
            "witness": WitnessEvidence,
            "replay": ReplayEvidence,
        }
        for area, kind in nested_types.items():
            with self.subTest(area=area):
                incomplete = object.__new__(kind)
                forged = replace(self.ev, **{area: incomplete})
                self.assertDenied(
                    decide(self.req, self.p, forged), self._REASONS[area]
                )

    def test_grant_tuple_elements_do_not_invoke_custom_equality(self):
        for name, value in (
            ("permitted_methods", ("find", self.RaisesOnComparison())),
            ("permitted_namespaces", ("research", self.RaisesOnComparison())),
            ("permitted_methods", (self.AlwaysEqual(),)),
            ("permitted_namespaces", (self.AlwaysEqual(),)),
        ):
            with self.subTest(field=name):
                forged = with_change(self.ev, "grant", **{name: value})
                self.assertDenied(
                    decide(self.req, self.p, forged),
                    "OWNER_GRANT_UNVERIFIED",
                )

    def test_mutated_policy_with_custom_string_equality_denied(self):
        cases = (
            ("expected_user_sid", self.AlwaysEqual()),
            ("expected_appcontainer_sid", self.RaisesOnComparison()),
            ("installation_id", self.AlwaysEqual()),
            ("permitted_methods", ("find", self.RaisesOnComparison())),
            ("permitted_namespaces", ("research", self.AlwaysEqual())),
        )
        for name, value in cases:
            with self.subTest(field=name):
                current_policy = policy()
                object.__setattr__(current_policy, name, value)
                self.assertDenied(
                    decide(self.req, current_policy, self.ev),
                    "REQUEST_OR_POLICY_INVALID",
                )

    def test_invalid_types_cannot_broaden_synthetic_allow(self):
        # The positive model case remains possible with a fully fabricated
        # Python fixture; this test proves type checks, not OS authentication.
        self.assertEqual("MODEL_ALLOW", decide(
            self.req, self.p, self.ev
        ).verdict)
        wrong = with_change(self.ev, "broker",
                            origin=self.AlwaysEqual())
        self.assertDenied(
            decide(self.req, self.p, wrong), "BROKER_TRUST_UNVERIFIED"
        )


if __name__ == "__main__":
    unittest.main()
