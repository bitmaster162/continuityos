"""R6A request/response wire invariants. In-memory synthetic values only."""
from __future__ import annotations

import hashlib
import json
import unittest

from continuityos.h3 import readonly_contract as rc

NONCE = "0123456789abcdef0123456789abcdef"
REQ_ID = "request-001"
SESSION = "session-001"
NAMESPACE = "research"
SCOPE = ("research",)


def json_bytes(value: object) -> bytes:
    return json.dumps(
        value, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


_DEFAULT = object()


def obj(method="find", params=_DEFAULT):
    if params is _DEFAULT:
        params = {"namespace": NAMESPACE, "key": "item-1"}
    return {
        "protocol": rc.PROTOCOL,
        "request_id": REQ_ID,
        "session_id": SESSION,
        "nonce": NONCE,
        "method": method,
        "params": params,
    }


def request(method="find", params=_DEFAULT):
    return rc.parse_request(json_bytes(obj(method, params)))


def response(req, result, *, status="ok", extra=None):
    o = {"protocol": rc.PROTOCOL, "request_id": req.request_id,
         "session_id": req.session_id, "nonce": req.nonce,
         "method": req.method, "request_sha256": rc.request_sha256(req),
         "status": status, "result": result}
    if extra:
        o.update(extra)
    return json_bytes(o)


class ReadonlyRequestTests(unittest.TestCase):
    def test_exact_five_read_methods_have_bounded_schemas(self):
        cases = {
            "memory_status": {},
            "list_namespaces": {},
            "find": {"namespace": NAMESPACE, "key": "item-1"},
            "recall": {"namespace": NAMESPACE, "query": "topic", "k": 10},
            "context": {"namespace": NAMESPACE, "query": "topic", "k": 1},
        }
        for method, params in cases.items():
            with self.subTest(method=method):
                parsed = request(method, params)
                self.assertEqual(method, parsed.method)
                self.assertEqual(params, dict(parsed.params))
                self.assertIsInstance(parsed.params, tuple)

    def test_client_serialization_roundtrip(self):
        raw = rc.make_request(
            request_id=REQ_ID, session_id=SESSION, nonce=NONCE,
            method="find", params={"namespace": NAMESPACE, "key": "item-1"},
        )
        self.assertEqual(rc.parse_request(raw), request())
        self.assertLessEqual(len(raw), rc.MAX_REQUEST_BYTES)

    def test_no_authority_claim_fields_accepted(self):
        for key in ("user_sid", "token", "grant", "signature",
                    "service_sid", "broker_key", "db_path", "owner"):
            with self.subTest(key=key):
                body = obj()
                body[key] = "ATTACKER_CLAIM"
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(json_bytes(body))

    def test_all_mutation_names_denied(self):
        for name in ("remember", "forget", "upsert", "checkpoint",
                     "preflight_exec", "execute_preflight",
                     "memory_write_checked", "raw_sql", "dump_db"):
            with self.subTest(name=name):
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(json_bytes(obj(name, {})))

    def test_missing_or_unknown_params_denied(self):
        for params in ({"namespace": NAMESPACE}, {"key": "item-1"},
                       {"namespace": NAMESPACE, "key": "item-1", "limit": 10},
                       [], None):
            with self.subTest(params=params):
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(json_bytes(obj("find", params)))

    def test_recalls_cannot_search_all_namespaces(self):
        with self.assertRaises(rc.ContractError):
            request("recall", {"query": "topic"})
        with self.assertRaises(rc.ContractError):
            request("context", {"query": "topic"})

    def test_duplicate_top_level_json_keys_denied(self):
        raw = (
            '{"protocol":"continuityos.h3.ipc/v3","request_id":"request-001",'
            '"request_id":"override","session_id":"session-001","nonce":"'
            + NONCE + '","method":"find","params":{"namespace":"research","key":"item-1"}}'
        )
        with self.assertRaises(rc.ContractError):
            rc.parse_request(raw.encode())

    def test_duplicate_nested_json_keys_denied(self):
        raw = (
            '{"protocol":"continuityos.h3.ipc/v3","request_id":"request-001",'
            '"session_id":"session-001","nonce":"' + NONCE
            + '","method":"find","params":{"namespace":"research",'
            '"namespace":"secret","key":"item-1"}}'
        )
        with self.assertRaises(rc.ContractError):
            rc.parse_request(raw.encode())

    def test_reject_non_json_bytes_and_oversized(self):
        for raw in (b"", b"\xff", b"{", b"x" * (rc.MAX_REQUEST_BYTES + 1)):
            with self.subTest(length=len(raw)):
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(raw)
        with self.assertRaises(rc.ContractError):
            rc.parse_request("not bytes")  # type: ignore[arg-type]

    def test_reject_non_json_numeric_constant(self):
        raw = json_bytes(obj()).replace(b'"key":"item-1"', b'"key":NaN')
        with self.assertRaises(rc.ContractError):
            rc.parse_request(raw)

    def test_reject_protocol_and_blank_ids(self):
        for change in ({"protocol": "continuityos.h3.ipc/v1"},
                       {"request_id": ""}, {"session_id": ""}):
            with self.subTest(change=change):
                raw = obj()
                raw.update(change)
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(json_bytes(raw))

    def test_reject_nonce_bad_shape(self):
        for nonce in ("ABCDEF" * 6, "a" * 31, "a" * 65, 123):
            with self.subTest(nonce=nonce):
                raw = obj()
                raw["nonce"] = nonce
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(json_bytes(raw))

    def test_reject_control_characters(self):
        for value in ("bad\nquery", "bad\rquery", "\x00"):
            with self.subTest(value=value):
                with self.assertRaises(rc.ContractError):
                    request("recall", {"namespace": NAMESPACE, "query": value})

    def test_reject_invalid_k_bool_float_and_excess(self):
        for k in (True, False, 0, 11, 1.0, -1, "3"):
            with self.subTest(k=k):
                with self.assertRaises(rc.ContractError):
                    request("recall", {"namespace": NAMESPACE, "query": "x", "k": k})

    def test_reject_extra_params_in_metadata_methods(self):
        for method in ("memory_status", "list_namespaces"):
            with self.subTest(method=method):
                with self.assertRaises(rc.ContractError):
                    request(method, {"namespace": NAMESPACE})

    def test_no_database_or_execution_primitive_exposed(self):
        forbidden = {"db_path", "path", "sql", "argv", "command", "query_sql"}
        self.assertTrue(forbidden.isdisjoint(
            set().union(*rc._OPTIONAL_PARAMS.values(), *rc._REQUIRED_PARAMS.values())
        ))
        self.assertFalse(rc._MUTATING_METHODS & rc.READ_ONLY_METHODS)


class ReadonlyResponseTests(unittest.TestCase):
    def test_valid_synthetic_status(self):
        req = request("memory_status", {})
        raw = rc.make_response(request=req, result={"available": True},
                               authorized_namespaces=SCOPE)
        parsed = rc.parse_response(raw, request=req,
                                   authorized_namespaces=SCOPE)
        self.assertEqual(parsed.status, "ok")
        self.assertEqual(parsed.result, {"available": True})

    def test_valid_scoped_namespace_listing(self):
        req = request("list_namespaces", {})
        payload = [{"namespace": NAMESPACE, "count": 7}]
        raw = rc.make_response(request=req, result=payload,
                               authorized_namespaces=SCOPE)
        parsed = rc.parse_response(raw, request=req,
                                   authorized_namespaces=SCOPE)
        self.assertEqual(parsed.status, "ok")
        self.assertEqual(parsed.result, payload)

    def test_forbidden_namespace_never_listed(self):
        req = request("list_namespaces", {})
        payload = [{"namespace": "secrets", "count": 1}]
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=payload,
                             authorized_namespaces=SCOPE)

    def test_reject_duplicate_namespace_rows(self):
        req = request("list_namespaces", {})
        payload = [{"namespace": NAMESPACE, "count": 1}] * 2
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=payload,
                             authorized_namespaces=SCOPE)

    def test_find_binds_key_and_namespace(self):
        req = request()
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "synthetic"}
        raw = rc.make_response(request=req, result=record,
                               authorized_namespaces=SCOPE)
        parsed = rc.parse_response(raw, request=req,
                                   authorized_namespaces=SCOPE)
        self.assertEqual(parsed.status, "ok")
        self.assertEqual(parsed.result, record)

    def test_find_denies_foreign_key(self):
        req = request()
        record = {"namespace": NAMESPACE, "key": "another", "text": "x"}
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=record,
                             authorized_namespaces=SCOPE)

    def test_find_denies_foreign_namespace(self):
        req = request()
        record = {"namespace": "secrets", "key": "item-1", "text": "x"}
        with self.assertRaises(rc.ContractError):
            rc.parse_response(response(req, record), request=req,
                              authorized_namespaces=SCOPE)

    def test_reject_raw_db_and_secret_fields(self):
        req = request()
        for field in ("db_path", "raw_db", "password", "owner_auth",
                      "handle", "secret", "metadata"):
            with self.subTest(field=field):
                payload = {"namespace": NAMESPACE, "key": "item-1",
                           "text": "synthetic", field: "not allowed"}
                with self.assertRaises(rc.ContractError):
                    rc.parse_response(response(req, payload), request=req,
                                      authorized_namespaces=SCOPE)

    def test_recall_result_count_is_bounded_by_k(self):
        req = request("recall", {"namespace": NAMESPACE, "query": "x", "k": 2})
        record = {"namespace": NAMESPACE, "key": "x", "text": "synthetic"}
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=[record] * 3,
                             authorized_namespaces=SCOPE)

    def test_recall_requires_exact_namespace(self):
        req = request("recall", {"namespace": NAMESPACE, "query": "x"})
        record = {"namespace": "secrets", "key": "x", "text": "data"}
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=[record],
                             authorized_namespaces=SCOPE)

    def test_context_is_scoped_and_text_bounded(self):
        req = request("context", {"namespace": NAMESPACE, "query": "x"})
        raw = rc.make_response(
            request=req,
            result={"namespace": NAMESPACE, "text": "offline\nsynthetic"},
            authorized_namespaces=SCOPE
        )
        self.assertEqual(
            rc.parse_response(raw, request=req,
                              authorized_namespaces=SCOPE).result["text"],
            "offline\nsynthetic"
        )
        with self.assertRaises(rc.ContractError):
            rc.make_response(
                request=req,
                result={"namespace": NAMESPACE, "text": "z" * 4097},
                authorized_namespaces=SCOPE
            )

    def test_denied_response_contains_no_result(self):
        req = request()
        raw = rc.make_response(request=req, result=None, denied=True,
                               authorized_namespaces=SCOPE)
        parsed = rc.parse_response(raw, request=req,
                                   authorized_namespaces=SCOPE)
        self.assertEqual(parsed.status, "denied")
        self.assertIsNone(parsed.result)
        with self.assertRaises(rc.ContractError):
            rc.parse_response(response(req, {"secret": "x"}, status="denied"),
                              request=req, authorized_namespaces=SCOPE)

    def test_response_binding_mismatch_denied(self):
        req = request()
        valid = {"namespace": NAMESPACE, "key": "item-1", "text": "x"}
        wrong = json.loads(response(req, valid))
        for name, value in (("request_id", "other-id"), ("protocol", "unknown"),
                            ("session_id", "other-session"), ("nonce", "f" * 32),
                            ("method", "recall")):
            with self.subTest(name=name):
                payload = dict(wrong)
                payload[name] = value
                with self.assertRaises(rc.ContractError):
                    rc.parse_response(json_bytes(payload), request=req,
                                      authorized_namespaces=SCOPE)

    def test_unknown_response_fields_denied(self):
        req = request()
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "x"}
        with self.assertRaises(rc.ContractError):
            rc.parse_response(response(req, record, extra={"db_handle": "bad"}),
                              request=req, authorized_namespaces=SCOPE)

    def test_oversized_response_denied(self):
        req = request()
        with self.assertRaises(rc.ContractError):
            rc.parse_response(b" " * (rc.MAX_RESPONSE_BYTES + 1),
                              request=req, authorized_namespaces=SCOPE)

    def test_denies_missing_scope(self):
        req = request()
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "x"}
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=record,
                             authorized_namespaces=())

    def test_bad_scope_type_denied(self):
        req = request("memory_status", {})
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result={"available": True},
                             authorized_namespaces=["research"])  # type: ignore[arg-type]

    def test_duplicate_keys_in_response_denied(self):
        req = request()
        raw = (
            '{"protocol":"continuityos.h3.ipc/v3","request_id":"request-001",'
            '"session_id":"session-001","nonce":"' + NONCE + '",'
            '"method":"find","request_sha256":"' + rc.request_sha256(req) + '",'
            '"status":"denied","result":null,"result":null}'
        ).encode("ascii")
        with self.assertRaises(rc.ContractError):
            rc.parse_response(raw, request=req, authorized_namespaces=SCOPE)


class V3HardeningTests(unittest.TestCase):
    """Regression for incompatibly revised, synthetic v3 wire protocol."""

    def test_version_is_explicit_incompatible_v3(self):
        self.assertEqual(rc.PROTOCOL, "continuityos.h3.ipc/v3")
        for old_protocol in ("continuityos.h3.ipc/v1", "continuityos.h3.ipc/v2"):
            with self.subTest(old=old_protocol):
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(json_bytes({**obj(), "protocol": old_protocol}))

    def test_v3_response_contains_all_binding_fields(self):
        req = request()
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "only fixture"}
        raw = rc.make_response(request=req, result=record,
                               authorized_namespaces=SCOPE)
        envelope = json.loads(raw)
        self.assertEqual(
            set(envelope),
            {"protocol", "request_id", "session_id", "nonce",
             "method", "request_sha256", "status", "result"},
        )
        for field in ("protocol", "request_id", "session_id", "nonce", "method"):
            self.assertEqual(envelope[field], getattr(req, field))
        self.assertEqual(envelope["request_sha256"], rc.request_sha256(req))

    def test_cross_session_replay_of_same_request_id_denied(self):
        a = request()
        payload = {"namespace": NAMESPACE, "key": "item-1", "text": "synthetic"}
        raw = rc.make_response(request=a, result=payload,
                               authorized_namespaces=SCOPE)
        b = rc.parse_request(rc.make_request(
            request_id=a.request_id, session_id="other-session",
            nonce=a.nonce, method="find",
            params={"namespace": NAMESPACE, "key": "item-1"},
        ))
        with self.assertRaises(rc.ContractError):
            rc.parse_response(raw, request=b, authorized_namespaces=SCOPE)

    def test_nonce_reuse_in_different_request_denied(self):
        a = request()
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "fixture"}
        raw = rc.make_response(request=a, result=record,
                               authorized_namespaces=SCOPE)
        b = rc.parse_request(rc.make_request(
            request_id=a.request_id, session_id=a.session_id,
            nonce="f" * 32, method="find",
            params={"namespace": NAMESPACE, "key": "item-1"},
        ))
        with self.assertRaises(rc.ContractError):
            rc.parse_response(raw, request=b, authorized_namespaces=SCOPE)

    def test_denied_can_be_created_and_parsed_with_no_scope(self):
        req = request()
        raw = rc.make_response(request=req, result=None,
                               authorized_namespaces=(), denied=True)
        parsed = rc.parse_response(raw, request=req, authorized_namespaces=())
        self.assertEqual(parsed.status, "denied")
        self.assertIsNone(parsed.result)

    def test_denied_differs_from_not_found_and_ok(self):
        req = request()
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "fixture"}
        denied = rc.parse_response(
            rc.make_response(request=req, result=None, denied=True,
                             authorized_namespaces=()),
            request=req, authorized_namespaces=(),
        )
        not_found = rc.parse_response(
            rc.make_response(request=req, result=None, not_found=True,
                             authorized_namespaces=SCOPE),
            request=req, authorized_namespaces=SCOPE,
        )
        found = rc.parse_response(
            rc.make_response(request=req, result=record,
                             authorized_namespaces=SCOPE),
            request=req, authorized_namespaces=SCOPE,
        )
        self.assertEqual((denied.status, not_found.status, found.status),
                         ("denied", "not_found", "ok"))
        self.assertIsNone(denied.result)
        self.assertIsNone(not_found.result)
        self.assertEqual(found.result, record)

    def test_ok_find_or_context_none_must_use_not_found(self):
        cases = (
            request(),
            request("context", {"namespace": NAMESPACE, "query": "topic"}),
        )
        for req in cases:
            with self.subTest(method=req.method):
                with self.assertRaises(rc.ContractError):
                    rc.make_response(request=req, result=None,
                                     authorized_namespaces=SCOPE)

    def test_not_found_rejected_without_scope_or_for_wrong_method(self):
        req = request()
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=None, not_found=True,
                             authorized_namespaces=())
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=None, not_found=True,
                             authorized_namespaces=("other",))
        status = request("memory_status", {})
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=status, result=None, not_found=True,
                             authorized_namespaces=SCOPE)

    def test_not_found_must_not_contain_payload(self):
        req = request()
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req,
                             result={"namespace": NAMESPACE, "text": "private"},
                             authorized_namespaces=SCOPE, not_found=True)

    def test_denied_not_found_flags_mutually_exclusive(self):
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=request(), result=None,
                             authorized_namespaces=SCOPE,
                             denied=True, not_found=True)

    def test_constructor_does_not_assume_a_parser_was_used(self):
        req = request()
        with self.assertRaises(rc.ContractError):
            rc.ReadonlyRequest(req.protocol, req.request_id, req.session_id,
                               req.nonce, "find", (("namespace", NAMESPACE),))
        with self.assertRaises(rc.ContractError):
            rc.ReadonlyRequest(req.protocol, req.request_id, req.session_id,
                               req.nonce, ["find"], req.params)
        with self.assertRaises(rc.ContractError):
            rc.ReadonlyRequest(req.protocol, req.request_id, req.session_id,
                               req.nonce, "find", None)
        with self.assertRaises(rc.ContractError):
            rc.ReadonlyRequest(req.protocol, req.request_id, req.session_id,
                               req.nonce, "find", (("key", "item-1"),
                                                    ("key", "other"),
                                                    ("namespace", NAMESPACE)))

    def test_mutation_after_construction_detected_before_response(self):
        req = request()
        object.__setattr__(req, "method", ["find"])
        with self.assertRaises(rc.ContractError):
            rc.validate_request(req)
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=None,
                             authorized_namespaces=(), denied=True)

    def test_unicode_surrogate_refused_in_request_and_response(self):
        escaped = json.dumps(
            {**obj(), "params": {"namespace": NAMESPACE, "key": "\ud800"}},
            ensure_ascii=True,
        ).encode("ascii")
        with self.assertRaises(rc.ContractError):
            rc.parse_request(escaped)
        req = request()
        bad = {"namespace": NAMESPACE, "key": "item-1", "text": "\udfff"}
        raw = json.dumps({
            "protocol": rc.PROTOCOL, "request_id": req.request_id,
            "session_id": req.session_id, "nonce": req.nonce,
            "method": req.method, "request_sha256": rc.request_sha256(req),
            "status": "ok", "result": bad,
        }, ensure_ascii=True).encode("ascii")
        with self.assertRaises(rc.ContractError):
            rc.parse_response(raw, request=req, authorized_namespaces=SCOPE)
        with self.assertRaises(rc.ContractError):
            rc.make_response(request=req, result=bad,
                             authorized_namespaces=SCOPE)

    def test_old_v1_response_rejected(self):
        req = request()
        raw = json_bytes({
            "protocol": "continuityos.h3.ipc/v1",
            "request_id": req.request_id,
            "status": "denied", "result": None,
        })
        with self.assertRaises(rc.ContractError):
            rc.parse_response(raw, request=req, authorized_namespaces=())

    def test_denied_protocol_still_bound_to_request(self):
        req = request()
        denied = json.loads(rc.make_response(
            request=req, result=None, authorized_namespaces=(), denied=True,
        ))
        for field, bad in (
            ("session_id", "another-session"),
            ("nonce", "f" * 32),
            ("method", "context"),
        ):
            with self.subTest(field=field):
                altered = {**denied, field: bad}
                with self.assertRaises(rc.ContractError):
                    rc.parse_response(json_bytes(altered), request=req,
                                      authorized_namespaces=())


class V3FullRequestDigestTests(unittest.TestCase):
    """Synthetic v3 response must match every canonical request field."""

    def test_canonical_full_request_digest_matches_domain_separated_sha256(self):
        req = request("recall", {"k": 2, "query": "alpha", "namespace": NAMESPACE})
        data = rc.canonical_request_bytes(req)
        expected = hashlib.sha256(
            b"continuityos.h3.canonical-request.v3\x00" + data
        ).hexdigest()
        self.assertEqual(rc.request_sha256(req), expected)
        self.assertEqual(len(expected), 64)
        self.assertEqual(
            json.loads(data),
            {"protocol": rc.PROTOCOL, "request_id": req.request_id,
             "session_id": req.session_id, "nonce": req.nonce,
             "method": req.method,
             "params": {"namespace": NAMESPACE, "query": "alpha", "k": 2}},
        )

    def test_digest_is_deterministic_under_param_key_order(self):
        left = request("recall", {"k": 2, "namespace": NAMESPACE, "query": "alpha"})
        right = request("recall", {"query": "alpha", "k": 2, "namespace": NAMESPACE})
        self.assertEqual(rc.canonical_request_bytes(left),
                         rc.canonical_request_bytes(right))
        self.assertEqual(rc.request_sha256(left), rc.request_sha256(right))

    def test_recall_query_namespace_k_changes_all_rejected(self):
        original = request(
            "recall", {"namespace": NAMESPACE, "query": "alpha", "k": 2}
        )
        record = {"namespace": NAMESPACE, "key": "item-1", "text": "fixture"}
        allowed = (NAMESPACE, "notes")
        old_response = rc.make_response(
            request=original, result=[record], authorized_namespaces=allowed
        )
        mutations = {
            "query": {"namespace": NAMESPACE, "query": "beta", "k": 2},
            "namespace": {"namespace": "notes", "query": "alpha", "k": 2},
            "k": {"namespace": NAMESPACE, "query": "alpha", "k": 3},
            "k_presence": {"namespace": NAMESPACE, "query": "alpha"},
        }
        for field, params in mutations.items():
            with self.subTest(changed=field):
                new_req = request("recall", params)
                # IDs, nonce and method are unchanged: only full-request
                # binding must cause rejection, even for compatible results.
                for name in ("protocol", "request_id", "session_id",
                             "nonce", "method"):
                    self.assertEqual(getattr(original, name), getattr(new_req, name))
                self.assertNotEqual(rc.request_sha256(original),
                                    rc.request_sha256(new_req))
                with self.assertRaisesRegex(rc.ContractError, "digest"):
                    rc.parse_response(old_response, request=new_req,
                                      authorized_namespaces=allowed)

    def test_context_query_and_find_key_rebinding_rejected(self):
        cases = (
            ("context", {"namespace": NAMESPACE, "query": "alpha"},
             {"namespace": NAMESPACE, "query": "beta"},
             {"namespace": NAMESPACE, "text": "fixture"}),
            ("find", {"namespace": NAMESPACE, "key": "item-1"},
             {"namespace": NAMESPACE, "key": "item-2"},
             {"namespace": NAMESPACE, "key": "item-1", "text": "fixture"}),
        )
        for method, original_params, other_params, result in cases:
            with self.subTest(method=method):
                left = request(method, original_params)
                right = request(method, other_params)
                signed_by_nobody = rc.make_response(
                    request=left, result=result, authorized_namespaces=SCOPE
                )
                with self.assertRaisesRegex(rc.ContractError, "digest"):
                    rc.parse_response(signed_by_nobody, request=right,
                                      authorized_namespaces=SCOPE)

    def test_all_response_statuses_include_digest(self):
        req = request()
        variants = (
            ("ok", {"namespace": NAMESPACE, "key": "item-1", "text": "fixture"},
             {"authorized_namespaces": SCOPE}),
            ("not_found", None,
             {"authorized_namespaces": SCOPE, "not_found": True}),
            ("denied", None,
             {"authorized_namespaces": (), "denied": True}),
        )
        for status, value, options in variants:
            with self.subTest(status=status):
                raw = rc.make_response(request=req, result=value, **options)
                wire = json.loads(raw)
                self.assertEqual(wire["request_sha256"], rc.request_sha256(req))
                self.assertEqual(
                    rc.parse_response(raw, request=req,
                                      authorized_namespaces=options["authorized_namespaces"]).status,
                    status,
                )

    def test_wrong_missing_malformed_digest_never_accepted(self):
        req = request()
        wire = json.loads(rc.make_response(
            request=req, result=None, authorized_namespaces=(), denied=True
        ))
        invalid = (None, True, 0, "", "f" * 63, "f" * 65,
                   "F" * 64, "f" * 64, {"hex": "wrong"})
        for value in invalid:
            with self.subTest(value=str(value)[:20]):
                forged = {**wire, "request_sha256": value}
                with self.assertRaises(rc.ContractError):
                    rc.parse_response(json_bytes(forged), request=req,
                                      authorized_namespaces=())
        missing = dict(wire)
        del missing["request_sha256"]
        with self.assertRaises(rc.ContractError):
            rc.parse_response(json_bytes(missing), request=req,
                              authorized_namespaces=())

    def test_v1_v2_response_payloads_are_explicitly_incompatible(self):
        req = request()
        for old_proto in ("continuityos.h3.ipc/v1", "continuityos.h3.ipc/v2"):
            with self.subTest(old_proto=old_proto):
                old = {"protocol": old_proto, "request_id": req.request_id,
                       "session_id": req.session_id, "nonce": req.nonce,
                       "method": req.method, "status": "denied", "result": None}
                with self.assertRaises(rc.ContractError):
                    rc.parse_response(json_bytes(old), request=req,
                                      authorized_namespaces=())

    def test_digest_is_not_a_signature_or_replay_prevention(self):
        req = request()
        # Anyone knowing request content can forge the expected digest.
        forged = {
            "protocol": rc.PROTOCOL, "request_id": req.request_id,
            "session_id": req.session_id, "nonce": req.nonce,
            "method": req.method, "request_sha256": rc.request_sha256(req),
            "status": "denied", "result": None,
        }
        parsed = rc.parse_response(json_bytes(forged), request=req,
                                   authorized_namespaces=())
        self.assertEqual(parsed.status, "denied")
        # The same bytes can be parsed twice; replay protection is external.
        self.assertEqual(rc.parse_response(json_bytes(forged), request=req,
                                           authorized_namespaces=()).status,
                         "denied")

    def test_mutated_request_cannot_be_hashed(self):
        req = request()
        object.__setattr__(req, "params", (("namespace", "research"),))
        with self.assertRaises(rc.ContractError):
            rc.canonical_request_bytes(req)
        with self.assertRaises(rc.ContractError):
            rc.request_sha256(req)


class R6GUnicodeDisplaySafetyTests(unittest.TestCase):
    """Bound Unicode control/display risks without excluding normal scripts."""

    @staticmethod
    def forbidden_codepoints():
        # DEL/C1, bidi control and invisible direction markers, U+2028/2029,
        # BOM and the original C0 controls. Preserve ZWNJ/ZWJ.
        return (
            tuple(range(0x00, 0x20))
            + tuple(range(0x7F, 0xA0))
            + (0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0xFEFF)
            + tuple(range(0x202A, 0x202F))
            + tuple(range(0x2066, 0x2070))
        )

    def test_forbidden_unicode_set_is_exact_and_unique(self):
        points = self.forbidden_codepoints()
        self.assertEqual(86, len(points))
        self.assertEqual(len(points), len(set(points)))
        self.assertNotIn(0x200C, points)  # ZWNJ
        self.assertNotIn(0x200D, points)  # ZWJ

    def test_all_forbidden_controls_rejected_in_query_and_key(self):
        for point in self.forbidden_codepoints():
            value = "a" + chr(point) + "b"
            for method, params in (
                ("recall", {"namespace": NAMESPACE, "query": value}),
                ("find", {"namespace": NAMESPACE, "key": value}),
                ("context", {"namespace": NAMESPACE, "query": value}),
            ):
                with self.subTest(point=f"U+{point:04X}", method=method):
                    with self.assertRaises(rc.ContractError):
                        request(method, params)

    def test_forbidden_controls_rejected_in_all_record_texts(self):
        cases = (
            ("find", {"namespace": NAMESPACE, "key": "item-1"}),
            ("recall", {"namespace": NAMESPACE, "query": "topic"}),
            ("context", {"namespace": NAMESPACE, "query": "topic"}),
        )
        for point in self.forbidden_codepoints():
            if point in (0x09, 0x0A):
                continue  # Only result text may contain TAB and LF.
            text = "a" + chr(point) + "b"
            for method, params in cases:
                with self.subTest(point=f"U+{point:04X}", method=method):
                    req = request(method, params)
                    if method == "context":
                        result = {"namespace": NAMESPACE, "text": text}
                    else:
                        record = {
                            "namespace": NAMESPACE, "key": "item-1",
                            "text": text,
                        }
                        result = [record] if method == "recall" else record
                    with self.assertRaises(rc.ContractError):
                        rc.make_response(
                            request=req, result=result,
                            authorized_namespaces=SCOPE,
                        )
                    with self.assertRaises(rc.ContractError):
                        rc.parse_response(
                            response(req, result), request=req,
                            authorized_namespaces=SCOPE,
                        )

    def test_escaped_control_characters_cannot_bypass_wire_validation(self):
        for point in (0x7F, 0x85, 0x9B, 0x061C, 0x200E, 0x2028,
                      0x202E, 0x2066, 0x206F, 0xFEFF):
            value = "a" + chr(point) + "b"
            with self.subTest(point=f"U+{point:04X}"):
                wire_request = json.dumps(
                    obj("recall", {"namespace": NAMESPACE, "query": value}),
                    ensure_ascii=True, separators=(",", ":"),
                ).encode("ascii")
                with self.assertRaises(rc.ContractError):
                    rc.parse_request(wire_request)

    def test_multilingual_and_joiner_text_remains_allowed(self):
        samples = (
            "\u041f\u0440\u0438\u0432\u0435\u0442",  # Cyrillic
            "\u0e20\u0e32\u0e29\u0e32\u0e44\u0e17\u0e22",  # Thai
            "\u4e2d\u6587",  # Han
            "\u0627\u0644\u0639\u0631\u0628\u064a\u0629",  # Arabic
            "\u0645\u06cc\u200c\u0631\u0648\u0645",  # Persian ZWNJ
            "\u0915\u094d\u200d\u0937",  # Indic ZWJ
            "\U0001f468\u200d\U0001f469\u200d\U0001f467",  # Emoji ZWJ
            "re\u0301sume\u0301",  # Combining accents
        )
        for sample in samples:
            with self.subTest(sample=ascii(sample)):
                find = request("find", {"namespace": NAMESPACE, "key": sample})
                find_record = {
                    "namespace": NAMESPACE, "key": sample, "text": sample,
                }
                result = rc.parse_response(
                    rc.make_response(request=find, result=find_record,
                                     authorized_namespaces=SCOPE),
                    request=find, authorized_namespaces=SCOPE,
                )
                self.assertEqual(result.result, find_record)

                for method in ("recall", "context"):
                    req = request(method, {
                        "namespace": NAMESPACE, "query": sample,
                    })
                    payload = (
                        [{"namespace": NAMESPACE, "key": "item-1",
                          "text": sample}]
                        if method == "recall"
                        else {"namespace": NAMESPACE, "text": sample}
                    )
                    parsed = rc.parse_response(
                        rc.make_response(request=req, result=payload,
                                         authorized_namespaces=SCOPE),
                        request=req, authorized_namespaces=SCOPE,
                    )
                    self.assertEqual(parsed.result, payload)

    def test_tab_and_lf_only_allowed_in_result_text(self):
        for whitespace in ("\t", "\n"):
            with self.subTest(char=repr(whitespace)):
                value = "a" + whitespace + "b"
                for method in ("find", "recall", "context"):
                    req = request(method, {
                        "namespace": NAMESPACE,
                        **({"key": "item-1"} if method == "find"
                           else {"query": "topic"}),
                    })
                    payload = (
                        {"namespace": NAMESPACE, "text": value}
                        if method == "context"
                        else {"namespace": NAMESPACE, "key": "item-1",
                              "text": value}
                    )
                    if method == "recall":
                        payload = [payload]
                    parsed = rc.parse_response(
                        rc.make_response(request=req, result=payload,
                                         authorized_namespaces=SCOPE),
                        request=req, authorized_namespaces=SCOPE,
                    )
                    self.assertEqual(parsed.result, payload)
                with self.assertRaises(rc.ContractError):
                    request("recall", {
                        "namespace": NAMESPACE, "query": value,
                    })


if __name__ == "__main__":
    unittest.main()
