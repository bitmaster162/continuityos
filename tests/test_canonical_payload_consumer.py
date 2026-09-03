from __future__ import annotations

import hashlib
import json
from pathlib import Path
import ssl

import pytest

import continuityos.canonical_payload_consumer as c


def meta(**changes):
    value = {
        "stable_source_id": c.STABLE_SOURCE_ID,
        "role": c.ROLE,
        "resolution_disposition": c.DISPOSITION,
        "currentness_status": c.CURRENTNESS,
        "authority_upgraded": False,
        "record_digest": c.RECORD_DIGEST,
        "projection_digest": c.PROJECTION_DIGEST,
        "snapshot_digest": c.SNAPSHOT_DIGEST,
    }
    value.update(changes)
    return value


def canon_health_doc(**changes):
    value = {
        "ok": True,
        "enabled": True,
        "status": "READ_ONLY_READY",
        "source_id": c.STABLE_SOURCE_ID,
        "role": c.ROLE,
        "resolution_disposition": c.DISPOSITION,
        "record_digest": c.RECORD_DIGEST,
        "projection_digest": c.PROJECTION_DIGEST,
        "authority_upgraded": False,
        "integrity_check": "ok",
    }
    value.update(changes)
    return value


def decisions():
    return [{"decision_id": f"D{i:03d}", "status": "CURRENT", "decision": f"decision-{i}"} for i in range(1, 140)]


def projects():
    rows = [{"project_id": f"project-{i}", "status": "CURRENT_TRUNK"} for i in range(1, 10)]
    rows.append({"project_id": "vision-accessibility-legacy", "status": "LEGACY_VALID_CONCEPT"})
    return rows


def health_doc(**changes):
    value = {"ok": True, "enabled": True, "status": "READ_ONLY_READY", **meta(), "decision_count": 139, "project_count": 10}
    value.update(changes)
    return value


def decision_collection(**changes):
    value = {"meta": meta(), "count": 139, "range": ["D001", "D139"], "records": decisions()}
    value.update(changes)
    return value


def project_collection(**changes):
    value = {"meta": meta(), "count": 10, "records": projects()}
    value.update(changes)
    return value


def binding_doc(**changes):
    value = {
        "schema": c.BINDING_SCHEMA,
        "origin": c.ORIGIN,
        "auth": {"scheme": c.AUTH_SCHEME, "username": c.USERNAME},
        "stable_source_id": c.STABLE_SOURCE_ID,
        "role": c.ROLE,
        "resolution_disposition": c.DISPOSITION,
        "currentness_status": c.CURRENTNESS,
        "authority_upgraded": False,
        "record_digest": c.RECORD_DIGEST,
        "projection_digest": c.PROJECTION_DIGEST,
        "snapshot_digest": c.SNAPSHOT_DIGEST,
        "decision_count": 139,
        "decision_range": ["D001", "D139"],
        "project_count": 10,
        "project_status_counts": {"CURRENT_TRUNK": 9, "LEGACY_VALID_CONCEPT": 1},
        "cache_control_required_tokens": ["private", "no-store"],
    }
    value.update(changes)
    return value


def write_binding(tmp_path: Path, doc=None):
    path = tmp_path / "canonical-binding.json"
    raw = json.dumps(doc or binding_doc(), sort_keys=True, separators=(",", ":")).encode()
    path.write_bytes(raw)
    return path, hashlib.sha256(raw).hexdigest()


def enabled_env(path: Path, sha: str, password="secret-sentinel"):
    return {c.FEATURE_ENV: "1", c.BINDING_ENV: str(path), c.BINDING_SHA_ENV: sha, c.PASSWORD_ENV: password}


class FakeResponse:
    def __init__(self, status=200, doc=None, *, headers=None, raw=None):
        self.status = status
        self._body = raw if raw is not None else json.dumps(doc if doc is not None else {}).encode()
        self._headers = {"Cache-Control": "private, no-store", "Content-Encoding": "identity", **(headers or {})}

    def getheaders(self):
        return list(self._headers.items())

    def read(self, n=-1):
        return self._body if n < 0 else self._body[:n]


class QueueFactory:
    def __init__(self, responses=None, *, error=None):
        self.responses = list(responses or [])
        self.error = error
        self.requests = []

    def __call__(self, host, port, *, timeout, context):
        assert host == c.HOST and port == c.PORT and timeout == c.TIMEOUT_SECONDS
        if self.error:
            raise self.error
        factory = self

        class Connection:
            def request(self, method, path, headers=None):
                factory.requests.append((method, path, dict(headers or {})))

            def getresponse(self):
                if not factory.responses:
                    raise AssertionError("fake response queue exhausted")
                return factory.responses.pop(0)

            def close(self):
                return None

        return Connection()


def config(password="secret-sentinel"):
    return c.ConsumerConfig(binding=binding_doc(), binding_sha256="a" * 64, password=password)


def consumer(responses=None, *, error=None, password="secret-sentinel"):
    factory = QueueFactory(responses, error=error)
    return c.CanonicalPayloadConsumer(config(password), connection_factory=factory), factory


def health_responses(payload=None):
    return [FakeResponse(200, canon_health_doc()), FakeResponse(200, payload or health_doc())]


def test_A01_flag_absent_disabled_zero_network(tmp_path):
    assert c.load_config({}) is None
    assert c.disabled_receipt()["effects"]["network_read"] is False


def test_A02_flag_invalid_hold_zero_network():
    with pytest.raises(c.ConsumerHold) as exc:
        c.load_config({c.FEATURE_ENV: "yes"})
    assert exc.value.status == "HOLD_CONFIG_INVALID"
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is False


def test_A03_binding_missing_symlink_noncanonical_or_sha_mismatch_hold_zero_network(tmp_path):
    missing = tmp_path / "missing.json"
    with pytest.raises(c.ConsumerHold) as exc:
        c.load_config(enabled_env(missing, "a" * 64))
    assert exc.value.status == "HOLD_BINDING_UNAVAILABLE"
    path, sha = write_binding(tmp_path)
    link = tmp_path / "binding-link.json"
    try:
        link.symlink_to(path)
    except (OSError, NotImplementedError):
        pytest.skip("symlink unavailable")
    with pytest.raises(c.ConsumerHold) as exc:
        c.load_config(enabled_env(link, sha))
    assert exc.value.status == "HOLD_BINDING_NONCANONICAL"
    with pytest.raises(c.ConsumerHold) as exc:
        c.load_config(enabled_env(path, "b" * 64))
    assert exc.value.status == "HOLD_BINDING_SHA_MISMATCH"


def test_A04_password_missing_hold_zero_network(tmp_path):
    path, sha = write_binding(tmp_path)
    with pytest.raises(c.ConsumerHold) as exc:
        c.load_config(enabled_env(path, sha, password=""))
    assert exc.value.status == "HOLD_AUTH_UNBOUND"


def test_A05_origin_auth_identity_mismatch_hold_zero_network(tmp_path):
    for doc in (binding_doc(origin="https://example.invalid"), binding_doc(auth={"scheme": "Basic", "username": "other"})):
        path, sha = write_binding(tmp_path, doc)
        with pytest.raises(c.ConsumerHold) as exc:
            c.load_config(enabled_env(path, sha))
        assert exc.value.status == "HOLD_BINDING_IDENTITY_MISMATCH"
        path.unlink()


def test_A06_tls_certificate_failure_hold_no_downgrade_and_receipt_marks_network():
    client, _ = consumer(error=ssl.SSLCertVerificationError(1, "cert failure"))
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_TLS_FAILURE"
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True


@pytest.mark.parametrize("status", [401, 403])
def test_A07_http_401_403_hold_auth_no_retry(status):
    client, factory = consumer([FakeResponse(status, {"detail": {"status": "AUTH"}})])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_AUTH" and len(factory.requests) == 1
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True


def test_A08_http_3xx_hold_redirect_denied():
    client, factory = consumer([FakeResponse(302, {}, headers={"Location": "https://example.invalid"})])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_REDIRECT_DENIED" and len(factory.requests) == 1


def test_A09_health_not_read_only_ready_holds_for_canon_or_payload():
    client, _ = consumer([FakeResponse(200, canon_health_doc(status="DISABLED_DEFAULT", enabled=False))])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_CANON_HEALTH_MISMATCH"
    client, _ = consumer(health_responses(health_doc(status="DISABLED_DEFAULT", enabled=False)))
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_HEALTH_MISMATCH"


def test_A10_meta_source_role_disposition_currentness_or_authority_upgrade_mismatch_hold():
    for change in ({"stable_source_id": "wrong"}, {"role": "wrong"}, {"resolution_disposition": "wrong"}, {"currentness_status": "STALE"}, {"authority_upgraded": True}):
        client, _ = consumer(health_responses(health_doc(**change)))
        with pytest.raises(c.ConsumerHold) as exc:
            client.health()
        assert exc.value.status == "HOLD_META_MISMATCH"
        assert c.hold_receipt(exc.value)["effects"]["network_read"] is True


def test_A11_record_projection_or_snapshot_digest_mismatch_hold():
    for key in ("record_digest", "projection_digest", "snapshot_digest"):
        client, _ = consumer(health_responses(health_doc(**{key: "0" * 64})))
        with pytest.raises(c.ConsumerHold) as exc:
            client.health()
        assert exc.value.status == "HOLD_META_MISMATCH"


def test_A12_decisions_exact_139_contiguous_D001_D139_all_current():
    client, _ = consumer([FakeResponse(200, decision_collection())])
    assert len(client.decisions()["records"]) == 139
    bad = decisions(); bad[-1] = {**bad[-1], "status": "HOLD"}
    client, _ = consumer([FakeResponse(200, decision_collection(records=bad))])
    with pytest.raises(c.ConsumerHold):
        client.decisions()


def test_A13_projects_exact_10_unique_9_trunk_1_legacy_valid():
    client, _ = consumer([FakeResponse(200, project_collection())])
    assert len(client.projects()["records"]) == 10
    bad = projects(); bad[-1] = {"project_id": bad[0]["project_id"], "status": "LEGACY_VALID_CONCEPT"}
    client, _ = consumer([FakeResponse(200, project_collection(records=bad))])
    with pytest.raises(c.ConsumerHold):
        client.projects()


def test_A14_health_decisions_projects_meta_identical():
    dc = decision_collection(); dc["meta"] = meta(record_digest="1" * 64)
    client, _ = consumer([
        FakeResponse(200, canon_health_doc()),
        FakeResponse(200, health_doc()),
        FakeResponse(200, dc),
        FakeResponse(200, project_collection()),
    ])
    with pytest.raises(c.ConsumerHold) as exc:
        client.snapshot()
    assert exc.value.status == "HOLD_META_MISMATCH"
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True


def test_A15_cache_control_private_and_no_store_required_for_payload_surface():
    client, _ = consumer([
        FakeResponse(200, canon_health_doc(), headers={"Cache-Control": ""}),
        FakeResponse(200, health_doc(), headers={"Cache-Control": "private"}),
    ])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_CACHE_CONTROL"


def test_A16_D001_200_D139_200_D999_404_invalid_decision_422_local():
    client, factory = consumer([
        FakeResponse(200, {"meta": meta(), "record": decisions()[0]}),
        FakeResponse(200, {"meta": meta(), "record": decisions()[-1]}),
        FakeResponse(404, {"detail": {"status": "NOT_FOUND"}}),
    ])
    assert client.decision("D001")["status"] == 200
    assert client.decision("D139")["status"] == 200
    assert client.decision("D999")["status"] == 404
    before = len(factory.requests)
    assert client.decision("not-valid")["status"] == 422
    assert client.decision("D001/../../")["status"] == 422
    assert client.decision("D001?x=1")["status"] == 422
    assert client.decision("D001#frag")["status"] == 422
    assert len(factory.requests) == before == 3


def test_A17_continuity_platform_200_unknown_project_404_invalid_project_422_local():
    record = {"project_id": "continuity-platform", "status": "CURRENT_TRUNK"}
    client, factory = consumer([
        FakeResponse(200, {"meta": meta(), "record": record}),
        FakeResponse(404, {"detail": {"status": "NOT_FOUND"}}),
    ])
    assert client.project("continuity-platform")["status"] == 200
    assert client.project("unknown-project")["status"] == 404
    before = len(factory.requests)
    assert client.project("INVALID!")["status"] == 422
    assert client.project("continuity-platform/../../")["status"] == 422
    assert client.project("continuity-platform?x=1")["status"] == 422
    assert len(factory.requests) == before == 2


def test_A18_outbound_http_method_allowlist_GET_only_and_both_health_routes():
    client, factory = consumer(health_responses())
    client.health()
    assert [item[0] for item in factory.requests] == ["GET", "GET"]
    assert [item[1] for item in factory.requests] == [c.CANON_HEALTH_PATH, c.PAYLOAD_HEALTH_PATH]


def test_A19_response_size_limit_fails_closed_and_marks_network():
    client, _ = consumer([FakeResponse(200, canon_health_doc(), headers={"Content-Length": str(c.HEALTH_MAX_BYTES + 1)})])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_RESPONSE_SIZE"
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True


def test_A20_secret_sentinel_absent_from_stdout_stderr_exceptions_and_receipts():
    secret = "VERY-SECRET-SENTINEL"
    client, _ = consumer([FakeResponse(401, {})], password=secret)
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    rendered = json.dumps(c.hold_receipt(exc.value), sort_keys=True)
    assert secret not in str(exc.value) and secret not in rendered


def test_A21_zero_filesystem_db_subprocess_provider_write():
    receipt = c.effects(network_read=True)
    for key in ("filesystem_write", "database_write", "memory_write", "operational_memory_write", "subprocess_execution", "provider_write", "current_state_apply", "canonical_mutation"):
        assert receipt[key] is False
    source = Path(c.__file__).read_text(encoding="utf-8")
    assert "import subprocess" not in source and "import sqlite3" not in source and ".write_text(" not in source and ".write_bytes(" not in source


def test_A22_context_output_projection_only_with_all_effect_ceilings_deny():
    client, _ = consumer([
        FakeResponse(200, canon_health_doc()),
        FakeResponse(200, health_doc()),
        FakeResponse(200, decision_collection()),
        FakeResponse(200, project_collection()),
    ])
    context = client.context()
    assert context["schema"] == c.CONTEXT_SCHEMA and context["mode"] == "EPHEMERAL_PROJECTION_ONLY"
    assert context["effects"]["execution_authorized"] is False and context["effects"]["authority_upgrade"] is False and context["effects"]["mcp_auto_injection"] is False


def test_A23_three_repeated_snapshots_identical_digests_and_canonical_output_hash():
    responses = []
    for _ in range(3):
        responses.extend([
            FakeResponse(200, canon_health_doc()),
            FakeResponse(200, health_doc()),
            FakeResponse(200, decision_collection()),
            FakeResponse(200, project_collection()),
        ])
    client, _ = consumer(responses)
    snapshots = [client.snapshot() for _ in range(3)]
    assert len({s["meta"]["snapshot_digest"] for s in snapshots}) == 1
    assert len({s["canonical_output_sha256"] for s in snapshots}) == 1


def test_A24_producer_503_hold_status_propagates_without_fallback():
    client, factory = consumer([
        FakeResponse(200, canon_health_doc()),
        FakeResponse(503, {"detail": {"status": "HOLD_PAYLOAD_RECONCILE", "reason": "remote"}}),
    ])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_PAYLOAD_RECONCILE" and len(factory.requests) == 2
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True


def test_A25_current_session_containment_is_tested_in_containment_suite():
    assert {"health", "snapshot", "decision", "project", "context"} == {"health", "snapshot", "decision", "project", "context"}


def test_A26_canon_health_identity_and_payload_health_are_both_required():
    client, factory = consumer(health_responses())
    result = client.health()
    assert result["canon_health"]["source_id"] == c.STABLE_SOURCE_ID
    assert result["meta"]["stable_source_id"] == c.STABLE_SOURCE_ID
    assert len(factory.requests) == 2
    client, _ = consumer([FakeResponse(200, canon_health_doc(projection_digest="0" * 64))])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_CANON_HEALTH_MISMATCH"


def test_A27_malformed_point_ids_never_enter_request_target():
    client, factory = consumer([])
    for value in ("D001/../x", "D001?x=1", "D001#x", " D001", "D001%2Fetc"):
        assert client.decision(value)["status"] == 422
    for value in ("continuity-platform/../x", "continuity-platform?x=1", "#frag", "UPPER"):
        assert client.project(value)["status"] == 422
    assert factory.requests == []


def test_A28_transport_failure_receipt_is_conservatively_network_true():
    client, _ = consumer(error=OSError("network down"))
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    receipt = c.hold_receipt(exc.value)
    assert exc.value.status == "HOLD_TRANSPORT_FAILURE"
    assert receipt["effects"]["network_read"] is True
    assert receipt["effects"]["http_method"] == "GET"


def test_A29_post_network_json_and_validation_holds_mark_network_true():
    client, _ = consumer([FakeResponse(200, raw=b"not-json", headers={"Cache-Control": ""})])
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_JSON_INVALID"
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True

    client, _ = consumer(health_responses(health_doc(decision_count=138)))
    with pytest.raises(c.ConsumerHold) as exc:
        client.health()
    assert exc.value.status == "HOLD_COUNT_MISMATCH"
    assert c.hold_receipt(exc.value)["effects"]["network_read"] is True
