from __future__ import annotations

import json
import unittest

from continuityos.ruap_portability import (
    REQUIRED_AUTHORITY_CEILING,
    diff_ruap_snapshots,
    export_ruap_snapshot,
    import_ruap_snapshot,
    validate_ruap_snapshot,
)


def snapshot(*, claim: str = "current", source_id: str = "s1") -> dict:
    return {
        "schema": "ruap.snapshot/v1",
        "generated_at": "2026-09-01T15:44:47+07:00",
        "authority_ceiling": "OBSERVE_ONLY",
        "sources": [
            {
                "id": source_id,
                "provider": "github",
                "locator": "owner/repo@main",
                "observed_at": "2026-09-01T15:44:47+07:00",
            }
        ],
        "observations": [
            {
                "subject": "repo.main",
                "claim": claim,
                "class": "PROVIDER_READBACK",
                "source_id": source_id,
                "freshness_required_before_effect": True,
            }
        ],
    }


class RuapPortabilityTests(unittest.TestCase):
    def test_valid_snapshot_imports_as_evidence_only(self):
        raw = json.dumps(snapshot()).encode()
        result = validate_ruap_snapshot(raw)
        self.assertTrue(result.ok)
        evidence = import_ruap_snapshot(raw)
        self.assertEqual(evidence.authority_class, "EVIDENCE_ONLY")
        self.assertEqual(evidence.authority_ceiling, REQUIRED_AUTHORITY_CEILING)
        self.assertEqual(evidence.source_count, 1)
        self.assertEqual(evidence.observation_count, 1)
        self.assertTrue(evidence.freshness_required)

    def test_key_order_does_not_change_identity(self):
        first = snapshot()
        second = {
            "observations": first["observations"],
            "sources": first["sources"],
            "authority_ceiling": first["authority_ceiling"],
            "generated_at": first["generated_at"],
            "schema": first["schema"],
        }
        self.assertEqual(
            import_ruap_snapshot(json.dumps(first)).snapshot_sha256,
            import_ruap_snapshot(json.dumps(second)).snapshot_sha256,
        )

    def test_rejects_non_observe_only_ceiling(self):
        value = snapshot()
        value["authority_ceiling"] = "EXECUTE"
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertFalse(result.ok)
        self.assertIn("authority_ceiling_not_observe_only", result.errors)

    def test_accepts_explicit_safe_root_effect_authority_values(self):
        value = snapshot()
        value.update(
            {
                "execution_authority": "NONE",
                "can_execute": False,
                "can_trade": False,
                "capital_permission": "DENY",
                "deploy_permission": "DENY",
            }
        )
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertTrue(result.ok, result.errors)

    def test_rejects_explicit_execute_authority(self):
        value = snapshot()
        value["can_execute"] = True
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertFalse(result.ok)
        self.assertIn("root_effect_authority_not_safe:can_execute", result.errors)

    def test_rejects_explicit_trade_authority(self):
        value = snapshot()
        value["can_trade"] = True
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertFalse(result.ok)
        self.assertIn("root_effect_authority_not_safe:can_trade", result.errors)

    def test_rejects_unknown_or_escalating_root_effect_authority_values(self):
        cases = (
            ("execution_authority", "ALLOW"),
            ("execution_authority", "UNKNOWN"),
            ("capital_permission", "GRANTED"),
            ("capital_permission", "UNKNOWN"),
            ("deploy_permission", "ALLOW"),
            ("deploy_permission", "UNKNOWN"),
        )
        for key, unsafe_value in cases:
            with self.subTest(key=key, unsafe_value=unsafe_value):
                value = snapshot()
                value[key] = unsafe_value
                result = validate_ruap_snapshot(json.dumps(value))
                self.assertFalse(result.ok)
                self.assertIn(f"root_effect_authority_not_safe:{key}", result.errors)

    def test_rejects_wrong_types_for_root_effect_authority_values(self):
        cases = (
            ("execution_authority", False),
            ("can_execute", "false"),
            ("can_trade", 0),
            ("capital_permission", None),
            ("deploy_permission", True),
        )
        for key, wrong_type_value in cases:
            with self.subTest(key=key, wrong_type_value=wrong_type_value):
                value = snapshot()
                value[key] = wrong_type_value
                result = validate_ruap_snapshot(json.dumps(value))
                self.assertFalse(result.ok)
                self.assertIn(f"root_effect_authority_invalid_type:{key}", result.errors)

    def test_rejects_duplicate_source_ids(self):
        value = snapshot()
        value["sources"].append(dict(value["sources"][0]))
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertFalse(result.ok)
        self.assertIn("duplicate_source_id", result.errors)

    def test_rejects_unknown_observation_source(self):
        value = snapshot()
        value["observations"][0]["source_id"] = "missing"
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertFalse(result.ok)
        self.assertIn("observation_0_unknown_source_id", result.errors)

    def test_rejects_unknown_observation_class(self):
        value = snapshot()
        value["observations"][0]["class"] = "EXECUTION_AUTHORITY"
        result = validate_ruap_snapshot(json.dumps(value))
        self.assertFalse(result.ok)
        self.assertIn("observation_0_unsupported_class", result.errors)

    def test_export_is_deterministic_and_observe_only(self):
        value = snapshot()
        one = export_ruap_snapshot(
            generated_at=value["generated_at"],
            sources=value["sources"],
            observations=value["observations"],
        )
        two = export_ruap_snapshot(
            generated_at=value["generated_at"],
            sources=value["sources"],
            observations=value["observations"],
        )
        self.assertEqual(one, two)
        parsed = json.loads(one)
        self.assertEqual(parsed["authority_ceiling"], "OBSERVE_ONLY")

    def test_diff_reports_added_source_and_observation(self):
        old = snapshot()
        new = snapshot()
        new["sources"].append(
            {
                "id": "s2",
                "provider": "drive",
                "locator": "file-2",
                "observed_at": "2026-09-01T15:45:00+07:00",
            }
        )
        new["observations"].append(
            {
                "subject": "doc.current",
                "claim": "fresh",
                "class": "PROVIDER_READBACK",
                "source_id": "s2",
            }
        )
        delta = diff_ruap_snapshots(json.dumps(old), json.dumps(new))
        self.assertEqual(delta.added_source_ids, ("s2",))
        self.assertEqual(delta.removed_source_ids, ())
        self.assertEqual(len(delta.added_observation_digests), 1)
        self.assertEqual(delta.removed_observation_digests, ())

    def test_non_utf8_fails_closed(self):
        result = validate_ruap_snapshot(b"\xff\xfe")
        self.assertFalse(result.ok)
        self.assertEqual(result.errors, ("snapshot_not_utf8",))


if __name__ == "__main__":
    unittest.main()
