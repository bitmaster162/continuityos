from __future__ import annotations

import copy
import unittest

from continuityos.shadow_replay_history import (
    ShadowContinuityError,
    build_case_append_candidate,
    build_empty_case_ledger,
    build_empty_replay_registry,
    build_replay_admission_candidate,
    sha256_obj,
    validate_case_ledger,
    validate_replay_registry,
)

ROOT = "1" * 64
CASE_SHA = "2" * 64
BINDING = "3" * 64
REPLAY_INPUT = "4" * 64
GENESIS = "5" * 64


class ShadowReplayHistoryR3Tests(unittest.TestCase):
    def registry(self):
        return build_empty_replay_registry(registry_id="p0-r3", authority_root_sha256=ROOT)

    def ledger(self):
        return build_empty_case_ledger(
            ledger_id="ledger:case-001",
            case_id="case-001",
            case_sha256=CASE_SHA,
            case_binding_sha256=BINDING,
            genesis_sha256=GENESIS,
        )

    def append(self, ledger, event_type, subject, idem, second):
        return build_case_append_candidate(
            ledger,
            expected_ledger_sha256=ledger["ledger_sha256"],
            expected_head_event_sha256=ledger["head_event_sha256"],
            event_type=event_type,
            subject_sha256=subject,
            idempotency_key=idem,
            recorded_at=f"2026-08-20T02:{second:02d}:00+07:00",
        )["next_ledger_candidate"]

    def test_new_case_admission_is_candidate_only(self):
        registry = self.registry()
        candidate = build_replay_admission_candidate(
            registry,
            expected_registry_sha256=registry["registry_sha256"],
            expected_authority_root_sha256=ROOT,
            case_id="case-001",
            case_sha256=CASE_SHA,
            case_binding_sha256=BINDING,
            replay_input_sha256=REPLAY_INPUT,
            ledger_id="ledger:case-001",
        )
        self.assertEqual(candidate["status"], "ADMITTABLE_NEW_CASE_SHADOW_ONLY")
        self.assertFalse(candidate["registry_write_performed"])
        self.assertFalse(candidate["apply_allowed"])
        self.assertEqual(candidate["execution_authority"], "NONE")
        self.assertEqual(candidate["next_registry_candidate"]["entry_count"], 1)

    def test_old_case_cannot_reenter_under_new_case_id(self):
        registry = self.registry()
        first = build_replay_admission_candidate(
            registry,
            expected_registry_sha256=registry["registry_sha256"],
            expected_authority_root_sha256=ROOT,
            case_id="case-001",
            case_sha256=CASE_SHA,
            case_binding_sha256=BINDING,
            replay_input_sha256=REPLAY_INPUT,
            ledger_id="ledger:case-001",
        )["next_registry_candidate"]
        with self.assertRaisesRegex(ShadowContinuityError, "case_alias_replay_detected"):
            build_replay_admission_candidate(
                first,
                expected_registry_sha256=first["registry_sha256"],
                expected_authority_root_sha256=ROOT,
                case_id="case-rewrapped",
                case_sha256=CASE_SHA,
                case_binding_sha256="6" * 64,
                replay_input_sha256="7" * 64,
                ledger_id="ledger:rewrapped",
            )

    def test_same_case_id_with_new_binding_is_fork(self):
        registry = self.registry()
        first = build_replay_admission_candidate(
            registry,
            expected_registry_sha256=registry["registry_sha256"],
            expected_authority_root_sha256=ROOT,
            case_id="case-001",
            case_sha256=CASE_SHA,
            case_binding_sha256=BINDING,
            replay_input_sha256=REPLAY_INPUT,
            ledger_id="ledger:case-001",
        )["next_registry_candidate"]
        with self.assertRaisesRegex(ShadowContinuityError, "case_history_fork_detected"):
            build_replay_admission_candidate(
                first,
                expected_registry_sha256=first["registry_sha256"],
                expected_authority_root_sha256=ROOT,
                case_id="case-001",
                case_sha256="8" * 64,
                case_binding_sha256="9" * 64,
                replay_input_sha256="a" * 64,
                ledger_id="ledger:fork",
            )

    def test_stale_external_registry_snapshot_is_rejected(self):
        registry = self.registry()
        with self.assertRaisesRegex(ShadowContinuityError, "replay_registry_external_snapshot_mismatch"):
            validate_replay_registry(
                registry,
                expected_registry_sha256="f" * 64,
                expected_authority_root_sha256=ROOT,
            )

    def test_happy_history_chain_is_append_only_candidate(self):
        ledger = self.ledger()
        steps = (
            ("CASE_QUALIFIED", "a" * 64, "q", 31),
            ("TWIN_COMMITTED", "b" * 64, "t", 32),
            ("DECISION_PACKET", "c" * 64, "d", 33),
            ("HUMAN_REVEAL", "d" * 64, "r", 34),
            ("OUTCOME_RECEIPT", "e" * 64, "o", 35),
            ("RETURN_INTAKE", "f" * 64, "i", 36),
        )
        for event_type, subject, idem, second in steps:
            ledger = self.append(ledger, event_type, subject, idem, second)
        validated = validate_case_ledger(
            ledger,
            expected_ledger_sha256=ledger["ledger_sha256"],
            expected_head_event_sha256=ledger["head_event_sha256"],
        )
        self.assertEqual(validated["event_count"], 6)
        self.assertEqual(validated["human_reveal_count"], 1)
        self.assertEqual(validated["outcome_count"], 1)
        self.assertEqual(validated["return_intake_count"], 1)
        self.assertFalse(validated["write_allowed"])
        self.assertFalse(validated["apply_allowed"])

    def test_one_case_one_reveal(self):
        ledger = self.ledger()
        ledger = self.append(ledger, "CASE_QUALIFIED", "a" * 64, "q", 31)
        ledger = self.append(ledger, "TWIN_COMMITTED", "b" * 64, "t", 32)
        ledger = self.append(ledger, "DECISION_PACKET", "c" * 64, "d", 33)
        ledger = self.append(ledger, "HUMAN_REVEAL", "d" * 64, "r1", 34)
        with self.assertRaisesRegex(ShadowContinuityError, "one_case_one_reveal_violation"):
            self.append(ledger, "HUMAN_REVEAL", "e" * 64, "r2", 35)

    def test_duplicate_return_is_rejected(self):
        ledger = self.ledger()
        for event_type, subject, idem, second in (
            ("CASE_QUALIFIED", "a" * 64, "q", 31),
            ("TWIN_COMMITTED", "b" * 64, "t", 32),
            ("DECISION_PACKET", "c" * 64, "d", 33),
            ("HUMAN_REVEAL", "d" * 64, "r", 34),
            ("OUTCOME_RECEIPT", "e" * 64, "o", 35),
            ("RETURN_INTAKE", "f" * 64, "i1", 36),
        ):
            ledger = self.append(ledger, event_type, subject, idem, second)
        with self.assertRaisesRegex(ShadowContinuityError, "duplicate_return_intake_detected"):
            self.append(ledger, "RETURN_INTAKE", "f" * 64, "i2", 37)

    def test_event_reordering_even_if_rehashed_is_rejected(self):
        ledger = self.ledger()
        ledger = self.append(ledger, "CASE_QUALIFIED", "a" * 64, "q", 31)
        ledger = self.append(ledger, "TWIN_COMMITTED", "b" * 64, "t", 32)
        forged = copy.deepcopy(ledger)
        forged_events = list(forged["events"])
        forged_events.reverse()
        previous = forged["genesis_sha256"]
        for seq, event in enumerate(forged_events, start=1):
            event["sequence"] = seq
            event["previous_event_sha256"] = previous
            event["event_sha256"] = sha256_obj({k: v for k, v in event.items() if k != "event_sha256"})
            previous = event["event_sha256"]
        forged["events"] = tuple(forged_events)
        forged["head_event_sha256"] = previous
        forged["ledger_sha256"] = sha256_obj({k: v for k, v in forged.items() if k != "ledger_sha256"})
        with self.assertRaisesRegex(ShadowContinuityError, "case_event_order_regression"):
            validate_case_ledger(
                forged,
                expected_ledger_sha256=forged["ledger_sha256"],
                expected_head_event_sha256=forged["head_event_sha256"],
            )

    def test_forked_previous_head_is_rejected_even_if_ledger_rehashed(self):
        ledger = self.ledger()
        ledger = self.append(ledger, "CASE_QUALIFIED", "a" * 64, "q", 31)
        ledger = self.append(ledger, "TWIN_COMMITTED", "b" * 64, "t", 32)
        forged = copy.deepcopy(ledger)
        forged["events"][1]["previous_event_sha256"] = "0" * 64
        forged["events"][1]["event_sha256"] = sha256_obj(
            {k: v for k, v in forged["events"][1].items() if k != "event_sha256"}
        )
        forged["head_event_sha256"] = forged["events"][1]["event_sha256"]
        forged["ledger_sha256"] = sha256_obj({k: v for k, v in forged.items() if k != "ledger_sha256"})
        with self.assertRaisesRegex(ShadowContinuityError, "case_event_chain_fork_detected"):
            validate_case_ledger(
                forged,
                expected_ledger_sha256=forged["ledger_sha256"],
                expected_head_event_sha256=forged["head_event_sha256"],
            )

    def test_rollback_to_old_but_valid_snapshot_fails_external_head(self):
        genesis = self.ledger()
        after_one = self.append(genesis, "CASE_QUALIFIED", "a" * 64, "q", 31)
        after_two = self.append(after_one, "TWIN_COMMITTED", "b" * 64, "t", 32)
        with self.assertRaisesRegex(ShadowContinuityError, "case_ledger_external_snapshot_mismatch"):
            validate_case_ledger(
                after_one,
                expected_ledger_sha256=after_two["ledger_sha256"],
                expected_head_event_sha256=after_two["head_event_sha256"],
            )

    def test_outcome_before_reveal_and_return_before_outcome_are_rejected(self):
        ledger = self.ledger()
        ledger = self.append(ledger, "CASE_QUALIFIED", "a" * 64, "q", 31)
        ledger = self.append(ledger, "TWIN_COMMITTED", "b" * 64, "t", 32)
        ledger = self.append(ledger, "DECISION_PACKET", "c" * 64, "d", 33)
        with self.assertRaisesRegex(ShadowContinuityError, "outcome_without_human_reveal"):
            self.append(ledger, "OUTCOME_RECEIPT", "e" * 64, "o", 34)
        with self.assertRaisesRegex(ShadowContinuityError, "return_without_outcome"):
            self.append(ledger, "RETURN_INTAKE", "f" * 64, "i", 34)


if __name__ == "__main__":
    unittest.main()
