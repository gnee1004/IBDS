from __future__ import annotations

import unittest

from payload.sqli import SQLI_RULES
from payload.xss import XSS_RULES

_REQUIRED_FIELDS = {"attack_id", "vuln_type", "technique", "sequence", "payload_templates"}


class PayloadRulesTests(unittest.TestCase):
    def test_rules_have_required_fields(self) -> None:
        for rule in SQLI_RULES + XSS_RULES:
            self.assertTrue(_REQUIRED_FIELDS <= set(rule))

    def test_attack_ids_are_unique(self) -> None:
        attack_ids = [r["attack_id"] for r in SQLI_RULES + XSS_RULES]
        self.assertEqual(len(attack_ids), len(set(attack_ids)))

    def test_boolean_rules_have_matching_true_false_counts(self) -> None:
        for rule in SQLI_RULES:
            if rule["technique"] in ("boolean_and", "boolean_or"):
                templates = rule["payload_templates"]
                self.assertEqual(len(templates["true_attack"]), len(templates["false_attack"]))

    def test_no_empty_payload_lists(self) -> None:
        for rule in SQLI_RULES + XSS_RULES:
            for step_payloads in rule["payload_templates"].values():
                self.assertTrue(step_payloads)


if __name__ == "__main__":
    unittest.main()
