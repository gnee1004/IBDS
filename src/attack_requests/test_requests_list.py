from __future__ import annotations
import unittest
from attack_requests.requests_list import RULES, _MAX_ORDER_BY

_REQUIRED_FIELDS = {"attack_id", "vuln_type", "technique", "sequence", "payload_templates"}

class AttackRulesTests(unittest.TestCase):
    def test_rules_have_required_fields(self) -> None:
        for rule in RULES:
            self.assertTrue(_REQUIRED_FIELDS <= set(rule))
    
    def test_attack_ids_are_unique(self) -> None:
        attack_ids = [r["attack_id"] for r in RULES]
        self.assertEqual(len(attack_ids), len(set(attack_ids)))

    def test_order_by_covers_one_to_max(self) -> None:
        rule = next(r for r in RULES if r["attack_id"] == "AR-SQLI-ORDERBY")
        payloads = rule["payload_templates"]["orderby_attack"]
        self.assertEqual(len(payloads), _MAX_ORDER_BY * 3)
        for n in range(1, _MAX_ORDER_BY + 1):
            self.assertTrue(any(f"ORDER BY {n}" in p for p in payloads))


if __name__ == "__main__":
    unittest.main()