from __future__ import annotations

import unittest

from scan.match.matcher import AttackRule
from scan.models import DiscoveryResult, ScanPoint
from scan.mutation.request_builder import (
    build_families_for_point, generate_families,
    generate_xss_families, generate_stored_xss_families,
)


def _rule(attack_id="PL-TEST", payloads=None) -> AttackRule:
    return AttackRule(
        attack_id=attack_id, vuln_type="xss", technique="body",
        sequence=["baseline", "attack"],
        payload_templates={"attack": payloads or ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]},
        allowed_locations=["query"], allowed_value_types=["string"],
    )


def _form_point() -> ScanPoint:
    return ScanPoint(target_id="t0", name="comment", location="form", original_value="x", value_type="string")


def _point() -> ScanPoint:
    return ScanPoint(target_id="t0", name="q", location="query", original_value="x", value_type="string")


def _target() -> dict:
    return {"method": "GET", "url": "http://example.com/s?q=x", "base_url": "http://example.com/s"}


class BuildFamiliesForPointTests(unittest.TestCase):
    def test_no_filter_keeps_all_rendered_payloads(self) -> None:
        families = build_families_for_point(_point(), _target(), [_rule()])

        self.assertEqual(len(families), 1)
        self.assertEqual(len(families[0].mutations), 2)

    def test_payload_filter_drops_non_matching_payloads(self) -> None:
        families = build_families_for_point(
            _point(), _target(), [_rule()],
            payload_filter=lambda p: "script" in p,
        )

        self.assertEqual(len(families), 1)
        self.assertEqual(len(families[0].mutations), 1)
        self.assertIn("script", families[0].mutations[0].payload)

    def test_family_with_zero_surviving_payloads_is_dropped_entirely(self) -> None:
        families = build_families_for_point(
            _point(), _target(), [_rule()],
            payload_filter=lambda p: False,
        )

        self.assertEqual(families, [])


class GenerateXssFamiliesTests(unittest.TestCase):
    def test_not_reflected_produces_no_families(self) -> None:
        discovery = DiscoveryResult(reflected=False, valid_specials=set())

        families = generate_xss_families(_point(), _target(), discovery)

        self.assertEqual(families, [])

    def test_reflected_with_no_valid_specials_drops_all_tag_based_payloads(self) -> None:
        discovery = DiscoveryResult(reflected=True, valid_specials=set())

        families = generate_xss_families(_point(), _target(), discovery)

        for family in families:
            for mutation in family.mutations:
                self.assertFalse(any(ch in mutation.payload for ch in ["<", ">", '"']))

    def test_reflected_with_full_specials_includes_tag_based_payloads(self) -> None:
        discovery = DiscoveryResult(
            reflected=True,
            valid_specials={"<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"},
        )

        families = generate_xss_families(_point(), _target(), discovery)
        payloads = [m.payload for f in families for m in f.mutations]

        self.assertTrue(any("<script>" in p for p in payloads))

    def test_stored_technique_is_excluded_from_reflected_route(self) -> None:
        discovery = DiscoveryResult(
            reflected=True,
            valid_specials={"<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"},
        )

        families = generate_xss_families(_point(), _target(), discovery)

        self.assertTrue(all(f.technique != "stored" for f in families))


class GenerateStoredXssFamiliesTests(unittest.TestCase):
    def test_query_location_produces_no_families(self) -> None:
        families = generate_stored_xss_families(_point(), _target())

        self.assertEqual(families, [])

    def test_form_location_only_uses_stored_technique(self) -> None:
        families = generate_stored_xss_families(_form_point(), _target())

        self.assertTrue(len(families) >= 1)
        self.assertTrue(all(f.technique == "stored" for f in families))

    def test_form_location_does_not_require_discovery(self) -> None:
        families = generate_stored_xss_families(_form_point(), _target())

        self.assertIsInstance(families, list)


if __name__ == "__main__":
    unittest.main()
