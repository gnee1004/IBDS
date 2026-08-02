from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import dataclass

from analyzer import family_pipeline
from analyzer.headless import HeadlessVerdict


@dataclass
class _FakeHeadless:  # 실제 브라우저 없이 headless 결과를 고정값으로 흉내내는 stub
    executed: bool = True

    def confirm_via_render(self, response_body: str) -> HeadlessVerdict:
        return HeadlessVerdict(executed=self.executed, method="render", evidence="fake render")

    def confirm_via_navigate(self, url: str, cookies: dict, method: str) -> HeadlessVerdict:
        return HeadlessVerdict(executed=self.executed, method="navigate", evidence="fake navigate")


def _family(vuln_type="xss", technique="body", mutations=None) -> dict:
    return {
        "family_id": "t0_name_PL-XSS-BODY",
        "vuln_type": vuln_type,
        "technique": technique,
        "target_id": "t0",
        "param": "name",
        "attack_id": "PL-XSS-BODY",
        "baseline": {"case": {"case_id": "t0_name_PL-XSS-BODY_baseline"}, "status": "ok"},
        "mutations": mutations or [],
    }


def _case_result(payload: str, response_body: str, case_id="t0_name_PL-XSS-BODY_attack_0") -> dict:
    return {
        "case": {
            "case_id": case_id, "payload": payload,
            "url": "http://x/vuln?name=" + payload, "method": "GET",
        },
        "status": "ok",
        "response_body": response_body,
        "effective_cookies": {},
    }


class JudgeCaseTests(unittest.TestCase):
    def test_raw_hit_becomes_headless_target_and_vulnerable_when_executed(self) -> None:
        case_result = _case_result("<script>alert(1)</script>", "<script>alert(1)</script>")
        finding = family_pipeline._judge_case(_family(), case_result, _FakeHeadless(executed=True))

        self.assertTrue(finding.headless_checked)
        self.assertEqual(finding.final_status, "vulnerable")

    def test_raw_hit_but_headless_not_executed_is_reflected_only(self) -> None:
        case_result = _case_result("<script>alert(1)</script>", "<script>alert(1)</script>")
        finding = family_pipeline._judge_case(_family(), case_result, _FakeHeadless(executed=False))

        self.assertTrue(finding.headless_checked)
        self.assertEqual(finding.final_status, "reflected_only")

    def test_no_raw_hit_and_not_dom_skips_headless_and_is_safe(self) -> None:
        case_result = _case_result("<script>alert(1)</script>", "no reflection here")
        finding = family_pipeline._judge_case(_family(technique="body"), case_result, _FakeHeadless())

        self.assertFalse(finding.headless_checked)
        self.assertIsNone(finding.headless_verdict)
        self.assertEqual(finding.final_status, "safe")

    def test_dom_technique_is_always_headless_target_even_without_raw_hit(self) -> None:
        case_result = _case_result("#<img src=x onerror=alert(1)>", "no reflection here")
        finding = family_pipeline._judge_case(
            _family(technique="dom"), case_result, _FakeHeadless(executed=True)
        )

        self.assertTrue(finding.headless_checked)
        self.assertEqual(finding.headless_verdict["method"], "navigate")
        self.assertEqual(finding.final_status, "vulnerable")


class RunTests(unittest.TestCase):
    def test_run_writes_one_finding_per_xss_mutation_and_skips_sqli(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            results_path = os.path.join(tmp, "request_results.jsonl")
            with open(results_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(_family(mutations=[
                    _case_result("<script>alert(1)</script>", "<script>alert(1)</script>"),
                ])) + "\n")
                f.write(json.dumps(_family(vuln_type="sqli", technique="error_meta", mutations=[
                    _case_result("' OR 1=1", "sql error"),
                ])) + "\n")

            out_path = family_pipeline.run(results_path, headless=_FakeHeadless(executed=True))

            with open(out_path, encoding="utf-8") as f:
                lines = [json.loads(line) for line in f]

            self.assertEqual(len(lines), 1)
            self.assertEqual(lines[0]["final_status"], "vulnerable")


if __name__ == "__main__":
    unittest.main()
