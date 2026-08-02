from __future__ import annotations

import json
import os
import tempfile
import unittest
from dataclasses import asdict, dataclass

from analyzer import family_pipeline
from analyzer.headless import HeadlessVerdict
from scan.models import CaseResult, FamilyResult, MutationCase


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


# scan.models의 실제 dataclass를 asdict로 왕복시켜 만든 fixture (Finding 1: attack_id 필드 누락 회귀 방지)
def _real_family_result(payload: str, response_body: str) -> dict:
    baseline_case = MutationCase(
        case_id="t0_name_PL-XSS-BODY_baseline", step="baseline", method="GET",
        url="http://x/vuln?name=orig", headers={}, cookies={}, body_type="query", body="",
    )
    mutation_case = MutationCase(
        case_id="t0_name_PL-XSS-BODY_attack_0", step="body_attack", method="GET",
        url="http://x/vuln?name=" + payload, headers={}, cookies={}, body_type="query", body="",
        payload=payload, original_value="orig",
    )
    family_result = FamilyResult(
        family_id="t0_name_PL-XSS-BODY", vuln_type="xss", technique="body",
        target_id="t0", param="name", attack_id="PL-XSS-BODY",
        baseline=CaseResult(case=baseline_case, status="ok", response_status=200,
                             response_headers={}, response_body="orig", effective_cookies={}),
        mutations=[CaseResult(case=mutation_case, status="ok", response_status=200,
                               response_headers={}, response_body=response_body, effective_cookies={})],
    )
    return asdict(family_result)


class RealDataclassRoundTripTests(unittest.TestCase):
    # FamilyResult에 attack_id가 실제로 존재하고 _judge_case까지 KeyError 없이 전달되는지 확인
    def test_judge_case_reads_attack_id_from_real_family_result_asdict(self) -> None:
        family = _real_family_result("<script>alert(1)</script>", "<script>alert(1)</script>")
        case_result = family["mutations"][0]

        finding = family_pipeline._judge_case(family, case_result, _FakeHeadless(executed=True))

        self.assertEqual(finding.attack_id, "PL-XSS-BODY")
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

    # Finding 2: 한 case의 판정 실패(예외)가 나머지 case 판정을 막지 않는지 확인
    def test_one_case_raising_does_not_abort_other_cases(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            results_path = os.path.join(tmp, "request_results.jsonl")
            broken_case_result = {"status": "ok"}  # "case" 키가 없어 _judge_case 내부에서 KeyError 유발
            good_case_result = _case_result("<script>alert(1)</script>", "<script>alert(1)</script>")
            with open(results_path, "w", encoding="utf-8") as f:
                f.write(json.dumps(_family(mutations=[broken_case_result, good_case_result])) + "\n")

            out_path = family_pipeline.run(results_path, headless=_FakeHeadless(executed=True))

            with open(out_path, encoding="utf-8") as f:
                lines = [json.loads(line) for line in f]

            self.assertEqual(len(lines), 1)  # 깨진 case는 건너뛰고 정상 case만 기록됨
            self.assertEqual(lines[0]["final_status"], "vulnerable")


# Finding 5: status="error"인 case_result는 headless를 호출하지 않고 즉시 safe 처리되는지 확인
class ErrorStatusCaseTests(unittest.TestCase):
    def test_error_status_case_skips_headless_and_is_safe(self) -> None:
        case_result = _case_result("#<img src=x onerror=alert(1)>", "")
        case_result["status"] = "error"  # 요청 자체가 실패한 case

        class _RaisingHeadless:  # 호출되면 즉시 실패해 headless가 호출되지 않았음을 증명하는 stub
            def confirm_via_render(self, response_body: str) -> HeadlessVerdict:
                raise AssertionError("headless가 호출되면 안 됨")

            def confirm_via_navigate(self, url: str, cookies: dict, method: str) -> HeadlessVerdict:
                raise AssertionError("headless가 호출되면 안 됨")

        finding = family_pipeline._judge_case(_family(technique="dom"), case_result, _RaisingHeadless())

        self.assertFalse(finding.headless_checked)
        self.assertIsNone(finding.headless_verdict)
        self.assertEqual(finding.final_status, "safe")


if __name__ == "__main__":
    unittest.main()
