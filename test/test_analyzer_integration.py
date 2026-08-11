import json
import os
import tempfile
import unittest

from analyzer.scan import analyze_family, analyze_results


def case(step, payload, body, elapsed=0.1, headers=None):
    return {
        "case": {
            "step": step,
            "method": "GET",
            "url": "http://example.test/?q=1",
            "body_type": "query",
            "payload": payload,
        },
        "status": "ok",
        "response_status": 200,
        "response_body": body,
        "response_headers": headers or {},
        "elapsed": elapsed,
    }


def family(vuln_type, technique, mutations, baseline_body="normal page", baseline=None):
    return {
        "family_id": f"f-{vuln_type}-{technique}",
        "target_id": "t0",
        "vuln_type": vuln_type,
        "technique": technique,
        "param": "q",
        "baseline": baseline if baseline is not None else case("baseline", None, baseline_body),
        "mutations": mutations,
    }


# DVWA sqli_blind 흉내: 큰 정적 페이지에서 한 줄만 exists/MISSING 차이 (blind SQLi)
_BLIND_TPL = ("<html>공통 본문 " * 60) + "{M}" + (" 공통 푸터 " * 60) + "</html>"
_BLIND_EXISTS = _BLIND_TPL.replace("{M}", "User ID exists in the database.")
_BLIND_MISSING = _BLIND_TPL.replace("{M}", "User ID is MISSING from the database.")


class AnalyzerIntegrationTest(unittest.TestCase):
    def test_reflected_xss(self):
        payload = "<script>alert(1)</script>"
        findings = analyze_family(family("xss", "body", [case("attack", payload, payload)]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vuln_type"], "xss")

    def test_error_sqli(self):
        body = "You have an error in your SQL syntax"
        findings = analyze_family(family("sqli", "error_meta", [case("attack", "1'", body)]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["technique"], "error_meta")

    def test_boolean_sqli(self):
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1 AND 1=1", "normal page"),
                case("false_attack", "1 AND 1=2", "access denied with different content"),
            ],
        )
        self.assertEqual(len(analyze_family(item)), 1)

    def test_boolean_blind_sqli(self):
        # 정적 페이지에서 exists/MISSING 미세차 + 스타일 페어링('만 통함)으로 blind 탐지
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1' AND '1'='1", _BLIND_EXISTS),    # ' 스타일 통함 → exists
                case("true_attack", "1 AND 1=1", _BLIND_MISSING),        # 숫자 스타일 미해석 → missing
                case("false_attack", "1' AND '1'='2", _BLIND_MISSING),   # ' 스타일 → missing
                case("false_attack", "1 AND 1=2", _BLIND_MISSING),       # 숫자 스타일 → missing
            ],
            baseline_body=_BLIND_EXISTS,
        )
        self.assertEqual(len(analyze_family(item)), 1)

    def test_boolean_or_sqli(self):
        # OR 패턴: true(OR 1=1)가 baseline과 다름(전체 행 반환), false는 baseline과 같음 → 방향 반대여도 탐지
        item = family(
            "sqli",
            "boolean_or",
            [
                case("true_attack", "x' OR '1'='1", "row1\nrow2\nrow3\nrow4\nrow5 전체 반환"),
                case("false_attack", "x' AND '1'='2", "빈 결과 페이지"),
            ],
            baseline_body="빈 결과 페이지",
        )
        self.assertEqual(len(analyze_family(item)), 1)

    def test_boolean_and_true_gate(self):
        # true가 baseline과 크게 다름 = 주입이 SQL로 해석 안 됨 → 안전(미탐)
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1' AND '1'='1", "완전히 다른 에러 페이지 zzz"),
                case("false_attack", "1' AND '1'='2", "또 다른 페이지 yyy"),
            ],
            baseline_body="정상 목록 aaaa bbbb cccc dddd",
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_boolean_dynamic_no_false_positive(self):
        # true/false 논리적으로 동일, user_token만 매번 다른 동적 페이지 → 오탐 없어야
        tok = lambda i: f"<input name=user_token value=tok{i}>"
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1 AND 1=1", "본문 " + tok(1) + " welcome"),
                case("false_attack", "1 AND 1=2", "본문 " + tok(2) + " welcome"),
            ],
            baseline_body="본문 " + tok(0) + " welcome",
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_union_sqli(self):
        body = "The used SELECT statements have a different number of columns"
        item = family("sqli", "union", [case("attack", "1' UNION SELECT NULL-- -", body)])
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["technique"], "union")

    def test_order_by_sqli(self):
        # ASC/DESC 응답 정렬이 달라짐 → 주입 확인
        item = family(
            "sqli",
            "order_by",
            [
                case("attack", "name ASC -- ", "row A\nrow B\nrow C"),
                case("attack", "name DESC -- ", "row C\nrow B\nrow A"),
            ],
        )
        self.assertEqual(len(analyze_family(item)), 1)

    def test_stacked_time_sqli(self):
        # baseline 대비 지연이 재현되면 time-based(stacked) 확인
        item = family(
            "sqli",
            "stacked",
            [
                case("attack", "1'; SELECT SLEEP(3)-- ", "", elapsed=3.1),
                case("attack", "1'; SELECT SLEEP(3)-- ", "", elapsed=3.0),
            ],
        )
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "high")

    def test_time_no_false_positive_on_slow_page(self):
        # 원래 느린 페이지(baseline 3s)에서 공격도 3s면 baseline 차이 없음 → 미탐
        item = family(
            "sqli",
            "time_mysql",
            [case("attack", "1 AND SLEEP(3)-- ", "", elapsed=3.1)],
            baseline=case("baseline", None, "", elapsed=3.0),
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_open_redirect(self):
        item = family(
            "open_redirect",
            "open_redirect",
            [case("attack", "https://attacker.example/", "",
                  headers={"Location": "https://attacker.example/"})],
            baseline=case("baseline", None, "", headers={"Location": "/home"}),
        )
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vuln_type"], "open_redirect")

    def test_jsonl_to_findings(self):
        payload = "<img src=x onerror=alert(1)>"
        item = family("xss", "body", [case("attack", payload, payload)])
        with tempfile.TemporaryDirectory() as directory:
            results_path = os.path.join(directory, "request_results.jsonl")
            with open(results_path, "w", encoding="utf-8") as file:
                file.write(json.dumps(item) + "\n")
            output_path = analyze_results(results_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, encoding="utf-8") as file:
                self.assertEqual(len(json.load(file)), 1)


if __name__ == "__main__":
    unittest.main()
