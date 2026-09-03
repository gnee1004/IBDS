import json
import os
import tempfile
import unittest

from analyzer.scan import analyze_family, analyze_results
from analyzer.sqli.judge import _strip_value


def case(step, payload, body, elapsed=0.1):
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
        "elapsed": elapsed,
    }


def family(vuln_type, technique, mutations, baseline_body="normal page", baseline=None, dynamic_markers=None):
    return {
        "family_id": f"f-{vuln_type}-{technique}",
        "target_id": "t0",
        "vuln_type": vuln_type,
        "technique": technique,
        "param": "q",
        "baseline": baseline if baseline is not None else case("baseline", None, baseline_body),
        "mutations": mutations,
        "dynamic_markers": dynamic_markers or [],
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
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "medium")  # injection 스타일 1개뿐이라 재현성 확인 불가 -> suspected

    def test_boolean_sqli_high_confidence_when_multiple_styles_agree(self):
        # 서로 다른 injection 스타일(숫자식/따옴표식) 둘 다 같은 true/false 분기를 보이면 재현성 확인됨 -> confirmed
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1 AND 1=1", "normal page"),
                case("true_attack", "1' AND '1'='1", "normal page"),
                case("false_attack", "1 AND 1=2", "access denied with different content"),
                case("false_attack", "1' AND '1'='2", "access denied with different content"),
            ],
        )
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertIn("2/2", findings[0]["evidence"])

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
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "medium")  # ' 스타일 1개만 재현됨(숫자 스타일은 미해석) -> suspected

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

    def test_strip_value_ignores_short_payload(self):
        # original_value=""면 "{value}%" 같은 템플릿이 "%" 한 글자만 남는데,
        # 그런 짧은 값을 페이지 전체에서 무차별로 지우면 "50% 할인" 같은 무관한 콘텐츠까지 훼손됨 -> 이제 무시해야 함
        body = "오늘의 특가: 50% 할인 안내"
        self.assertEqual(_strip_value(body, "%"), body)

    def test_strip_value_still_strips_normal_length_payload(self):
        body = "결과: 1 AND 1=1 -- 이(가) 반사됨"
        self.assertNotIn("1 AND 1=1 -- ", _strip_value(body, "1 AND 1=1 -- "))

    def test_boolean_sqli_missed_without_dynamic_markers(self):
        # 응답마다 바뀌는 랜덤 값(세션ID 등)이 페이지에서 큰 비중을 차지하면,
        # dynamic_markers로 제거하지 않는 한 true 응답조차 baseline과 안 비슷해 보여 게이트를 못 넘고 놓친다.
        mk = lambda tok: f"정상 목록 시작 {tok} 목록 끝 안내문입니다"
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1 AND 1=1", mk("TOKB9C8D7E6F5G4H3I2J1K0")),
                case("false_attack", "1 AND 1=2", "정상 목록 시작 TOKC5D4E3F2G1H0I9J8K7L6 완전히 다른 에러 페이지입니다"),
            ],
            baseline_body=mk("TOKA1B2C3D4E5F6G7H8I9J0"),
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_boolean_sqli_detected_with_dynamic_markers(self):
        # 위와 완전히 같은 응답들이지만, baseline 2회 probe로 미리 찾아둔 dynamic_markers를 함께 주면
        # 그 랜덤 값 자리를 비교에서 제외해서 진짜 boolean 분기를 정상적으로 탐지해야 한다.
        from scan.mutation.discovery import _extract_dynamic_markers

        mk = lambda tok: f"정상 목록 시작 {tok} 목록 끝 안내문입니다"
        markers = _extract_dynamic_markers(mk("TOKZ9Y8X7W6V5U4T3S2R1Q0"), mk("TOKQ0W1E2R3T4Y5U6I7O8P9"))
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1 AND 1=1", mk("TOKB9C8D7E6F5G4H3I2J1K0")),
                case("false_attack", "1 AND 1=2", "정상 목록 시작 TOKC5D4E3F2G1H0I9J8K7L6 완전히 다른 에러 페이지입니다"),
            ],
            baseline_body=mk("TOKA1B2C3D4E5F6G7H8I9J0"),
            dynamic_markers=markers,
        )
        self.assertEqual(len(analyze_family(item)), 1)

    def test_error_based_canary_reflected_is_high_confidence(self):
        # extractvalue 등으로 심어둔 고유 문자열이 에러 메시지에 그대로 반사되면 즉시 고신뢰로 확정
        canary = "IBDSa1b2c3d4"
        item = family(
            "sqli",
            "error_meta",
            [
                case("attack", "1'", "normal page"),
                case("attack", f"1' AND extractvalue(1,concat(0x7e,'{canary}')) -- ",
                     f"XPATH syntax error: '~{canary}'"),
            ],
        )
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "high")
        self.assertIn(canary, findings[0]["evidence"])

    def test_error_based_generic_fallback_page_is_not_false_positive(self):
        # instructions.php 실전 오탐 재현: doc 파라미터가 깨지면 canary와 무관하게
        # DB 에러 키워드(mysqli_)를 우연히 담은 "동일한" 도움말 페이지로 폴백함.
        # canary는 반사 안 되고, 모든 mutation 응답이 완전히 동일 -> 오탐 없어야 함.
        canary = "IBDSdeadbeef"
        fallback_page = "도움말: 에러 예시로 mysqli_sql_exception 같은 게 있습니다"
        item = family(
            "sqli",
            "error_meta",
            [
                case("attack", "PDF'", fallback_page),
                case("attack", "PDF;", fallback_page),
                case("attack", f"PDF' AND extractvalue(1,concat(0x7e,'{canary}')) -- ", fallback_page),
            ],
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_error_based_canary_not_trusted_when_whole_payload_is_echoed(self):
        # xss_r류 실전 오탐 재현: 페이지가 payload를 SQL 처리 없이 그대로 반사(echo)하면
        # canary도 그냥 딸려서 반사될 뿐 -> payload 원문이 그대로 남아있으면 신뢰하면 안 됨
        canary = "IBDS12345678"
        payload = f"ZAP' AND extractvalue(1,concat(0x7e,'{canary}')) -- "
        item = family(
            "sqli",
            "error_meta",
            [case("attack", payload, f"Hello {payload}")],
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_error_based_canary_not_trusted_when_payload_echoed_with_trimmed_whitespace(self):
        # 실전 오탐 재현: 저장형 필드(guestbook 등)가 payload를 저장할 때 끝 공백만 트리밍해서
        # 그대로 반사함 -> exact match로는 못 걸러지므로 strip() 비교로 잡아내야 함
        canary = "IBDS87654321"
        payload = f"ZAP' AND extractvalue(1,concat(0x7e,'{canary}')) -- "  # 끝에 공백 있음
        stored_body = f"Name: ZAP' AND extractvalue(1,concat(0x7e,'{canary}')) --<br />"  # 끝 공백 트리밍됨
        item = family(
            "sqli",
            "error_meta",
            [case("attack", payload, stored_body)],
        )
        self.assertEqual(len(analyze_family(item)), 0)

    def test_error_based_varying_responses_still_detected_without_canary(self):
        # canary가 안 통해도(WAF 등으로), payload마다 응답이 달라지는 진짜 DB 에러는 기존처럼 키워드로 탐지돼야 함
        item = family(
            "sqli",
            "error_meta",
            [
                case("attack", "1'", "You have an error in your SQL syntax near '1''"),
                case("attack", "1;", "You have an error in your SQL syntax near '1;'"),
            ],
        )
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["confidence"], "high")

    def test_union_sqli(self):
        body = "The used SELECT statements have a different number of columns"
        item = family("sqli", "union", [case("attack", "1' UNION SELECT NULL-- -", body)])
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["technique"], "union")

    def test_order_by_sqli(self):
        # order_by는 ORDER BY <큰수>로 컬럼 에러(Unknown column)를 유발 → error-based 판정기로 탐지
        body = "Unknown column '100' in 'order clause'"
        item = family("sqli", "order_by", [case("attack", "1 ORDER BY 100 -- ", body)])
        findings = analyze_family(item)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["technique"], "order_by")

    def test_time_no_false_positive_on_slow_page(self):
        # 원래 느린 페이지(baseline 3s)에서 공격도 3s면 baseline 차이 없음 → 미탐
        item = family(
            "sqli",
            "time_mysql",
            [case("attack", "1 AND SLEEP(3)-- ", "", elapsed=3.1)],
            baseline=case("baseline", None, "", elapsed=3.0),
        )
        self.assertEqual(len(analyze_family(item)), 0)

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
