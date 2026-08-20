from __future__ import annotations

import unittest

from analyzer.scan import analyze_family


def _ok(response_body: str) -> dict:
    return {"status": "ok", "response_status": 200, "response_headers": {},
            "response_body": response_body, "elapsed": 0.01}


def _attack(payload: str, response_body: str, cid: str) -> dict:
    r = _ok(response_body)
    r["case"] = {"case_id": cid, "step": "attack", "method": "POST",
                 "url": "http://x/board", "body_type": "form", "payload": payload}
    return r


def _verify(payload: str, response_body: str, attack_cid: str) -> dict:
    r = _ok(response_body)
    r["case"] = {"case_id": f"{attack_cid}_verify", "step": "stored_verify", "method": "GET",
                 "url": "http://x/board", "body_type": "query", "payload": payload}
    return r


def _stored_family(mutations: list[dict], baseline_body: str = "board") -> dict:
    baseline = _ok(baseline_body)
    baseline["case"] = {"case_id": "t0_comment_PL-XSS-STORED_baseline", "step": "baseline",
                        "method": "POST", "url": "http://x/board", "body_type": "form"}
    return {
        "family_id": "t0_comment_PL-XSS-STORED", "target_id": "t0", "param": "comment",
        "attack_id": "PL-XSS-STORED", "vuln_type": "xss", "technique": "stored",
        "baseline": baseline, "mutations": mutations,
    }


_P = "<script>alert(1)</script>"


class AnalyzeStoredXssTests(unittest.TestCase):
    def test_confirmed_when_payload_survives_in_requery(self) -> None:
        cid = "t0_comment_PL-XSS-STORED_a0"
        family = _stored_family([
            _attack(_P, "thanks, saved", cid),   # POST 응답엔 payload 없음
            _verify(_P, f"<li>{_P}</li>", cid),  # 재조회 목록엔 저장분 노출
        ])

        findings = analyze_family(family)

        self.assertEqual(len(findings), 1)
        self.assertIn("재조회", findings[0]["evidence"])
        self.assertEqual(findings[0]["method"], "POST")  # 주입 지점을 가리킴

    def test_reflected_only_in_post_is_not_confirmed(self) -> None:
        cid = "t0_comment_PL-XSS-STORED_a0"
        family = _stored_family([
            _attack(_P, f"echo: {_P}", cid),     # POST 응답엔 반사되지만
            _verify(_P, "clean board", cid),     # 재조회엔 없음 → 저장 미확인
        ])

        self.assertEqual(analyze_family(family), [])

    def test_missing_verify_case_yields_no_finding(self) -> None:
        cid = "t0_comment_PL-XSS-STORED_a0"
        family = _stored_family([_attack(_P, f"echo: {_P}", cid)])  # 재조회 case 없음

        self.assertEqual(analyze_family(family), [])

    def test_requery_reflection_present_in_baseline_is_suppressed(self) -> None:
        cid = "t0_comment_PL-XSS-STORED_a0"
        # baseline 재조회 페이지에 이미 payload 형태가 있으면(정적 콘텐츠) 저장분으로 오인하지 않음
        family = _stored_family([
            _attack(_P, "saved", cid),
            _verify(_P, f"<li>{_P}</li>", cid),
        ], baseline_body=f"<li>{_P}</li>")

        self.assertEqual(analyze_family(family), [])


if __name__ == "__main__":
    unittest.main()
