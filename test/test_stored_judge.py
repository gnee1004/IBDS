from __future__ import annotations

import unittest

from analyzer import xss_detector as family_pipeline
from analyzer.xss.headless import HeadlessVerdict

PAYLOAD = "<script>alert(1)</script>"


class _FakeHeadless:  # 실제 브라우저 없이 navigate/render 발화 여부를 고정값으로 흉내
    def __init__(self, executed: bool):
        self.executed = executed
        self.render_calls: list[dict] = []  # render에 넘어온 url/headers 기록

    def confirm_via_navigate(self, url, cookies, method) -> HeadlessVerdict:
        return HeadlessVerdict(executed=self.executed, method="navigate", evidence="fake")

    def confirm_via_render(self, response_body, url=None, headers=None) -> HeadlessVerdict:
        self.render_calls.append({"url": url, "headers": headers})
        return HeadlessVerdict(executed=self.executed, method="render", evidence="fake")


def _family(sink_confirmed: bool = True) -> dict:
    return {
        "family_id": "t0_msg_PL-XSS-STORED", "target_id": "t0", "param": "msg",
        "attack_id": "PL-XSS-STORED", "technique": "stored",
        "sink_confirmed": sink_confirmed,
    }


def _case(payload: str, before: str, after: str) -> dict:
    return {
        "case": {"case_id": "c0", "payload": payload, "url": "http://x/list", "method": "GET"},
        "status": "ok",
        "before_revisit_body": before,
        "revisit_body": after,
        "revisit_url_used": "http://x/list",
        "effective_cookies": {},
    }


def _echo_case(response_body: str) -> dict:  # 재조회엔 payload 없음(저장 안 됨) + 등록 응답 본문만 다르게
    case_result = _case(PAYLOAD, "base", "base")
    case_result["case"]["url"] = "http://x/post"
    case_result.update(revisit_found=False, response_body=response_body,
                       response_headers={"content-type": "text/html"})
    return case_result


class StoredJudgeTests(unittest.TestCase):
    """§3.4 판정표 분기(에코백 포함)를 _judge_stored 단위로 검증."""

    def test_sink_unconfirmed_is_inconclusive(self) -> None:
        # Phase 1 sink 미확인 → inconclusive
        finding = family_pipeline._judge_stored(
            _family(sink_confirmed=False), _case(PAYLOAD, "", PAYLOAD), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "inconclusive")

    def test_payload_not_in_revisit_is_inconclusive(self) -> None:
        # Phase 2 재조회에 payload 끝내 안 뜸(N회 실패) → inconclusive
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, "base", "base only, no payload"), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "inconclusive")

    def test_residue_only_is_safe(self) -> None:
        # payload가 before/after 둘 다 있음(잔재) → diff 새 영역 없음 → safe
        body = "line1\n" + PAYLOAD
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, body, body), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "safe")

    def test_new_region_without_payload_is_safe(self) -> None:
        # payload는 잔재(before), 새 영역엔 noise만 → raw hit 없음 → safe
        before = "line1\n" + PAYLOAD
        after = before + "\n<p>just noise</p>"
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, before, after), _FakeHeadless(False))
        self.assertEqual(finding.final_status, "safe")

    def test_new_region_with_payload_not_executed_is_reflected_only(self) -> None:
        # 실제 저장 + raw hit + navigate 미발화 → reflected_only
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, "line1", "line1\n" + PAYLOAD), _FakeHeadless(executed=False))
        self.assertEqual(finding.final_status, "reflected_only")

    def test_new_region_with_payload_executed_is_vulnerable(self) -> None:
        # 실제 저장 + raw hit + navigate 발화 → vulnerable
        finding = family_pipeline._judge_stored(
            _family(), _case(PAYLOAD, "line1", "line1\n" + PAYLOAD), _FakeHeadless(executed=True))
        self.assertEqual(finding.final_status, "vulnerable")

    def test_echo_executed_is_reflected_only(self) -> None:
        # 저장 안 됨 + 등록 응답 에코 + render 발화 → reflected_only, 원래 URL·응답 헤더로 render
        headless = _FakeHeadless(executed=True)
        finding = family_pipeline._judge_stored(_family(), _echo_case("<p>" + PAYLOAD + "</p>"), headless)
        self.assertEqual(finding.final_status, "reflected_only")
        self.assertEqual(headless.render_calls,
                         [{"url": "http://x/post", "headers": {"content-type": "text/html"}}])

    def test_echo_not_executed_is_safe_with_evidence(self) -> None:
        # 저장 안 됨 + 등록 응답 에코 + render 미발화(CSP 등) → safe, headless 근거는 남김
        finding = family_pipeline._judge_stored(
            _family(), _echo_case("<p>" + PAYLOAD + "</p>"), _FakeHeadless(executed=False))
        self.assertEqual(finding.final_status, "safe")
        self.assertTrue(finding.headless_checked)

    def test_no_echo_is_safe_without_render(self) -> None:
        # 저장 안 됨 + 등록 응답에도 에코 없음 → render 없이 safe
        headless = _FakeHeadless(executed=True)
        finding = family_pipeline._judge_stored(_family(), _echo_case("<p>ok</p>"), headless)
        self.assertEqual(finding.final_status, "safe")
        self.assertEqual(headless.render_calls, [])


if __name__ == "__main__":
    unittest.main()
