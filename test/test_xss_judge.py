"""
judge_xss 단위테스트 — raw 판정(문자열·컨텍스트) 로직만 검증.
stored·속성탈출·JS컨텍스트를 컨텍스트별로 나눠 확인한다.
저장 여부(diff 게이트)·실제 발화(headless)는 judge_xss 범위 밖이라 여기서 다루지 않음.
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from analyzer.xss.judge import judge_xss, XssVerdict


class AttributeEscapeTests(unittest.TestCase):
    """속성 탈출 — payload가 속성값을 벗어나 그대로 반사되는 경우 (원문 반사 -> high)."""

    def test_double_quote_attribute_escape_is_high(self) -> None:
        payload = '"><script>alert(1)</script>'
        body = f'<input type="text" value="{payload}">'

        verdict = judge_xss(body, payload)

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")

    def test_single_quote_attribute_escape_is_high(self) -> None:
        payload = "'><svg onload=alert(1)>"
        body = f"<input type='text' value='{payload}'>"

        verdict = judge_xss(body, payload)

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")

    def test_escape_into_new_event_handler_attribute_is_high(self) -> None:
        payload = '" onmouseover="alert(1)'  # 태그를 안 닫고 새 핸들러 속성만 주입
        body = f'<input type="text" value="{payload}">'

        verdict = judge_xss(body, payload)

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")


class JsContextTests(unittest.TestCase):
    """JS 컨텍스트 — payload 원문은 변형됐지만 alert(1)이 실행 가능한 자리에 반사 (-> high)."""

    def test_alert_inside_script_string_is_high(self) -> None:
        payload = "<svg onload=alert(1)>"  # 필터로 태그가 제거돼 원문은 응답에 없음
        body = "<script>var msg = 'alert(1)';</script>"

        verdict = judge_xss(body, payload)

        self.assertNotIn(payload, body)  # 원문 반사가 아님을 명시
        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")

    def test_alert_breaking_out_of_js_string_is_high(self) -> None:
        payload = "raw-payload-not-echoed"
        body = "<script>var q = '';alert(1);//';</script>"

        verdict = judge_xss(body, payload)

        self.assertNotIn(payload, body)
        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")

    def test_alert_in_inline_event_handler_is_high(self) -> None:
        payload = "raw-payload-not-echoed"
        body = '<div onclick="alert(1)">click</div>'

        verdict = judge_xss(body, payload)

        self.assertNotIn(payload, body)
        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")


class ReflectedButNotExecutableTests(unittest.TestCase):
    """alert(1)은 반사됐지만 실행 컨텍스트(script/핸들러)가 아님 -> medium (수동 확인 필요)."""

    def test_alert_in_plain_text_is_medium(self) -> None:
        body = "<p>검색 결과: alert(1) 는 없습니다</p>"

        verdict = judge_xss(body, "raw-payload-not-echoed")

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "medium")

    def test_alert_in_html_comment_is_medium(self) -> None:
        body = "<div><!-- debug: alert(1) --></div>"

        verdict = judge_xss(body, "raw-payload-not-echoed")

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "medium")


class StoredTests(unittest.TestCase):
    """stored — 저장 후 재조회한 본문(revisit body)을 judge_xss에 넣었을 때 반사를 잡는지.

    실제 저장 여부(diff 게이트)·실제 발화(headless)는 judge_xss 범위 밖 — 여기선 반사 판정만 본다.
    """

    def test_stored_payload_verbatim_in_revisit_body_is_high(self) -> None:
        payload = "<script>alert(1)</script>"
        revisit_body = f"<ul class='comments'><li>{payload}</li></ul>"

        verdict = judge_xss(revisit_body, payload)

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")

    def test_stored_alert_rendered_into_script_context_is_high(self) -> None:
        payload = "<img src=x onerror=alert(1)>"  # 저장 시 태그가 벗겨지고 값만 script로 렌더됨
        revisit_body = "<script>var lastComment = 'alert(1)';</script>"

        verdict = judge_xss(revisit_body, payload)

        self.assertNotIn(payload, revisit_body)
        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "high")

    def test_stored_residue_without_alert_is_safe(self) -> None:
        # 과거 잔재 텍스트만 남고 실행 흔적(payload·alert)이 없으면 safe
        payload = "<script>alert(1)</script>"
        revisit_body = "<ul class='comments'><li>지난 방명록 글입니다</li></ul>"

        verdict = judge_xss(revisit_body, payload)

        self.assertFalse(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "")


class SafeAndEdgeTests(unittest.TestCase):
    def test_no_reflection_is_safe(self) -> None:
        verdict = judge_xss("<p>안녕하세요</p>", "<script>alert(1)</script>")

        self.assertFalse(verdict.vulnerable)
        self.assertEqual(verdict.confidence, "")

    def test_empty_body_is_safe(self) -> None:
        verdict = judge_xss("", "<script>alert(1)</script>")

        self.assertIsInstance(verdict, XssVerdict)
        self.assertFalse(verdict.vulnerable)


if __name__ == "__main__":
    unittest.main()
