from __future__ import annotations

import unittest

from scan.models import ScanPoint
from scan.match.rules_builder import get_rules
from scan.match.matcher import match_and_render
from scan.match.exec_token import exec_token, inject_exec_token
from analyzer.xss.headless import HeadlessSession

# #7 — 공격 payload에 고유 실행 토큰을 심고, headless는 그 토큰이 담긴 dialog만
# 실행으로 인정해 "기존 페이지 dialog"와 구분한다.


def _point() -> ScanPoint:
    return ScanPoint(target_id="t0", name="q", location="query",
                     original_value="abc", value_type="string")


class InjectTokenUnitTests(unittest.TestCase):
    def test_paren_call_argument_replaced_syntax_preserved(self) -> None:
        self.assertEqual(inject_exec_token("alert(1)", "999"), "alert(999)")
        self.assertEqual(inject_exec_token("alert()", "999"), "alert(999)")
        self.assertEqual(inject_exec_token("alert(document.domain)", "999"), "alert(999)")
        self.assertEqual(inject_exec_token("prompt()", "999"), "prompt(999)")

    def test_template_literal_call_keeps_backtick(self) -> None:
        # 백틱 호출은 paren 차단 우회 목적 → 문법(백틱) 보존, 인자만 토큰으로
        self.assertEqual(inject_exec_token("alert`1`", "999"), "alert`999`")

    def test_quoted_context_payload_stays_valid(self) -> None:
        self.assertEqual(inject_exec_token("';alert(1);//", "999"), "';alert(999);//")
        self.assertEqual(inject_exec_token("'-alert(1)-'", "999"), "'-alert(999)-'")


class RenderTokenTests(unittest.TestCase):
    def test_rendered_xss_payloads_carry_exec_token(self) -> None:
        tok = exec_token()
        xss = [r for r in get_rules() if r.vuln_type == "xss"]
        found = False
        for m in match_and_render(_point(), xss):
            for payloads in m.rendered_payloads.values():
                for p in payloads:
                    if any(c in p for c in ("alert", "prompt", "confirm")):
                        found = True
                        self.assertIn(tok, p, f"실행 토큰 미포함: {p!r}")
                        self.assertNotIn("alert(1)", p, f"고정 alert(1) 잔존: {p!r}")
        self.assertTrue(found, "dialog 유발 payload를 하나도 못 찾음")


class HeadlessTokenTests(unittest.TestCase):
    def test_page_native_dialog_not_counted(self) -> None:
        tok = exec_token()
        sess = HeadlessSession()
        try:
            native = sess.confirm_via_render("<svg onload=alert('PAGEOWN')>", exec_token=tok)
            self.assertFalse(native.executed, "페이지 자체 alert가 실행으로 오탐됨")
            ours = sess.confirm_via_render(f"<svg onload=alert({tok})>", exec_token=tok)
            self.assertTrue(ours.executed, "우리 토큰 alert가 실행으로 인정 안 됨")
        finally:
            sess.close()


if __name__ == "__main__":
    unittest.main()
