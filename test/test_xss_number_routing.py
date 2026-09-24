from __future__ import annotations

import unittest
from unittest import mock

from scan.models import ScanPoint
from scan.match.rules_builder import get_rules
from scan.match.matcher import match_and_render


def _point(value_type: str, location: str = "query", name: str = "page") -> ScanPoint:
    return ScanPoint(
        target_id="t0", name=name, location=location,
        original_value="1", value_type=value_type,
    )


class MatcherValueTypeTests(unittest.TestCase):
    """게이트② — 매처(allowed_value_types)가 number 파라미터에도 XSS 룰을 적용하는지."""

    def test_xss_rules_allow_number_value_type(self) -> None:
        xss_rules = [r for r in get_rules() if r.vuln_type == "xss"]
        self.assertTrue(xss_rules)  # XSS 룰이 존재해야 의미 있는 검증
        for r in xss_rules:
            self.assertIn("number", r.allowed_value_types,
                          f"{r.attack_id}: number가 허용 타입에 없음")

    def test_number_point_matches_xss_rules(self) -> None:
        # value_type=number 파라미터가 XSS 룰에 하나라도 매칭돼야 함
        xss_rules = [r for r in get_rules() if r.vuln_type == "xss"]
        self.assertTrue(match_and_render(_point("number"), xss_rules),
                        "number 파라미터가 XSS 룰에 하나도 매칭 안 됨")

    def test_string_point_still_matches_xss_rules(self) -> None:  # 회귀 방지
        xss_rules = [r for r in get_rules() if r.vuln_type == "xss"]
        self.assertTrue(match_and_render(_point("string"), xss_rules))

    def test_sqli_still_allows_both_types(self) -> None:  # 회귀 방지 — SQLi는 원래 둘 다
        sqli_rules = [r for r in get_rules() if r.vuln_type == "sqli"]
        self.assertTrue(sqli_rules)
        for r in sqli_rules:
            self.assertIn("string", r.allowed_value_types)
            self.assertIn("number", r.allowed_value_types)


class RouteScanPointValueTypeTests(unittest.TestCase):
    """게이트① — orchestrator 라우팅이 number 파라미터도 XSS 경로에 태우는지."""

    def _run(self, value_type: str):
        import orchestrator
        target = {"params": {}}  # destructive action 없음
        with mock.patch.object(orchestrator, "run_discovery", return_value=mock.sentinel.disc) as m_disc, \
             mock.patch.object(orchestrator, "generate_xss_families", return_value=[]) as m_xss, \
             mock.patch.object(orchestrator, "measure_dynamic_markers", return_value=(None, None)), \
             mock.patch.object(orchestrator, "generate_sqli_families", return_value=[]), \
             mock.patch.object(orchestrator, "generate_stored_xss_families", return_value=[]):
            orchestrator._route_scan_point(_point(value_type), target, zap=None)
        return m_disc, m_xss

    def test_number_param_is_routed_to_xss(self) -> None:
        m_disc, m_xss = self._run("number")
        self.assertTrue(m_disc.called, "number 파라미터가 XSS discovery에 안 태워짐")
        self.assertTrue(m_xss.called, "number 파라미터가 XSS family 생성에 안 감")

    def test_string_param_still_routed_to_xss(self) -> None:  # 회귀 방지
        m_disc, m_xss = self._run("string")
        self.assertTrue(m_disc.called)
        self.assertTrue(m_xss.called)


if __name__ == "__main__":
    unittest.main()
