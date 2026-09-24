from __future__ import annotations

import unittest

from scan.models import ScanPoint, DiscoveryResult
from scan.mutation.request_builder import generate_xss_families

# DOM 계열은 URL fragment(#뒤)로 주입되어 서버로 전송되지 않으므로,
# 서버 반사(reflected)·서버 반사 특수문자(valid_specials)와 독립이어야 한다. (#2)

_TARGET = {"url": "http://demo.local/search?q=abc", "method": "GET"}


def _point() -> ScanPoint:
    return ScanPoint(
        target_id="t0", name="q", location="query",
        original_value="abc", value_type="string",
    )


def _techniques(families) -> set[str]:
    return {f.technique for f in families}


class DomReflectionDecoupleTests(unittest.TestCase):

    def test_dom_generated_without_server_reflection(self) -> None:
        # 서버가 marker를 반사하지 않아도(순수 DOM) DOM family는 생성돼야 한다.
        disc = DiscoveryResult(reflected=False, valid_specials=set(), injection_context=None)
        families = generate_xss_families(_point(), _TARGET, disc)
        self.assertIn("dom", _techniques(families),
                      "reflected=False에서 DOM family가 생성되지 않음 (순수 DOM XSS 미탐)")

    def test_dom_payloads_not_filtered_by_server_specials(self) -> None:
        # 서버가 <,> 를 이스케이프해 valid_specials에서 빠져도 DOM payload는 살아남아야 한다.
        disc = DiscoveryResult(reflected=True, valid_specials=set(), injection_context=None)
        families = generate_xss_families(_point(), _TARGET, disc)
        dom = [f for f in families if f.technique == "dom"]
        self.assertTrue(dom, "DOM family가 없음")
        # DOM 룰의 payload 3개가 valid_specials 필터로 잘리지 않고 모두 남아야 한다.
        self.assertEqual(len(dom[0].mutations), 3,
                         "서버 특수문자 필터가 DOM payload를 잘라냄")

    def test_reflected_family_still_gated_when_not_reflected(self) -> None:  # 회귀 방지
        # reflected 계열(비-DOM)은 여전히 reflected=False면 생성되지 않아야 한다.
        disc = DiscoveryResult(reflected=False, valid_specials=set(), injection_context=None)
        families = generate_xss_families(_point(), _TARGET, disc)
        non_dom = _techniques(families) - {"dom"}
        self.assertFalse(non_dom,
                         f"reflected=False인데 비-DOM XSS family가 생성됨: {non_dom}")


if __name__ == "__main__":
    unittest.main()
