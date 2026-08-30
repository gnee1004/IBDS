from __future__ import annotations

import unittest

from scan.models import ScanPoint
from scan.mutation.discovery import (
    _extract_dynamic_markers,
    _take_tokens,
    detect_injection_context,
    measure_dynamic_markers,
    run_discovery,
)


class FakeZapCore:  # zap.core.send_request만 흉내내는 최소 stub
    def __init__(self, response_body: str):
        self._response_body = response_body

    def send_request(self, request, followredirects=False):
        return [{"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": self._response_body}]


class FakeZap:
    def __init__(self, response_body: str):
        self.core = FakeZapCore(response_body)


class FakeZapCoreSequence:  # 호출할 때마다 순서대로 다른 응답을 주는 stub (baseline 2회 요청 시뮬레이션용)
    def __init__(self, response_bodies: list[str]):
        self._bodies = list(response_bodies)

    def send_request(self, request, followredirects=False):
        body = self._bodies.pop(0)
        return [{"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": body}]


class FakeZapSequence:
    def __init__(self, response_bodies: list[str]):
        self.core = FakeZapCoreSequence(response_bodies)


def _point() -> ScanPoint:
    return ScanPoint(target_id="t0", name="q", location="query", original_value="x", value_type="string")


def _target() -> dict:
    return {"method": "GET", "url": "http://example.com/s?q=x", "base_url": "http://example.com/s"}


class RunDiscoveryTests(unittest.TestCase):
    def test_not_reflected_skips_specials_probe_and_returns_empty_set(self) -> None:
        zap = FakeZap(response_body="아무 반사도 없는 응답")

        result = run_discovery(_point(), _target(), zap)

        self.assertFalse(result.reflected)
        self.assertEqual(result.valid_specials, set())

    def test_reflected_with_all_specials_surviving_unescaped(self) -> None:
        # marker(ibdsreflect...)는 첫 요청, ibdsA...ibdsZ 구간은 두 번째(specials) 요청 응답을 흉내냄
        # FakeZap은 요청 1건만 흉내내므로, specials probe 응답을 그대로 반영한 body를 사용
        zap = FakeZap(response_body='echo: ibdsAibdsreflectt0qibdsA<>"\'=()/\\`ibdsZ')

        result = run_discovery(_point(), _target(), zap)

        self.assertTrue(result.reflected)
        self.assertEqual(result.valid_specials, {"<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"})

    def test_specials_partially_escaped_are_excluded(self) -> None:
        # < > 는 &lt; &gt;로 이스케이프되고 나머지만 그대로 반사된 상황을 흉내냄
        zap = FakeZap(response_body='ibdsAibdsreflectt0qibdsA&lt;&gt;"\'=()/\\`ibdsZ')

        result = run_discovery(_point(), _target(), zap)

        self.assertTrue(result.reflected)
        self.assertEqual(result.valid_specials, {'"', "'", "=", "(", ")", "/", "\\", "`"})


class DetectInjectionContextTests(unittest.TestCase):
    def test_marker_in_html_text_node(self) -> None:
        body = "<html><body><div>MARKER</div></body></html>"

        result = detect_injection_context(body, "MARKER")

        self.assertEqual(result, "inHTML")

    def test_marker_in_script_tag(self) -> None:
        body = "<html><body><script>var x = 'MARKER'</script></body></html>"

        result = detect_injection_context(body, "MARKER")

        self.assertEqual(result, "inScript")

    def test_marker_in_general_attribute(self) -> None:
        body = '<html><body><input value="MARKER"></body></html>'

        result = detect_injection_context(body, "MARKER")

        self.assertEqual(result, "inAttr")

    def test_marker_in_event_handler_attribute(self) -> None:
        body = '<html><body><div onclick="doSomething(\'MARKER\')"></div></body></html>'

        result = detect_injection_context(body, "MARKER")

        self.assertEqual(result, "inScript")

    def test_marker_in_url_attribute(self) -> None:
        body = '<html><body><a href="MARKER">link</a></body></html>'

        result = detect_injection_context(body, "MARKER")

        self.assertEqual(result, "inAttrUrl")

    def test_marker_in_safe_tag_returns_none(self) -> None:
        body = "<html><body><textarea>MARKER</textarea></body></html>"

        result = detect_injection_context(body, "MARKER")

        self.assertIsNone(result)

    def test_marker_not_present_returns_none(self) -> None:
        result = detect_injection_context("<html><body></body></html>", "MARKER")

        self.assertIsNone(result)


class ExtractDynamicMarkersTests(unittest.TestCase):
    def test_random_token_marker_generalizes_to_unseen_value(self) -> None:
        # 흔한 실제 케이스: CSRF 토큰처럼 완전히 랜덤한 값 -> 나중에 전혀 다른 값이 와도 지워져야 함
        body1 = "Welcome. token=aX92kLq. items: apple"
        body2 = "Welcome. token=Zp03mWe. items: apple"
        markers = _extract_dynamic_markers(body1, body2)

        from analyzer.sqli.judge import _strip_dynamic

        later = "Welcome. token=Q7fT1nZ. items: apple"  # 측정 때 못 본 완전히 새로운 값
        self.assertEqual(_strip_dynamic(later, markers), _strip_dynamic(body1, markers))

    def test_no_diff_returns_no_markers(self) -> None:
        body = "완전히 동일한 정적 페이지"
        self.assertEqual(_extract_dynamic_markers(body, body), [])

    def test_short_diff_near_body_edge_is_excluded(self) -> None:
        # 경계(prefix/suffix)를 채울 토큰이 모자라면 신뢰 불가로 판단해 마커에서 제외되어야 함
        markers = _extract_dynamic_markers("a", "b")
        self.assertEqual(markers, [])


class TakeTokensTests(unittest.TestCase):
    def test_collects_forward_until_min_length(self) -> None:
        tokens = ["ab", "cd", "ef", "gh"]
        result = _take_tokens(tokens, range(0, len(tokens)))
        self.assertEqual(result, "abcdef")  # len>=6 채울 때까지 순서대로 이어붙임

    def test_collects_backward_and_restores_order(self) -> None:
        tokens = ["ab", "cd", "ef", "gh"]
        result = _take_tokens(tokens, range(3, -1, -1))
        self.assertEqual(result, "cdefgh")  # 뒤에서부터 모으지만 결과는 원래 순서

    def test_not_enough_tokens_returns_none(self) -> None:
        tokens = ["a", "b"]
        self.assertIsNone(_take_tokens(tokens, range(0, len(tokens))))


class MeasureDynamicMarkersTests(unittest.TestCase):
    def test_sends_baseline_twice_and_extracts_markers(self) -> None:
        zap = FakeZapSequence([
            "Welcome. token=aX92kLq. items: apple",
            "Welcome. token=Zp03mWe. items: apple",
        ])

        markers = measure_dynamic_markers(_point(), _target(), zap)

        self.assertEqual(markers, [("token=", ". items")])


if __name__ == "__main__":
    unittest.main()
