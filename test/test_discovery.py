from __future__ import annotations

import unittest

from scan.models import ScanPoint
from scan.mutation.discovery import run_discovery


class FakeZapCore:  # zap.core.send_request만 흉내내는 최소 stub
    def __init__(self, response_body: str):
        self._response_body = response_body

    def send_request(self, request, followredirects=False):
        return [{"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": self._response_body}]


class FakeZap:
    def __init__(self, response_body: str):
        self.core = FakeZapCore(response_body)


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


if __name__ == "__main__":
    unittest.main()
