from __future__ import annotations

import unittest

from scan.models import MutationCase
from scan.requester import requester


class FakeZapCore:  # zap.core.send_request만 흉내내는 최소 stub
    def __init__(self, response):
        self._response = response

    def send_request(self, request, followredirects=False):
        return self._response


class FakeZap:
    def __init__(self, response):
        self.core = FakeZapCore(response)


# 테스트용 MutationCase 생성
def _make_case(url="http://example.com/vuln?name=x", cookies=None) -> MutationCase:
    return MutationCase(
        case_id="t0_name_baseline",
        step="baseline",
        method="GET",
        url=url,
        headers={},
        cookies=cookies or {},
        body_type="query",
        body="",
    )


class SendEffectiveCookiesTests(unittest.TestCase):
    def setUp(self) -> None:
        requester.clear_cookie_store()

    def test_send_returns_effective_cookies_used_for_request(self) -> None:
        case = _make_case(cookies={"PHPSESSID": "abc123"})
        fake_zap = FakeZap([{"responseHeader": "HTTP/1.1 200 OK\r\n", "responseBody": "hi"}])

        result = requester.send(case, fake_zap)

        self.assertEqual(result["effective_cookies"], {"PHPSESSID": "abc123"})

    def test_send_reflects_set_cookie_update_in_later_effective_cookies(self) -> None:
        case = _make_case(cookies={"PHPSESSID": "abc123"})
        fake_zap = FakeZap([{
            "responseHeader": "HTTP/1.1 200 OK\r\nSet-Cookie: PHPSESSID=rotated\r\n",
            "responseBody": "hi",
        }])
        requester.send(case, fake_zap)  # 첫 요청으로 쿠키 갱신

        second_case = _make_case(cookies={})
        result = requester.send(second_case, fake_zap)

        self.assertEqual(result["effective_cookies"], {"PHPSESSID": "rotated"})


if __name__ == "__main__":
    unittest.main()
