from __future__ import annotations

import unittest
from unittest.mock import patch

import orchestrator
from scan.models import ScanPoint


def _sp() -> ScanPoint:
    return ScanPoint(target_id="t0", name="mtxMessage", location="form",
                     original_value="x", value_type="string")


def _destructive_target() -> dict:
    return {
        "url": "http://dvwa/vulnerabilities/xss_s/",
        "method": "POST",
        "params": {"txtName": ["ZAP"], "mtxMessage": ["hi"], "btnClear": ["Clear Guestbook"]},
    }


def _benign_target() -> dict:
    return {
        "url": "http://dvwa/vulnerabilities/xss_s/",
        "method": "POST",
        "params": {"txtName": ["ZAP"], "mtxMessage": ["hi"], "btnSign": ["Sign Guestbook"]},
    }


class RouteScanPointDestructiveGuardTests(unittest.TestCase):
    # 파괴적 액션(Clear 등) 타겟 → family 를 하나도 만들지 않고 통째 드롭
    def test_destructive_target_produces_no_families(self):
        self.assertEqual(orchestrator._route_scan_point(_sp(), _destructive_target(), zap=None), [])

    # 가드는 진입 즉시 동작 — discovery/SQLi 측정 등 하류 호출로 내려가지 않음
    def test_destructive_target_short_circuits_before_downstream(self):
        with patch.object(orchestrator, "run_discovery") as m_disc, \
             patch.object(orchestrator, "measure_dynamic_markers") as m_noise:
            orchestrator._route_scan_point(_sp(), _destructive_target(), zap=None)
            m_disc.assert_not_called()
            m_noise.assert_not_called()

    # 정상 폼(Sign 등) → 가드에 걸리지 않고 하류 생성 경로로 진행
    def test_benign_target_is_not_dropped_by_guard(self):
        with patch.object(orchestrator, "run_discovery", return_value=None), \
             patch.object(orchestrator, "generate_xss_families", return_value=[]), \
             patch.object(orchestrator, "generate_stored_xss_families", return_value=[]), \
             patch.object(orchestrator, "measure_dynamic_markers", return_value=([], 1.0)), \
             patch.object(orchestrator, "generate_sqli_families", return_value=["SENTINEL"]):
            result = orchestrator._route_scan_point(_sp(), _benign_target(), zap=None)
        self.assertIn("SENTINEL", result)


if __name__ == "__main__":
    unittest.main()
