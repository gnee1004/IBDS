from __future__ import annotations

import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import orchestrator
from scan.models import ScanPoint, SinkProbeResult


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


# Phase 1 sink probe 라우팅 — _route_scan_point 안에서 probe_sink 결과를 어떻게 다루는지
class RouteScanPointProbeTests(unittest.TestCase):
    def setUp(self):
        fd, self.findings_path = tempfile.mkstemp(suffix=".jsonl")
        os.close(fd)

    def tearDown(self):
        if os.path.exists(self.findings_path):
            os.remove(self.findings_path)

    # findings.jsonl 을 파싱해 레코드 리스트로 반환
    def _read_findings(self) -> list[dict]:
        with open(self.findings_path, encoding="utf-8") as f:
            return [json.loads(line) for line in f if line.strip()]

    # 공통 배선 — 하류 생성기는 전부 patch, probe_sink 거동만 파라미터로 주입
    def _route(self, *, probe_return=None, probe_side_effect=None, stored=None, location="form"):
        sp = ScanPoint(target_id="t0", name="mtxMessage", location=location,
                       original_value="x", value_type="string")
        with patch.object(orchestrator, "run_discovery", return_value=None), \
             patch.object(orchestrator, "generate_xss_families", return_value=["REFLECTED"]), \
             patch.object(orchestrator, "generate_stored_xss_families",
                          return_value=list(stored or [])) as m_stored, \
             patch.object(orchestrator, "measure_dynamic_markers", return_value=([], 1.0)), \
             patch.object(orchestrator, "generate_sqli_families", return_value=["SQLI"]), \
             patch.object(orchestrator, "probe_sink") as m_probe:
            if probe_side_effect is not None:
                m_probe.side_effect = probe_side_effect
            else:
                m_probe.return_value = probe_return
            result = orchestrator._route_scan_point(
                sp, _benign_target(), zap=None,
                marker_factory=lambda name: "ibdsabcd_p00_n0001",
                findings_path=self.findings_path,
            )
        return result, m_probe, m_stored

    # sink 확인됨 → 그 param 의 stored family 에만 프로브 결과 부착, reflected/SQLi 는 그대로
    def test_probe_confirmed_attaches_fields_and_keeps_all_families(self):
        fam = SimpleNamespace(sink_confirmed=None, revisit_url=None, probe_marker=None, sink_note=None)
        probe = SinkProbeResult(param="mtxMessage", revisit_url="http://dvwa/gb/",
                                sink_confirmed=True, inconclusive=False,
                                probe_marker="ibdsabcd_p00_n0001")
        result, m_probe, _ = self._route(probe_return=probe, stored=[fam])
        m_probe.assert_called_once()
        self.assertIn(fam, result)
        self.assertIs(fam.sink_confirmed, True)
        self.assertEqual(fam.revisit_url, "http://dvwa/gb/")
        self.assertEqual(fam.probe_marker, "ibdsabcd_p00_n0001")
        self.assertIn("REFLECTED", result)
        self.assertIn("SQLI", result)
        self.assertEqual(self._read_findings(), [])

    # 마커 미반사(inconclusive) → stored family 생성 안 함, findings 에 inconclusive 레코드 1건
    def test_probe_inconclusive_emits_finding_without_stored_family(self):
        fam = SimpleNamespace(sink_confirmed=None, revisit_url=None, probe_marker=None, sink_note=None)
        probe = SinkProbeResult(param="mtxMessage", revisit_url="http://dvwa/gb/",
                                sink_confirmed=False, inconclusive=True,
                                probe_marker="ibdsabcd_p00_n0001")
        result, _, _ = self._route(probe_return=probe, stored=[fam])
        self.assertNotIn(fam, result)
        self.assertIn("REFLECTED", result)
        self.assertIn("SQLI", result)
        findings = self._read_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "inconclusive")
        self.assertEqual(findings[0]["param"], "mtxMessage")
        self.assertIn("마커 재조회 미반사", findings[0]["sink_note"])

    # probe_sink 가 예외로 터짐 → 그 param 의 stored 만 포기, reflected/SQLi 는 진행 + findings 에 사유 기록
    def test_probe_exception_isolated_and_logged(self):
        result, _, _ = self._route(probe_side_effect=RuntimeError("boom"), stored=[SimpleNamespace()])
        self.assertIn("REFLECTED", result)
        self.assertIn("SQLI", result)
        findings = self._read_findings()
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "inconclusive")
        self.assertIn("프로브 오류: boom", findings[0]["sink_note"])

    # form 이 아닌 파라미터 → probe_sink 호출 안 함, 기존 else 분기(generate_stored_xss_families)로
    def test_probe_skipped_for_non_form_param(self):
        _, m_probe, m_stored = self._route(location="query")
        m_probe.assert_not_called()
        m_stored.assert_called_once()

    # marker_factory 가 없으면(구 호출부) 프로브 경로 자체를 타지 않음
    def test_probe_skipped_without_marker_factory(self):
        with patch.object(orchestrator, "run_discovery", return_value=None), \
             patch.object(orchestrator, "generate_xss_families", return_value=[]), \
             patch.object(orchestrator, "generate_stored_xss_families", return_value=[]), \
             patch.object(orchestrator, "measure_dynamic_markers", return_value=([], 1.0)), \
             patch.object(orchestrator, "generate_sqli_families", return_value=[]), \
             patch.object(orchestrator, "probe_sink") as m_probe:
            orchestrator._route_scan_point(_sp(), _benign_target(), zap=None)
        m_probe.assert_not_called()


if __name__ == "__main__":
    unittest.main()
