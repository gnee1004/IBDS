import json
import sys
import tempfile
import threading
import unittest
from contextlib import ExitStack
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import orchestrator
from scan.models import ScanPoint, MutationCase, RequestFamily, CaseResult, FamilyResult
from utilities.file_utils import save_json, append_jsonl
from web.models import ConfigPayload
from web.reports import build_report
from web.execution import ScanManager
from web.runs import list_runs, run_metadata, resolve_run_dir


# 외부 요청 없는 검사 가족 구성
def make_family(rule="AR-SQLI-1", vuln="sqli", technique="boolean"):
    fid = f"t0_q__occ0_{rule}"
    base = MutationCase(fid + "_baseline", "baseline", "GET", "http://example.test/?q=1", {}, {}, "query", "")
    mutations = [MutationCase(fid + f"_a{i}", "true_attack", "GET", "http://example.test/?q=payload", {}, {}, "query", "", payload=str(i)) for i in range(2)]
    return RequestFamily(fid, "t0", "q", rule, vuln, technique, base, mutations)


# 외부 통신을 대체한 진행률과 중단 검증
class PipelineTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        save_json(str(self.directory / "scan_targets.json"), [{"url": "http://example.test/?q=1"}])
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(orchestrator, "run_collection", return_value=(str(self.directory), str(self.directory / "scan_targets.json"))))
        self.stack.enter_context(patch.object(orchestrator, "_apply_revisit_overrides"))
        self.stack.enter_context(patch.object(orchestrator.requester, "get_zap_client"))
        self.stack.enter_context(patch.object(orchestrator, "HeadlessSession"))
        self.points = [ScanPoint("t0", "q", "query", "1", "number"), ScanPoint("t0", "r", "query", "2", "number")]
        self.stack.enter_context(patch.object(orchestrator, "build_scan_points", return_value=self.points))
        self.sent = {"response_status": 200, "response_headers": {}, "response_body": "ok", "elapsed": .1, "effective_cookies": {}}
        self.updates = []

    def execute(self, stop=None):
        return orchestrator.run_pipeline(on_progress=lambda **state: self.updates.append(state), should_stop=stop)

    def test_route_failure_and_empty_point_complete(self):
        with patch.object(orchestrator, "_route_scan_point", side_effect=[ValueError("route failed"), []]):
            self.execute()
        self.assertEqual(self.updates[-1]["completed"], 2)
        self.assertEqual(self.updates[-1]["total"], 2)
        report = build_report(self.directory)
        self.assertEqual(report["error_count"], 1)
        self.assertEqual(report["errors"][0]["url"], "http://example.test/?q=1")

    def test_shared_baseline_counted_once(self):
        families = [make_family(), make_family("AR-SQLI-2")]
        def send(case, zap):
            if case.step == "baseline":
                raise ValueError("baseline failed")
            return self.sent
        with patch.object(orchestrator, "_route_scan_point", side_effect=[families, []]), patch.object(orchestrator.requester, "send", side_effect=send):
            self.execute()
        self.assertEqual(self.updates[-1]["failed"], 1)
        self.assertEqual(build_report(self.directory)["error_count"], 1)

    def test_stop_saves_partial_sqli_without_judging(self):
        event = threading.Event()
        def send(case, zap):
            if case.step != "baseline":
                event.set()
            return self.sent
        with patch.object(orchestrator, "_route_scan_point", return_value=[make_family()]), patch.object(orchestrator.requester, "send", side_effect=send), patch.object(orchestrator, "analyze_family") as judge:
            self.execute(event.is_set)
        judge.assert_not_called()
        saved = json.loads((self.directory / "request_results.jsonl").read_text())
        self.assertEqual(len(saved["mutations"]), 1)
        self.assertTrue(self.updates[-1]["stopped"])
        self.assertEqual(self.updates[-1]["completed"], 0)
        self.assertEqual(build_report(self.directory)["counts"], {"inconclusive": 1})

    def test_stop_during_revisit_waits_for_after(self):
        event = threading.Event()
        family = make_family("PL-XSS-STORED", "xss", "stored")
        family.sink_confirmed, family.revisit_url = True, "http://example.test/view"
        def before(*args):
            event.set()
            return None, None
        with patch.object(orchestrator, "_route_scan_point", return_value=[family]), patch.object(orchestrator.requester, "send", return_value=self.sent) as send, patch.object(orchestrator, "_revisit_before", side_effect=before), patch.object(orchestrator, "_revisit_after_fields", return_value={}) as after, patch.object(orchestrator.family_pipeline, "judge_case", side_effect=ValueError("judge failed")):
            self.execute(event.is_set)
        after.assert_called_once()
        self.assertEqual(send.call_count, 2)
        self.assertTrue(self.updates[-1]["stopped"])
        self.assertEqual(build_report(self.directory)["errors"][0]["stage"], "judge")

    def test_stop_after_collection_sends_nothing(self):
        with patch.object(orchestrator.requester, "send") as send:
            self.execute(lambda: True)
        send.assert_not_called()
        self.assertTrue(self.updates[-1]["stopped"])

    def test_zero_points(self):
        with patch.object(orchestrator, "build_scan_points", return_value=[]):
            self.execute()
        self.assertEqual(self.updates[-1]["total"], 0)
        self.assertFalse(self.updates[-1]["stopped"])


# 보고서의 판정 보존과 실패 구분 검증
class ReportTests(unittest.TestCase):
    def test_failed_xss_is_not_safe_and_filters_are_dynamic(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp)
            family = make_family("PL-XSS-1", "xss", "new_technique")
            result = FamilyResult(family.family_id, "xss", family.technique, "t0", "q", family.attack_id,
                                  CaseResult(family.baseline, "ok"), [CaseResult(family.mutations[0], "error", error="send failed")])
            append_jsonl(str(path / "request_results.jsonl"), asdict(result))
            for status, case in [("safe", family.mutations[0].case_id), ("future_status", "other")]:
                append_jsonl(str(path / "findings.jsonl"), {"family_id": family.family_id, "target_id": "t0", "param": "q", "case_id": case, "final_status": status})
            with (path / "findings.jsonl").open("a") as stream:
                stream.write('{"partial":')
            report = build_report(path)
            self.assertEqual(report["counts"], {"future_status": 1})
            self.assertEqual(report["techniques"], ["new_technique"])
            self.assertEqual(report["error_count"], 1)

    def test_unknown_run_does_not_escape_results(self):
        with tempfile.TemporaryDirectory() as temp:
            self.assertIsNone(resolve_run_dir(temp, "../../config"))
            self.assertEqual(list_runs(temp), [])


# 실행 수명주기와 입력 검증
class ManagerTests(unittest.TestCase):
    def test_fatal_error_persisted(self):
        with tempfile.TemporaryDirectory() as temp:
            manager = ScanManager(Path(temp), pipeline=MagicMock(side_effect=ValueError("ZAP unavailable")))
            with patch("web.execution.read_config", return_value={"target_url": "http://example.test"}):
                manager.start()
            manager.worker.join(3)
            meta = run_metadata(manager.directory)
            self.assertEqual(meta["stage"], "failed")
            self.assertEqual(meta["error"], "ZAP unavailable")
            self.assertFalse(meta["running"])

    def test_stop_and_duplicate_start(self):
        entered = threading.Event()
        release = threading.Event()
        def pipeline(**kwargs):
            entered.set()
            release.wait(2)
            kwargs["on_progress"](total=3, completed=1, failed=2, stopped=kwargs["should_stop"]())
        with tempfile.TemporaryDirectory() as temp:
            manager = ScanManager(Path(temp), pipeline=pipeline)
            with patch("web.execution.read_config", return_value={"target_url": "http://example.test"}):
                manager.start()
                entered.wait(2)
                with self.assertRaises(RuntimeError):
                    manager.start()
                manager.stop()
                release.set()
                manager.worker.join(3)
            self.assertEqual(manager.snapshot()["stage"], "stopped")
            self.assertAlmostEqual(manager.snapshot()["percent"], 100 / 3)
            self.assertEqual(list_runs(Path(temp))[0]["stage"], "stopped")

    def test_config_validation(self):
        for value in ["javascript:alert(1)", "http://", "http://host:bad", "http://host/a b"]:
            with self.assertRaises(ValueError):
                ConfigPayload(target_url=value)
        self.assertEqual(ConfigPayload(target_url=" http://localhost:8080 ").target_url, "http://localhost:8080")


if __name__ == "__main__":
    unittest.main()
