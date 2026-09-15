import json
import socket
import sys
import tempfile
import threading
import time
import unittest
from contextlib import ExitStack
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import uvicorn
import web.app as webapp
from web.execution import ScanManager


# 임시 설정과 모의 파이프라인을 통한 실제 HTTP 검증
class ApiTests(unittest.TestCase):
    def test_settings_scan_stop_sse_history(self):
        gate = threading.Event()
        def pipeline(**kwargs):
            kwargs["on_progress"](total=4, completed=1, failed=1, stopped=False)
            gate.wait(3)
            kwargs["on_progress"](total=4, completed=1, failed=1, stopped=kwargs["should_stop"]())
        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            root = Path(temp)
            manager = ScanManager(root, pipeline)
            stack.enter_context(patch.object(webapp, "manager", manager))
            stack.enter_context(patch.object(webapp, "PROJECT_ROOT", root))
            stack.enter_context(patch("web.settings.TARGET_CONFIG", root / "target.json"))
            sock = socket.socket()
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
            server = uvicorn.Server(uvicorn.Config(webapp.app, log_level="error"))
            worker = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
            worker.start()
            try:
                deadline = time.monotonic() + 4
                while not server.started and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertTrue(server.started)

                def request(path, data=None):
                    body = json.dumps(data).encode() if data is not None else None
                    req = Request(f"http://127.0.0.1:{port}{path}", data=body,
                                  headers={"Content-Type": "application/json", "X-IBDS-Client": "local-ui"})
                    return urlopen(req, timeout=3)

                for page in ["/", "/run", "/scan"]:
                    with request(page) as response:
                        self.assertIn('lang="ko"', response.read().decode())
                with request("/api/config", {"target_url": "http://example.test", "revisit_urls": {"http://example.test/post": "http://example.test/view"}}) as response:
                    self.assertTrue(json.load(response)["saved"])
                with self.assertRaises(HTTPError) as invalid:
                    request("/api/config", {"target_url": "javascript:alert(1)"})
                self.assertEqual(invalid.exception.code, 422)
                with request("/api/scan/start", {}) as response:
                    run = json.load(response)["run"]
                with self.assertRaises(HTTPError) as duplicate:
                    request("/api/scan/start", {})
                self.assertEqual(duplicate.exception.code, 409)
                with self.assertRaises(HTTPError) as locked:
                    request("/api/config", {"target_url": "http://changed.test"})
                self.assertEqual(locked.exception.code, 409)
                with request("/api/scan/stream") as stream:
                    self.assertTrue(stream.readline().startswith(b"id:"))
                    state = json.loads(stream.readline().decode().removeprefix("data: "))
                    self.assertEqual(state["percent"], 25)
                    self.assertEqual(state["failed"], 1)
                with request("/api/scan/stop", {}) as response:
                    self.assertTrue(json.load(response)["stop_requested"])
                gate.set()
                manager.worker.join(3)
                with request("/api/scans") as response:
                    self.assertEqual(json.load(response)["runs"][0]["stage"], "stopped")
                with request("/api/results?run=" + run) as response:
                    self.assertEqual(json.load(response)["meta"]["stage"], "stopped")
            finally:
                gate.set()
                server.should_exit = True
                worker.join(5)
                sock.close()


if __name__ == "__main__":
    unittest.main()
