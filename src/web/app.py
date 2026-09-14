"""로컬 웹 서비스 — 설정 화면 + 스캔 실행/리포트 화면.
orchestrator.run_pipeline()을 그대로 호출하는 창문 역할만 함. 스캔 로직 자체는 무수정.
실행: python src/web/app.py (플래그 없음, CLAUDE.md #1)
"""
from __future__ import annotations
import json
import os
import sys
import threading
import time

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_ROOT = os.path.dirname(_THIS_DIR)          # src/
_PROJECT_ROOT = os.path.dirname(_SRC_ROOT)      # 리포 루트
if _SRC_ROOT not in sys.path:
    sys.path.insert(0, _SRC_ROOT)

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from orchestrator import run_pipeline
from utilities.file_utils import load_json, save_json
from web.reports import build_report, latest_out_dir, list_runs, resolve_run_dir

_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")
_STATIC_DIR = os.path.join(_THIS_DIR, "static")

app = FastAPI()
app.mount("/static", StaticFiles(directory=_STATIC_DIR), name="static")

# 한 번에 스캔 하나만 (로컬 1인용 도구라 동시 스캔 관리 불필요)
_lock = threading.Lock()
_state = {"running": False, "results_path": None, "findings_path": None, "error": None, "log": []}


# run_pipeline()의 print() 출력을 터미널에 그대로 내보내면서, 동시에 상태의 로그 목록에도 쌓음 (스캔 실행 화면 표시용)
class _LogTee:
    def __init__(self, original, sink: list[str]):
        self._original = original
        self._sink = sink
        self._buf = ""

    def write(self, text: str) -> None:
        self._original.write(text)
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line:
                with _lock:
                    self._sink.append(line)

    def flush(self) -> None:
        self._original.flush()


def _run_scan_bg() -> None:
    def on_paths_ready(results_path: str, findings_path: str) -> None:
        with _lock:
            _state["results_path"] = results_path
            _state["findings_path"] = findings_path

    original_stdout = sys.stdout
    sys.stdout = _LogTee(original_stdout, _state["log"])
    try:
        run_pipeline(on_paths_ready=on_paths_ready)
    except Exception as e:
        with _lock:
            _state["error"] = str(e)
    finally:
        sys.stdout = original_stdout
        with _lock:
            _state["running"] = False


@app.get("/")
def index_page():
    return FileResponse(os.path.join(_STATIC_DIR, "index.html"))


@app.get("/run")
def run_page():
    return FileResponse(os.path.join(_STATIC_DIR, "run.html"))


@app.get("/scan")
def scan_page():
    return FileResponse(os.path.join(_STATIC_DIR, "scan.html"))


# 설정 조회 - 타겟 URL + 재방문 주소(revisit_urls) override 목록
@app.get("/api/config")
def get_config():
    cfg = load_json(_TARGET_CONFIG, default={})
    return {"target_url": cfg.get("target_url", ""), "revisit_urls": cfg.get("revisit_urls") or {}}


class ConfigPayload(BaseModel):
    target_url: str
    revisit_urls: dict[str, str] = {}


# 설정 저장 - config/target_config.json 자동 생성/갱신
@app.post("/api/config")
def save_config(payload: ConfigPayload):
    save_json(_TARGET_CONFIG, {
        "target_url": payload.target_url.strip(),
        "revisit_urls": {k.strip(): v.strip() for k, v in payload.revisit_urls.items() if k.strip() and v.strip()},
    })
    return {"saved": True}


# 스캔 시작 - 백그라운드 스레드에서 run_pipeline() 실행, 진행 상황은 /api/scan/stream이 담당
@app.post("/api/scan/start")
def start_scan():
    with _lock:
        if _state["running"]:
            raise HTTPException(409, "이미 스캔이 진행 중입니다.")
        _state.update(running=True, results_path=None, findings_path=None, error=None, log=[])
    threading.Thread(target=_run_scan_bg, daemon=True).start()
    return {"started": True}


# 진행 상황 스트리밍(SSE) - findings.jsonl 줄 수 + 새로 찍힌 로그 줄을 1초마다 내보냄
@app.get("/api/scan/stream")
def scan_stream():
    def gen():
        log_idx = 0
        while True:
            with _lock:
                running = _state["running"]
                findings_path = _state["findings_path"]
                error = _state["error"]
                new_logs = _state["log"][log_idx:]
                log_idx = len(_state["log"])

            findings_count = 0
            if findings_path and os.path.exists(findings_path):
                with open(findings_path, encoding="utf-8") as f:
                    findings_count = sum(1 for _ in f)

            stage = "collecting" if running and not findings_path else ("scanning" if running else "done")
            payload = {"running": running, "stage": stage, "findings_count": findings_count, "logs": new_logs}
            if findings_path:
                payload["run"] = os.path.basename(os.path.dirname(findings_path))  # 완료 후 리포트로 이동할 때 씀
            if not running and error:
                payload["error"] = error
            yield f"data: {json.dumps(payload, ensure_ascii=False)}\n\n"

            if not running:
                break
            time.sleep(1)

    return StreamingResponse(gen(), media_type="text/event-stream")


# 과거 실행 기록 목록 (최신순) - 리포트 화면의 실행 기록 선택용
@app.get("/api/scans")
def get_scans():
    return {"runs": list_runs(_PROJECT_ROOT)}


# 스캔 결과를 URL·파라미터 단위로 묶어서 반환. run 지정 없으면 가장 최근 실행
@app.get("/api/results")
def get_results(run: str | None = None):
    out_dir = resolve_run_dir(_PROJECT_ROOT, run) if run else latest_out_dir(_PROJECT_ROOT)
    if not out_dir:
        return {"groups": [], "run": None}
    return {"groups": build_report(out_dir), "run": os.path.basename(out_dir)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=1080)
