import re
import sys
import threading
from collections import deque
from dataclasses import asdict
from datetime import datetime

from web.models import ConfigPayload, RunState
from web.runs import run_dirs, run_metadata, save_run
from web.settings import PROJECT_ROOT, read_config


# 스캔 스레드 출력만 수집하는 터미널 복제
class LogTee:
    def __init__(self, original, manager):
        self.original = original
        self.manager = manager
        self.thread_id = threading.get_ident()
        self.buffer = ""

    def write(self, value):
        self.original.write(value)
        if threading.get_ident() == self.thread_id:
            self.buffer += value
            parts = re.split(r"[\r\n]", self.buffer)
            self.buffer = parts.pop()
            for line in parts:
                if line:
                    self.manager.log(line)
        return len(value)

    def flush(self):
        self.original.flush()

    def finish(self):
        if self.buffer:
            self.manager.log(self.buffer)
            self.buffer = ""

    def __getattr__(self, key):
        return getattr(self.original, key)


# 단일 스캔 실행과 상태 스트림 관리
class ScanManager:
    def __init__(self, root=PROJECT_ROOT, pipeline=None):
        self.root = root
        self.pipeline = pipeline
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.state = RunState()
        self.logs = deque(maxlen=2000)
        self.sequence = 0
        self.directory = None
        self.worker = None

    # 이전 서버 종료로 남은 실행 상태 복구
    def recover(self):
        for directory in run_dirs(self.root):
            meta = run_metadata(directory)
            if meta.get("running"):
                meta.update(running=False, stage="interrupted", error="서버 종료로 실행이 끊겼습니다.")
                save_run(directory, meta)

    # 상태의 영속 저장
    def persist(self):
        if self.directory:
            save_run(self.directory, asdict(self.state))

    # 새 실행 생성과 중복 실행 차단
    def start(self):
        with self.lock:
            if self.state.running:
                raise RuntimeError("이미 스캔이 진행 중입니다.")
            ConfigPayload(**read_config())
            now = datetime.now()
            self.directory = self.root / "results" / now.strftime("collection_%Y%m%d_%H%M%S_%f")
            self.state = RunState(run=self.directory.name, stage="collecting", running=True,
                                  started_at=now.isoformat(timespec="seconds"))
            self.logs.clear()
            self.sequence = 0
            self.stop_event.clear()
            self.persist()
            self.worker = threading.Thread(target=self.execute, daemon=True)
            self.worker.start()
            return self.snapshot()

    # 협조적 중단 요청 접수
    def stop(self):
        with self.lock:
            if self.state.running:
                self.stop_event.set()
                self.state.stop_requested = True
                self.persist()
            return self.snapshot()

    # 순번과 심각도를 포함한 로그 저장
    def log(self, line):
        with self.lock:
            self.sequence += 1
            level = "error" if "[ERROR]" in line else "warning" if "[WARN]" in line or "실패" in line else "info"
            self.logs.append({"id": self.sequence, "level": level, "text": line})

    # 진행 콜백의 상태 반영
    def progress(self, **values):
        with self.lock:
            for key, value in values.items():
                setattr(self.state, key, value)
            self.state.stage = "scanning"
            self.persist()

    # 재접속 가능한 실행 상태 스냅샷
    def snapshot(self, after=0):
        with self.lock:
            data = asdict(self.state)
            data["logs"] = [line for line in self.logs if line["id"] > after]
            data["cursor"] = self.sequence
            data["percent"] = (100 * self.state.completed / self.state.total
                               if self.state.total else 100 if self.state.stage == "completed" else None)
            return data

    # 파이프라인 실행과 종료 상태 확정
    def execute(self):
        stdout, stderr = sys.stdout, sys.stderr
        out_tee, err_tee = LogTee(stdout, self), LogTee(stderr, self)
        sys.stdout, sys.stderr = out_tee, err_tee
        try:
            pipeline = self.pipeline
            if pipeline is None:
                from orchestrator import run_pipeline
                pipeline = run_pipeline
            pipeline(on_progress=self.progress, should_stop=self.stop_event.is_set,
                     output_dir=str(self.directory))
            with self.lock:
                self.state.stage = "stopped" if self.state.stopped else "completed"
        except Exception as exc:
            self.log(f"[ERROR] 파이프라인 중단: {exc}")
            with self.lock:
                self.state.stage = "failed"
                self.state.error = str(exc) or type(exc).__name__
        finally:
            out_tee.finish()
            err_tee.finish()
            sys.stdout, sys.stderr = stdout, stderr
            with self.lock:
                self.state.running = False
                self.state.finished_at = datetime.now().isoformat(timespec="seconds")
                self.persist()
