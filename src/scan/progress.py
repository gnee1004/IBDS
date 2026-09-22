from dataclasses import dataclass
from typing import Callable


# 실행 진행률과 협조적 중단 상태
@dataclass
class PipelineProgress:
    callback: Callable | None = None
    stop_requested: Callable | None = None
    total: int = 0
    completed: int = 0
    failed: int = 0
    stopped: bool = False

    # 현재 집계 전달
    def publish(self):
        if self.callback:
            self.callback(total=self.total, completed=self.completed, failed=self.failed,
                          stopped=self.stopped)

    # 안전한 경계에서 중단 신호 확인
    def should_stop(self):
        self.stopped = self.stopped or bool(self.stop_requested and self.stop_requested())
        return self.stopped
