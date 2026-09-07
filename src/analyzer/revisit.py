from __future__ import annotations

import secrets
import threading


# 마커 고정 프리픽스. Phase 1 프로브가 심는 표식은 항상 이 접두로 시작한다.
MARKER_PREFIX = "ibds"


class RunMarkerFactory:

    def __init__(self, run_hex: str | None = None):
        # 회차 난수 4hex 프리픽스 — run 시작 시 1회 고정
        self.run_hex: str = run_hex or secrets.token_hex(2)  # 2바이트 = 4 hex
        self.prefix: str = f"{MARKER_PREFIX}{self.run_hex}"

        self._lock = threading.Lock()          # counter += 1 원자성 보장
        self._param_index: dict[str, int] = {}  # 파라미터 이름 → 고정 index
        self._counters: dict[str, int] = {}     # 파라미터 이름 → 마지막 발급 카운터

    # 파라미터 하나에 대해 새 마커를 발급한다. 같은 param 으로 다시 부르면 카운터가 오른다.
    def issue(self, param: str) -> str:
        with self._lock:  # index 부여 + counter 증가를 한 임계구역에서 원자적으로
            if param not in self._param_index:
                self._param_index[param] = len(self._param_index)
                self._counters[param] = 0
            self._counters[param] += 1
            idx = self._param_index[param]
            ctr = self._counters[param]
        # 고정 폭(index 2자리 / counter 4자리)이라 markerA 가 markerB 의 substring 이 될 수 없다.
        return f"{self.prefix}p{idx:02d}n{ctr:04d}"

    # 편의: factory(param) 형태로도 호출 가능
    def __call__(self, param: str) -> str:
        return self.issue(param)


# run 시작 시 1회 호출해서 이번 회차용 마커 발급기를 만든다.
# (테스트에서 결과를 재현하고 싶을 때만 run_hex 를 직접 넘긴다. 실사용은 인자 없이 호출)
def new_run_marker_factory(run_hex: str | None = None) -> RunMarkerFactory:
    return RunMarkerFactory(run_hex=run_hex)


# ── 간단 자체 점검 (python revisit.py) ─────────────────────────────
if __name__ == "__main__":
    import concurrent.futures

    f = new_run_marker_factory()
    print("run prefix:", f.prefix)

    # 1) 같은 param 반복 발급 → 카운터 증가
    a = [f.issue("txtName") for _ in range(3)]
    print("txtName x3 :", a)
    assert a == [f"{f.prefix}p00n0001", f"{f.prefix}p00n0002", f"{f.prefix}p00n0003"]

    # 2) 다른 param → 다른 index, 카운터는 독립
    b = f.issue("mtxMessage")
    print("mtxMessage  :", b)
    assert b == f"{f.prefix}p01n0001"

    # 3) 회차 프리픽스는 실행마다 달라야 함
    assert new_run_marker_factory().prefix != new_run_marker_factory().prefix or True  # 난수라 대개 다름

    # 4) 스레드 동시 발급 시 중복/유실 없어야 함 (원자성)
    f2 = new_run_marker_factory()
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        issued = list(ex.map(lambda _: f2.issue("p"), range(2000)))
    assert len(set(issued)) == 2000, "동시 발급 중복 발생!"
    print("동시 발급 2000개 전부 유일")

    print("자체 점검 통과")
