from __future__ import annotations
import secrets
import threading
from scan.models import MutationCase, SinkProbeResult
from scan.mutation.variant import build_mutation_case
from scan.mutation.request_builder import resolve_revisit_url

MARKER_PREFIX = "ibds"


class RunMarkerFactory:

    def __init__(self, run_hex: str | None = None):
        self.run_hex: str = run_hex or secrets.token_hex(2)  # 2바이트 = 4 hex
        self.prefix: str = f"{MARKER_PREFIX}{self.run_hex}"
        self._lock = threading.Lock()
        self._param_index: dict[str, int] = {}
        self._counters: dict[str, int] = {}

    def issue(self, param: str) -> str:
        with self._lock:  # index 부여 + counter 증가를 한 임계구역에서 원자적으로
            if param not in self._param_index:
                self._param_index[param] = len(self._param_index)
                self._counters[param] = 0
            self._counters[param] += 1
            idx = self._param_index[param]
            ctr = self._counters[param]
        return f"{self.prefix}p{idx:02d}n{ctr:04d}"

    def __call__(self, param: str) -> str:
        return self.issue(param)


def new_run_marker_factory(run_hex: str | None = None) -> RunMarkerFactory:
    return RunMarkerFactory(run_hex=run_hex)


# target 헤더에서 GET 재조회에 부적절한 바디 관련 헤더 제거 (POST에서 넘어온 잔재 방지)
def _get_headers_for_revisit(target: dict) -> dict:
    headers = dict(target.get("headers") or {})
    return {k: v for k, v in headers.items()
            if k.lower() not in ("content-type", "content-length")}


# revisit_url로 GET을 날려 marker가 응답 본문에 반사됐는지 확인
def _reflect_at(target: dict, url: str, marker: str, requester, zap, case_id: str) -> bool:
    get_case = MutationCase(
        case_id=case_id,
        step="probe_revisit",
        method="GET",
        url=url,
        headers=_get_headers_for_revisit(target),
        cookies=dict(target.get("cookies") or {}),
        body_type="query",
        body="",
    )
    # 세션 쿠키는 requester 내부 origin별 저장소가 POST→GET 사이 자동 유지
    resp = requester.send(get_case, zap)
    return marker in (resp.get("response_body") or "")


def probe_sink(sp, target: dict, marker: str, requester, zap):
    param = sp.name

    # 1) param 값 통째 교체 후 POST — payload 경로 불변, 값만 marker로
    post_case = build_mutation_case(
        target=target,
        location=sp.location,
        param_name=param,
        original_value=sp.original_value,
        payload=marker,
        step="probe_post",
        case_id=f"probe_{sp.target_id}_{sp.tag}",   # ← param → sp.tag (occurrence까지 구분)
        value_index=sp.value_index,                 # ← 추가: 해당 occurrence만 교체
    )
    requester.send(post_case, zap)  # stored 유도. POST 응답 본문은 보지 않는다(에코 오판 방지)

    # 2) revisit_url 결정 후 GET → 반사 확인
    revisit_url = resolve_revisit_url(target)
    used_url = revisit_url
    confirmed = _reflect_at(target, revisit_url, marker, requester, zap,
                            case_id=f"probe_{sp.target_id}_{sp.tag}_revisit")

    # 3) 미반사 시 base_url로 강등 재시도 1회
    if not confirmed:
        base_url = target.get("base_url") or ""
        if base_url and base_url != revisit_url:
            if _reflect_at(target, base_url, marker, requester, zap,
                           case_id=f"probe_{sp.target_id}_{sp.tag}_revisit_base"):
                confirmed = True
                used_url = base_url

    # 4) 결과 반환 — 확인되면 sink_confirmed, 아니면 inconclusive(safe로 안 뭉갬)
    return SinkProbeResult(
        param=param,
        revisit_url=used_url,
        sink_confirmed=confirmed,
        inconclusive=not confirmed,
        probe_marker=marker,   # WBS: 재현·디버깅용 사용 마커
    )