from __future__ import annotations

import difflib
import secrets
import threading
import time
from dataclasses import dataclass

# 코어 모델 — refetch/probe_sink 공용. 가벼운 의존이라 단독으로 import.
try:
    from scan.models import MutationCase, SinkProbeResult
except Exception:  # pragma: no cover - 단독 테스트용
    MutationCase = SinkProbeResult = None

# probe_sink 전용 의존 (request_builder→discovery→bs4 체인). 없으면 probe_sink만 비활성.
# refetch는 이 둘을 안 쓰므로 여기서 실패해도 영향받지 않게 별도 try로 분리.
try:
    from scan.mutation.variant import build_mutation_case
    from scan.mutation.request_builder import resolve_revisit_url
except Exception:  # pragma: no cover - 단독 테스트용
    build_mutation_case = resolve_revisit_url = None

MARKER_PREFIX = "ibds"

REVISIT_MAX_RETRY = 3      # revisit_max_retry — 적응형 재시도 상한
REVISIT_AWAIT_MS = 500     # revisit_await_ms — 미검출 시 백오프 대기(ms)


# 회차 마커 발급
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


# 공용 헬퍼
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


# Phase 1 sink 확인 프로브
def probe_sink(sp, target: dict, marker: str, requester, zap):
    """param 값을 marker로 통째 교체해 POST(저장 유도) → revisit_url GET으로 반사 확인.
    미반사 시 base_url로 강등 1회 재시도. 결과는 SinkProbeResult."""
    param = sp.name

    # 1) param 값 통째 교체 후 POST — payload 경로 불변, 값만 marker로
    post_case = build_mutation_case(
        target=target,
        location=sp.location,
        param_name=param,
        original_value=sp.original_value,
        payload=marker,
        step="probe_post",
        case_id=f"probe_{sp.target_id}_{param}",
    )
    requester.send(post_case, zap)  # stored 유도. POST 응답 본문은 보지 않는다(에코 오판 방지)

    # 2) revisit_url 결정 후 GET → 반사 확인
    revisit_url = resolve_revisit_url(target)
    used_url = revisit_url
    confirmed = _reflect_at(target, revisit_url, marker, requester, zap,
                            case_id=f"probe_{sp.target_id}_{param}_revisit")

    # 3) 미반사 시 base_url로 강등 재시도 1회
    if not confirmed:
        base_url = target.get("base_url") or ""
        if base_url and base_url != revisit_url:
            if _reflect_at(target, base_url, marker, requester, zap,
                           case_id=f"probe_{sp.target_id}_{param}_revisit_base"):
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


# 재조회 + diff 게이트
@dataclass
class RefetchResult:
    body: str               # 재조회 GET 응답 본문 (= after 스냅샷)
    status: int | None      # 재조회 응답 상태코드
    attempts: int           # 실제 GET 시도 횟수 (1 ~ max_retry)
    found: bool             # payload가 응답에서 보였는지 (조기 종료 근거)


# 공격 POST 뒤 revisit_url을 다시 GET. payload 미검출 시에만 백오프로 재시도.
# 기본 1회, 안 보이면 백오프(await_ms×n) 대기 후 최대 max_retry회, 보이면 즉시 멈춤(적응형).
def refetch(revisit_url, cookies, payload, requester, zap,
            target=None, max_retry=REVISIT_MAX_RETRY, await_ms=REVISIT_AWAIT_MS) -> RefetchResult:
    headers = _get_headers_for_revisit(target or {})
    body, status, attempts = "", None, 0
    for attempts in range(1, max_retry + 1):
        if attempts > 1:
            time.sleep(await_ms * (attempts - 1) / 1000)
        get_case = MutationCase(
            case_id=f"refetch_n{attempts}",
            step="revisit_after",
            method="GET",
            url=revisit_url,
            headers=headers,
            cookies=dict(cookies or {}),
            body_type="query",
            body="",
        )
        resp = requester.send(get_case, zap)     # 세션 쿠키는 requester 내부 store가 유지
        body = resp.get("response_body") or ""
        status = resp.get("response_status")
        if payload and payload in body:          # 보이면 즉시 종료
            return RefetchResult(body=body, status=status, attempts=attempts, found=True)
    return RefetchResult(body=body, status=status, attempts=attempts, found=False)


# 공격 전(before) 대비 공격 후(after)에 새로 생긴/바뀐 영역만 추출.
# 과거 저장 잔재는 before에 이미 있어 diff가 빼버리므로 새 것으로 안 센다.
def diff_new_region(before_body, after_body):
    before_lines = (before_body or "").splitlines()
    after_lines = (after_body or "").splitlines()
    sm = difflib.SequenceMatcher(None, before_lines, after_lines, autojunk=False)
    new_parts = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):   # after에만 있는/바뀐 줄 = 이번 공격으로 생긴 것
            new_parts.extend(after_lines[j1:j2])
    return "\n".join(new_parts) if new_parts else None

