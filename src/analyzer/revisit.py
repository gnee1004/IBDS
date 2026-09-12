from __future__ import annotations
import difflib
import secrets
import threading
import time
from dataclasses import dataclass

try:
    from scan.models import MutationCase, SinkProbeResult
except Exception:
    MutationCase = SinkProbeResult = None

# probe_sink 전용 의존(bs4 체인). 실패해도 refetch/diff는 동작하도록 별도 분리.
try:
    from scan.mutation.variant import build_mutation_case
    from scan.mutation.request_builder import resolve_revisit_url
except Exception:
    build_mutation_case = resolve_revisit_url = None

MARKER_PREFIX = "ibds"
REVISIT_MAX_RETRY = 3      # revisit_max_retry
REVISIT_AWAIT_MS = 500     # revisit_await_ms


class RunMarkerFactory:

    def __init__(self, run_hex: str | None = None):
        self.run_hex: str = run_hex or secrets.token_hex(2)
        self.prefix: str = f"{MARKER_PREFIX}{self.run_hex}"
        self._lock = threading.Lock()
        self._param_index: dict[str, int] = {}
        self._counters: dict[str, int] = {}

    def issue(self, param: str) -> str:
        with self._lock:
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


def _get_headers_for_revisit(target: dict) -> dict:
    headers = dict(target.get("headers") or {})
    return {k: v for k, v in headers.items()
            if k.lower() not in ("content-type", "content-length")}


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
    resp = requester.send(get_case, zap)
    return marker in (resp.get("response_body") or "")


def probe_sink(sp, target: dict, marker: str, requester, zap):
    param = sp.name
    post_case = build_mutation_case(
        target=target,
        location=sp.location,
        param_name=param,
        original_value=sp.original_value,
        payload=marker,
        step="probe_post",
        case_id=f"probe_{sp.target_id}_{sp.tag}",
        value_index=sp.value_index,
    )
    requester.send(post_case, zap)  # POST 응답 본문은 보지 않음(에코 오판 방지)

    revisit_url = resolve_revisit_url(target)
    used_url = revisit_url
    confirmed = _reflect_at(target, revisit_url, marker, requester, zap,
                            case_id=f"probe_{sp.target_id}_{sp.tag}_revisit")

    if not confirmed:
        base_url = target.get("base_url") or ""
        if base_url and base_url != revisit_url:
            if _reflect_at(target, base_url, marker, requester, zap,
                           case_id=f"probe_{sp.target_id}_{sp.tag}_revisit_base"):
                confirmed = True
                used_url = base_url

    return SinkProbeResult(
        param=param,
        revisit_url=used_url,
        sink_confirmed=confirmed,
        inconclusive=not confirmed,
        probe_marker=marker,
    )


@dataclass
class RefetchResult:
    body: str               # 재조회 GET 응답 본문 (after 스냅샷)
    status: int | None      # 재조회 응답 상태코드
    attempts: int           # 총 GET 시도 횟수 (첫 GET 포함)
    found: bool             # payload가 응답에서 보였는지


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
        resp = requester.send(get_case, zap)
        body = resp.get("response_body") or ""
        status = resp.get("response_status")
        if payload and payload in body:
            return RefetchResult(body=body, status=status, attempts=attempts, found=True)
    return RefetchResult(body=body, status=status, attempts=attempts, found=False)


def diff_new_region(before_body, after_body):
    before_lines = (before_body or "").splitlines()
    after_lines = (after_body or "").splitlines()
    sm = difflib.SequenceMatcher(None, before_lines, after_lines, autojunk=False)
    new_parts = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            new_parts.extend(after_lines[j1:j2])
    return "\n".join(new_parts) if new_parts else None
