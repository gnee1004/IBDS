from __future__ import annotations
import difflib
import secrets
import threading
import time
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

from scan.mutation.variant import build_mutation_case

try:
    from scan.models import MutationCase, SinkProbeResult
except Exception:
    MutationCase = SinkProbeResult = None

MARKER_PREFIX = "ibds"
REVISIT_MAX_RETRY = 3      # revisit_max_retry
REVISIT_AWAIT_MS = 500     # revisit_await_ms


# 이번 스캔 실행 전체에서 고유 마커 문자열을 발급
class RunMarkerFactory:

    def __init__(self, run_hex: str | None = None):
        self.run_hex: str = run_hex or secrets.token_hex(2)
        self.prefix: str = f"{MARKER_PREFIX}{self.run_hex}"
        self._lock = threading.Lock()
        self._param_index: dict[str, int] = {}
        self._counters: dict[str, int] = {}

    # param 하나에 대해 새 마커 문자열 발급
    def issue(self, param: str) -> str:
        with self._lock:
            if param not in self._param_index:
                self._param_index[param] = len(self._param_index)
                self._counters[param] = 0
            self._counters[param] += 1      # 호출할 때마다 그 param의 카운터 1 증가
            idx = self._param_index[param]
            ctr = self._counters[param]
        return f"{self.prefix}p{idx:02d}n{ctr:04d}"

    # issue()와 동일 동작. marker_factory(param) 형태로 바로 호출하기 위한 래퍼
    def __call__(self, param: str) -> str:
        return self.issue(param)


# RunMarkerFactory 생성 진입점. 스캔 시작 시 1회 호출
def new_run_marker_factory(run_hex: str | None = None) -> RunMarkerFactory:
    return RunMarkerFactory(run_hex=run_hex)


# 재방문 목적지가 원본 target과 같은 host인지 검사 (af.md #8 — 외부 호스트로 인증정보 유출 방지)
def is_same_host(original_url: str, candidate_url: str) -> bool:
    return urlparse(original_url or "").netloc == urlparse(candidate_url or "").netloc


# 재조회 GET용 헤더 구성
def _get_headers_for_revisit(target: dict) -> dict:
    headers = dict(target.get("headers") or {})
    return {k: v for k, v in headers.items()
            if k.lower() not in ("content-type", "content-length")} # 원본 요청 헤더에서 POST 전용 헤더(Content-Type/Length) 제거


# 마커 반사 프로브가 어디서 마커 반사를 할지 결정
# 우선순위: 유저가 명시한 revisit_url → 동일 호스트 referer → base_url(그 파라미터가 나온곳) → target_url
def resolve_revisit_url(target: dict) -> str:
    if explicit := target.get("revisit_url"):
        return explicit
    
    target_host = urlparse(target.get("url", "")).netloc
    referer = target.get("headers", {}).get("referer", "")

    if referer and urlparse(referer).netloc == target_host:
        return referer
    
    return target.get("base_url") or target.get("url", "")


_MAX_EXTRA_SINKS = 3  # sweep으로 찾은 추가 출력 위치 상한 (위치마다 stored family 세트가 하나씩 늘어남)
STORED_BATCH_SIZE = 20  # 마커를 몇 지점씩 묶어 주입하고 훑을지 - 뒤 저장 요청이 앞 마커를 덮어쓰거나 목록 밖으로 밀어내는 것 방지
_MAX_SWEEP_PAGES = 500  # 묶음마다 훑을 페이지 상한
_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
               ".woff", ".woff2", ".ttf", ".swf", ".map", ".pdf")
_LOGIN_HINTS = ("login", "signin", "sign-in", "logon")


# 재조회 응답이 유효한지 (403, 500 등은 마커가 없어도 미발견으로 볼 수 없음)
def _is_valid_status(status) -> bool:
    return isinstance(status, int) and 200 <= status < 400


# 응답이 로그인 화면으로 이동했는지 - 가입 후 로그인 페이지 이동 같은 정상 흐름도 걸리므로 이것만으로 세션 만료로 보지 않음
def _is_login_redirect(status, location_url: str | None) -> bool:
    if not (isinstance(status, int) and 300 <= status < 400 and location_url):
        return False
    return any(h in urlparse(location_url).path.lower() for h in _LOGIN_HINTS)


# 재조회 GET 한 번 - (응답 본문, 응답 상태 코드, 로그인 화면으로 튕겼는지) 반환
def _fetch(target: dict, url: str, requester, zap, case_id: str) -> tuple[str, int | None, bool]:
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
    status = resp.get("response_status")
    location = (resp.get("response_headers") or {}).get("location")
    bounced = _is_login_redirect(status, urljoin(url, location) if location else None)
    return resp.get("response_body") or "", status, bounced


# 조회 응답을 마커 미발견 근거로 쓸 수 없으면 사유, 쓸 수 있으면 None
# 2xx·3xx가 아니거나 로그인 화면으로 튕긴 응답은 세션이 끊겼을 수 있어 미발견 근거가 못 됨
def _invalid_note(url: str, status, bounced: bool) -> str | None:
    if not _is_valid_status(status):
        return f"{url} ({status})"
    if bounced:
        return f"{url} ({status} 로그인 화면으로 이동)"
    return None


# 마커 반사 확인 - (마커 반사 여부, 조회가 무효면 사유 문자열 아니면 None)
def _reflect_at(target: dict, url: str, marker: str, requester, zap, case_id: str) -> tuple[bool, str | None]:
    body, status, bounced = _fetch(target, url, requester, zap, case_id)
    return marker in body, _invalid_note(url, status, bounced)  # 본문 자체는 버림


# 1단계 마커 주입 - marker로 param 값 교체해 POST 후 revisit_url(실패 시 base_url) GET으로 바로 확인
# 다른 페이지 출력은 묶음이 끝난 뒤 sweep_markers가 함께 찾는다
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
    sent = requester.send(post_case, zap)  # POST 응답 본문은 보지 않음(에코 오판 방지)
    post_status = sent.get("response_status")

    # POST 응답 Location으로 동적 revisit_url 결정 (write.php처럼 매번 새 id가 생기는 경우 대응)
    # 범위 밖(외부 호스트) Location은 따르지 않고 기존 정책(override/referer/base_url)으로 폴백 (af.md #8·#12)
    # 유저가 명시한 revisit_url이 최우선 — PRG(저장 후 자기 자신으로 이동)처럼 Location이 출력 위치가 아닌 경우 대응
    # 주소에 마커가 든 Location(/search?q=마커)은 보이는 마커가 저장이 아니라 반사라서 쓰지 않는다
    location = (sent.get("response_headers") or {}).get("location")
    location_url = urljoin(post_case.url, location) if location else None
    if target.get("revisit_url"):
        revisit_url, source = target["revisit_url"], "explicit"
    elif location_url and is_same_host(target.get("url", ""), location_url) and marker not in location_url:
        revisit_url, source = location_url, "location"
    else:
        revisit_url, source = resolve_revisit_url(target), "default"
    used_url = revisit_url
    checked_urls = [revisit_url]
    invalid_revisits: list[str] = []
    confirmed, invalid = _reflect_at(target, revisit_url, marker, requester, zap,
                                     case_id=f"probe_{sp.target_id}_{sp.tag}_revisit")
    if not confirmed and invalid:
        invalid_revisits.append(invalid)

    if not confirmed:
        base_url = target.get("base_url") or ""
        if base_url and base_url != revisit_url:
            checked_urls.append(base_url)
            found, invalid = _reflect_at(target, base_url, marker, requester, zap,
                                         case_id=f"probe_{sp.target_id}_{sp.tag}_revisit_base")
            if found:
                confirmed = True
                used_url, source = base_url, "default"
            elif invalid:
                invalid_revisits.append(invalid)

    return SinkProbeResult(
        param=param,
        revisit_url=used_url,
        sink_confirmed=confirmed,
        inconclusive=not confirmed,
        probe_marker=marker,
        revisit_source=source,
        checked_urls=checked_urls,
        invalid_revisits=invalid_revisits,
        post_status=post_status,
        login_redirect=_is_login_redirect(post_status, location_url),
    )


# 2단계 묶음 공동 조회 - 묶음으로 주입한 마커를 수집 페이지에서 한꺼번에 찾아 지점별 출력 위치 연결표를 만든다
# 페이지마다 GET 한 번만 보내 지점마다 전체를 훑는 것보다 요청을 줄인다 (ZAP Persistent XSS Spider 방식)
# probes: (지점 target, probe_sink 결과) 목록. 결과 객체에 출력 위치와 조회 기록을 채운다
# pages: (주소, 그 주소를 수집한 target) 목록 - 조회할 때 그 페이지를 수집한 요청의 헤더·쿠키를 쓴다
def sweep_markers(probes: list, pages: list[tuple[str, dict]], requester, zap, batch_id: int) -> None:
    markers = [r.probe_marker for _, r in probes]
    targets = [(url, page_target) for url, page_target in pages
               if not urlparse(url).path.lower().endswith(_STATIC_EXT)
               and not any(m in url for m in markers)]  # 주소에 마커가 들면 반사라서 저장 근거가 못 됨
    limit_hit = len(targets) > _MAX_SWEEP_PAGES
    checked, failed = 0, []
    for idx, (url, page_target) in enumerate(targets[:_MAX_SWEEP_PAGES]):
        try:
            body, status, bounced = _fetch(page_target, url, requester, zap, case_id=f"probe_sweep_b{batch_id}_{idx}")
        except Exception as e:
            failed.append(f"{url} ({e})")
            continue
        if invalid := _invalid_note(url, status, bounced):
            failed.append(invalid)
            continue
        checked += 1
        for target, r in probes:
            if r.probe_marker not in body or url == r.revisit_url or not is_same_host(target.get("url", ""), url):
                continue
            if not r.sink_confirmed:  # 주입 직후 확인에서 못 찾은 지점 - 다른 페이지 출력
                r.sink_confirmed, r.inconclusive = True, False
                r.revisit_url, r.revisit_source = url, "sweep"
            elif url not in r.extra_sinks and len(r.extra_sinks) < _MAX_EXTRA_SINKS:
                r.extra_sinks.append(url)
    for _, r in probes:
        r.batch_id, r.checked_count, r.failed_urls, r.sweep_limit_hit = batch_id, checked, list(failed), limit_hit


# 3단계 저장형 상태 결정 - 마커를 찾았으면 저장 요청이 오류였어도 출력 위치 확인 우선 (오류 응답 전에 저장됐을 수 있음)
# 저장 요청이나 주입 직후 재조회가 비정상이면 확인 실패, 둘 다 정상이면 수집 범위 내 미발견 (저장 없음이 아님)
# 저장 요청의 로그인 화면 이동은 주입 직후 재조회도 비정상일 때만 세션 만료 근거로 쓴다 (가입 후 로그인 이동 같은 정상 흐름 구분)
# 훑기 중 일부 페이지 조회 실패는 그 지점만 확인 실패로 돌리지 않고 탐색 불완전으로만 남긴다 (권한 없는 공용 페이지 하나가 묶음 전체를 가리지 않게)
def finalize_probe(r) -> None:
    if r.sink_confirmed:
        r.stored_status, r.invalid_revisits, r.fail_note = "sink_found", [], None
        return
    notes = []
    if not _is_valid_status(r.post_status):
        notes.append(f"저장 요청 응답 무효 ({r.post_status})")
    if r.invalid_revisits:
        notes.append(f"재조회 응답 무효: {', '.join(r.invalid_revisits)}")
    if r.login_redirect and notes:
        notes.insert(0, "저장 요청 뒤 로그인 화면으로 이동")
    if notes:
        r.stored_status, r.fail_note = "probe_failed", "; ".join(notes)
    elif r.checked_count == 0:
        # 훑은 페이지가 하나도 없으면 수집 범위 내 미발견이라 부를 근거가 없다 (수집 GET 페이지 0곳이거나 전부 조회 실패)
        r.stored_status = "probe_failed"
        r.fail_note = f"훑은 페이지 없음 (조회 실패 {len(r.failed_urls)}곳)" if r.failed_urls else "훑은 페이지 없음 (수집 GET 페이지 0곳)"
    else:
        r.stored_status = "not_found_in_scope"
        r.fail_note = f"훑기 조회 실패 {len(r.failed_urls)}곳으로 일부 범위 미탐색" if r.failed_urls else None


# refetch() 반환값 (재조회 이후 값)
@dataclass
class RefetchResult:
    body: str               # 재조회 GET 응답 본문 (after 스냅샷)
    status: int | None      # 재조회 응답 상태코드
    attempts: int           # 총 GET 시도 횟수 (첫 GET 포함)
    found: bool             # payload가 응답에서 보였는지
    headers: dict | None = None  # 재조회 응답 헤더 (headless가 스냅샷을 렌더링할 때 CSP·Content-Type 적용)



'''
# 공격 이후 재시도해 확인
POST 공격 후 revisit_url을 재조회해 payload 안 보이면 await_ms만큼 대기 후 max_retry회까지 재시도

payload=None, max_retry=1로 호출하면 재시도 없이 1회만 도는 것을 이용해 공격 전 스냅샷에도 재사용 가능
'''
def refetch(revisit_url, cookies, payload, requester, zap,
            target=None, max_retry=REVISIT_MAX_RETRY, await_ms=REVISIT_AWAIT_MS) -> RefetchResult:

    headers = _get_headers_for_revisit(target or {})
    body, status, attempts, resp_headers = "", None, 0, None
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
        resp_headers = resp.get("response_headers")
        if payload and payload in body:
            return RefetchResult(body=body, status=status, attempts=attempts, found=True, headers=resp_headers)
    return RefetchResult(body=body, status=status, attempts=attempts, found=False, headers=resp_headers)


# 공격 전/후 두 본문을 줄 단위로 비교해 새로 추가되거나 바뀐 영역만 추출
def diff_new_region(before_body, after_body):
    before_lines = (before_body or "").splitlines()
    after_lines = (after_body or "").splitlines()
    sm = difflib.SequenceMatcher(None, before_lines, after_lines, autojunk=False)
    new_parts = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag in ("insert", "replace"):
            new_parts.extend(after_lines[j1:j2])
    return "\n".join(new_parts) if new_parts else None
