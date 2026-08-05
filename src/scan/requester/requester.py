import os
import time
from urllib.parse import urlparse

from scan.normalize.importer import _parse_response_status, _parse_headers_block
from scan.models import MutationCase
from collector.zap_collector import ZapCollector

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))                       # src/scan/requester
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_THIS_DIR))) # repo root
_ZAP_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")

# site(origin)별 최신 쿠키 저장소, target이 아닌 origin 단위 공유
_cookie_store: dict[str, dict[str, str]] = {}


# 쿠키 저장소 초기화, 스캔 시작 시 1회 호출
def clear_cookie_store() -> None:
    _cookie_store.clear()


# config 기반 ZAP 클라이언트 생성, 기존 세션/컨텍스트는 서버 쪽 상태라 그대로 유지됨
def get_zap_client():
    return ZapCollector.from_config(_ZAP_CONFIG).zap


# URL에서 "scheme://netloc" 추출, http/https 구분용
def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid absolute URL: {url}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


# case origin의 현재 쿠키 조회, 최초 접근 시 수집 당시 쿠키로 초기화
def _get_cookies(case: MutationCase) -> dict[str, str]:
    origin = _origin(case.url)
    stored = _cookie_store.setdefault(origin, {})
    for name, value in case.cookies.items():  # 이미 갱신된 값은 덮어쓰지 않음
        stored.setdefault(name, value)
    return dict(stored)  # 내부 dict 참조 노출 방지


# 응답 원문에서 Set-Cookie 라인 추출, dict 변환 시 동일 이름 헤더 유실 방지
def _iter_set_cookie_values(response_header: str):
    for line in response_header.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "set-cookie":
            yield value.strip()


# 응답의 Set-Cookie를 저장소에 반영, 빈 값은 반영하지 않고 삭제 지시
def _update_cookies_from_response(origin: str, response_header: str) -> None:
    stored = _cookie_store.setdefault(origin, {})
    for set_cookie in _iter_set_cookie_values(response_header):
        cookie_pair = set_cookie.split(";", 1)[0].strip()  # Path/Expires 등 속성 제외
        if "=" not in cookie_pair:
            continue
        name, value = cookie_pair.split("=", 1)
        name, value = name.strip(), value.strip()
        if not name:
            continue
        if value:
            stored[name] = value
        else:
            stored.pop(name, None)


# MutationCase + cookies -> raw HTTP 요청 텍스트 재조립
def _build_raw_request(case: MutationCase, cookies: dict[str, str]) -> str:
    parsed = urlparse(case.url)
    path = parsed.path + (f"?{parsed.query}" if parsed.query else "")

    lines = [f"{case.method} {path} HTTP/1.1"]
    for k, v in case.headers.items():
        lines.append(f"{k}: {v}")
    if cookies:  # importer가 헤더에서 빼놓은 cookie, Cookie 헤더로 재조립
        cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
        lines.append(f"Cookie: {cookie_str}")

    request_text = "\r\n".join(lines) + "\r\n\r\n"
    if case.body:
        request_text += case.body
    return request_text


# case를 현재 쿠키로 전송, 응답의 Set-Cookie 반영 후 결과 dict 리턴
def send(case: MutationCase, zap) -> dict:
    origin = _origin(case.url)
    cookies = _get_cookies(case)
    raw_request = _build_raw_request(case, cookies)
    started = time.perf_counter()
    result = zap.core.send_request(request=raw_request, followredirects=False)
    elapsed = time.perf_counter() - started
    if not isinstance(result, list) or not result or not isinstance(result[0], dict):     # [{...}] 형태 아니면 원인 파악 위해 실제 응답값 그대로 예외 메시지에 포함
        raise RuntimeError(f"ZAP send_request 실패, 응답: {result!r}")
    msg = result[0]
    response_header = msg.get("responseHeader", "")

    _update_cookies_from_response(origin, response_header)  # 다음 요청부터 갱신된 쿠키 사용

    return {
        "case_id": case.case_id,
        "response_status": _parse_response_status(response_header),
        "response_headers": _parse_headers_block(response_header),
        "response_body": msg.get("responseBody", ""),
        "elapsed": elapsed,
    }
