import os
import time
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlparse

from scan.normalize.importer import _parse_response_status, _parse_headers_block
from scan.models import MutationCase
from collector.zap_collector import ZapCollector

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))                       # src/scan/requester
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(_THIS_DIR))) # repo root
_ZAP_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")

_SEND_MAX_RETRIES = 2
_SEND_RETRY_DELAY_SECS = 0.5

# site(origin)별 최신 쿠키 저장소, target이 아닌 origin 단위 공유.
# 키를 (name, path)로 둬서 같은 이름·다른 경로 쿠키가 서로 덮어쓰지 않도록 한다.
_cookie_store: dict[str, dict[tuple[str, str], str]] = {}

# 삭제된 쿠키 표식(tombstone) — 서버가 지운 (name, path)를 origin별로 기억한다.
# _get_cookies가 수집 당시 case.cookies로 되살리는 "재부활"을 막는 용도.
_deleted_cookies: dict[str, set[tuple[str, str]]] = {}


# 쿠키 저장소 초기화, 스캔 시작 시 1회 호출
def clear_cookie_store() -> None:
    _cookie_store.clear()
    _deleted_cookies.clear()


# config 기반 ZAP 클라이언트 생성, 기존 세션/컨텍스트는 서버 쪽 상태라 그대로 유지됨
def get_zap_client():
    return ZapCollector.from_config(_ZAP_CONFIG).zap


# URL에서 "scheme://netloc" 추출, http/https 구분용
def _origin(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid absolute URL: {url}")
    return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}"


# 요청 URL에서 경로 추출 (없으면 "/")
def _request_path(url: str) -> str:
    return urlparse(url).path or "/"


# Set-Cookie의 default-path 계산 (RFC 6265 §5.1.4): 경로가 "/"로 시작 안 하거나
# 첫 글자 뒤에 "/"가 없으면 "/", 아니면 마지막 "/" 앞까지.
def _default_path(req_path: str) -> str:
    if not req_path.startswith("/") or req_path.count("/") <= 1:
        return "/"
    return req_path[: req_path.rfind("/")] or "/"


# RFC 6265 §5.1.4 path-match: 쿠키 경로가 요청 경로를 포함하는지
def _path_matches(cookie_path: str, req_path: str) -> bool:
    if cookie_path == req_path:
        return True
    if req_path.startswith(cookie_path):
        return cookie_path.endswith("/") or req_path[len(cookie_path):].startswith("/")
    return False


# Set-Cookie 한 줄 파싱 -> (name, value, path, is_deletion).
# 삭제 지시 판단: 빈 값 / Max-Age<=0 / 과거 Expires 중 하나라도 해당.
def _parse_set_cookie(set_cookie: str, req_path: str) -> tuple[str, str, str, bool] | None:
    parts = [p.strip() for p in set_cookie.split(";")]
    if not parts or "=" not in parts[0]:
        return None
    name, value = parts[0].split("=", 1)
    name, value = name.strip(), value.strip()
    if not name:
        return None

    path = ""
    max_age: int | None = None
    expires_past = False
    for attr in parts[1:]:
        key, _, val = attr.partition("=")
        key, val = key.strip().lower(), val.strip()
        if key == "path" and val:
            path = val
        elif key == "max-age":
            try:
                max_age = int(val)
            except ValueError:
                max_age = None
        elif key == "expires" and val:
            try:
                exp = parsedate_to_datetime(val)
                if exp is not None:
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    expires_past = exp <= datetime.now(timezone.utc)
            except (TypeError, ValueError):
                expires_past = False

    if not path:
        path = _default_path(req_path)
    is_deletion = (value == "") or (max_age is not None and max_age <= 0) or expires_past
    return name, value, path, is_deletion


# case origin의 현재 쿠키 조회, 최초 접근 시 수집 당시 쿠키로 초기화.
# 요청 경로에 path-match 되는 쿠키만 골라 name->value 로 돌려준다(같은 이름이면 더 구체적인 경로 우선).
def _get_cookies(case: MutationCase) -> dict[str, str]:
    origin = _origin(case.url)
    req_path = _request_path(case.url)
    stored = _cookie_store.setdefault(origin, {})
    tombstones = _deleted_cookies.setdefault(origin, set())

    for name, value in case.cookies.items():  # 수집 당시 쿠키로 시딩 — 단, 삭제 표식은 되살리지 않음
        key = (name, "/")
        if key not in stored and key not in tombstones:
            stored[key] = value

    selected: dict[str, str] = {}
    best_path: dict[str, str] = {}  # name -> 채택된 경로 (더 긴=구체적 경로가 이김)
    for (name, path), value in stored.items():
        if not _path_matches(path, req_path):
            continue
        if name not in best_path or len(path) > len(best_path[name]):
            selected[name] = value
            best_path[name] = path
    return selected


# 응답 원문에서 Set-Cookie 라인 추출, dict 변환 시 동일 이름 헤더 유실 방지
def _iter_set_cookie_values(response_header: str):
    for line in response_header.splitlines():
        name, sep, value = line.partition(":")
        if sep and name.strip().lower() == "set-cookie":
            yield value.strip()


# 응답의 Set-Cookie를 저장소에 반영. (name, path) 단위로 저장/삭제하고,
# 삭제(빈 값·Max-Age<=0·과거 Expires)면 tombstone에 남겨 재부활을 막는다.
def _update_cookies_from_response(origin: str, response_header: str, req_path: str) -> None:
    stored = _cookie_store.setdefault(origin, {})
    tombstones = _deleted_cookies.setdefault(origin, set())
    for set_cookie in _iter_set_cookie_values(response_header):
        parsed = _parse_set_cookie(set_cookie, req_path)
        if parsed is None:
            continue
        name, value, path, is_deletion = parsed
        key = (name, path)