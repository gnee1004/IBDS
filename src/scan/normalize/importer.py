import re
from urllib.parse import urlparse, parse_qs

# 정적 파일 확장자
_STATIC_EXT = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|map)(\?|$)",
    re.IGNORECASE,
)


def _first_line(raw: str) -> str:
    if not raw:
        return ""
    return (raw.split("\r\n")[0] if "\r\n" in raw else raw.split("\n")[0]).strip()


# requestHeader 첫 줄 파싱(method, path)해 tuple에 저장
# 예: "GET /path?q=1 HTTP/1.1" -> ("GET", "/path?q=1")
def _parse_request_line(raw: str) -> tuple[str, str]:
    parts = _first_line(raw).split(" ")
    if len(parts) >= 2:
        return parts[0].upper(), parts[1]
    return "", ""


# responseHeader 첫 줄 파싱 (status code) 해 int로 저장
# 예: "HTTP/1.1 200 OK" -> 200
def _parse_response_status(raw: str) -> int:
    parts = _first_line(raw).split(" ")
    if len(parts) >= 2:
        try:
            return int(parts[1])
        except ValueError:
            pass
    return 0


# raw HTTP 헤더 블록 -> 헤더의 각 키, 값을 dict로 (첫 줄 스킵)
def _parse_headers_block(raw: str) -> dict[str, str]:
    headers = {}
    lines = raw.replace("\r\n", "\n").split("\n") if raw else []
    for line in lines[1:]:  # 첫 줄(요청행/상태행) 스킵
        if ": " in line:
            k, _, v = line.partition(": ")
            headers[k.lower().strip()] = v.strip()
    return headers


def _parse_cookies(cookie_str: str) -> dict[str, str]:
    cookies = {}
    for part in cookie_str.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            cookies[k.strip()] = v.strip()
    return cookies


# msg["url"] 없을 때 Host 헤더 + path로 URL 구성
def _build_url(msg: dict, req_headers: dict, path: str) -> str:
    url = (msg.get("url") or "").strip()
    if url:
        return url
    if path.startswith(("http://", "https://")):  # path에 절대 URL이 들어오는 경우
        return path
    host = req_headers.get("host", "")
    if not host:
        return path
    scheme = "https" if ":443" in host else "http"
    return f"{scheme}://{host}{path}"


def _safe_int(value) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


# POST 폼 바디(application/x-www-form-urlencoded) -> 파라미터 dict (첫 번째 값만)
def _parse_form_body(body: str) -> dict[str, str]:
    if not body:
        return {}
    raw = parse_qs(body, keep_blank_values=True)
    return {k: v[0] for k, v in raw.items()}


# ZAP 메시지 목록 -> RequestTarget 목록
# 조건: GET은 query parameter, POST는 x-www-form-urlencoded 바디 파라미터가 있는 것만 포함 (JSON/multipart는 추후 구현)
# 중복 제거: (method, base_url, param_location, 파라미터 이름 조합) 기준
def to_targets(messages: list[dict]) -> list[dict]:
    seen: set[tuple] = set()
    targets = []

    for msg in messages:
        req_header_raw = msg.get("requestHeader", "") or ""
        resp_header_raw = msg.get("responseHeader", "") or ""

        # method: msg 필드 우선, 없으면 requestHeader 파싱
        method = (msg.get("method") or "").upper().strip()
        header_method, header_path = _parse_request_line(req_header_raw)
        if not method:
            method = header_method
        if method not in ("GET", "POST"):
            continue

        req_headers = _parse_headers_block(req_header_raw)

        # url: msg 필드 우선, 없으면 Host헤더 + requestHeader path로 구성
        url = _build_url(msg, req_headers, header_path)
        if not url:
            continue

        parsed = urlparse(url)
        if _STATIC_EXT.search(parsed.path):
            continue

        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # 값이 여러 개인 파라미터는 첫 번째 값만 저장 (mvp형태. 나중에 달라질 수 있음.)
        if method == "GET":
            raw_params = parse_qs(parsed.query, keep_blank_values=True)
            if not raw_params:
                continue
            params = {k: v[0] for k, v in raw_params.items()}
            param_location = "query"
        else:  # POST
            content_type = req_headers.get("content-type", "")
            if "application/x-www-form-urlencoded" not in content_type:
                continue  # JSON/multipart 바디는 추후 구현
            params = _parse_form_body(msg.get("requestBody", "") or "")
            if not params:
                continue
            param_location = "body"

        # (method, base_url, param_location, 파라미터 이름 조합) 기준 중복 제거
        dedup_key = (method, base_url, param_location, frozenset(params.keys()))
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        cookies = _parse_cookies(req_headers.get("cookie", ""))
        headers_clean = {k: v for k, v in req_headers.items() if k != "cookie"}

        # status: msg 필드 우선, 없으면 responseHeader 파싱
        response_status = _safe_int(msg.get("statusCode")) or _parse_response_status(resp_header_raw)

        targets.append({
            "target_id":       f"t{len(targets)}",
            "method":          method,
            "url":             url,
            "base_url":        base_url,
            "params":          params,
            "param_location":  param_location,
            "headers":         headers_clean,
            "cookies":         cookies,
            "request_body":    msg.get("requestBody", "") or "",
            "response_status": response_status,
            "response_headers": _parse_headers_block(resp_header_raw),
            "response_body":   msg.get("responseBody", "") or "",
            "zap_message_id":  str(msg.get("id", "")),
        })

    return targets
