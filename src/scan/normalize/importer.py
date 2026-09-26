import re
from urllib.parse import urlparse, parse_qs
from .target import RequestTarget

# 정적 파일 확장자
_STATIC_EXT = re.compile(
    r"\.(css|js|png|jpg|jpeg|gif|svg|ico|woff2?|ttf|eot|pdf|zip|map)(\?|$)",
    re.IGNORECASE,
)


def _first_line(raw: str) -> str:
    if not raw:
        return ""
    return (raw.split("\r\n")[0] if "\r\n" in raw else raw.split("\n")[0]).strip()


# requestHeader 첫 줄 -> (method, path) (예: "GET /path?q=1 HTTP/1.1" -> ("GET", "/path?q=1"))
def _parse_request_line(raw: str) -> tuple[str, str]:
    parts = _first_line(raw).split(" ")
    if len(parts) >= 2:
        return parts[0].upper(), parts[1]
    return "", ""


# responseHeader 첫 줄 -> status code (예: "HTTP/1.1 200 OK" -> 200)
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


# POST 폼 바디(application/x-www-form-urlencoded) -> 파라미터 dict (같은 이름의 값 전부 보존)
def _parse_form_body(body: str) -> dict[str, list[str]]:
    if not body:
        return {}
    return parse_qs(body, keep_blank_values=True)


# ZAP 메시지 목록 -> RequestTarget 목록 (GET은 쿼리, POST는 쿼리 + form 바디 / JSON·multipart 바디는 추후 구현)
def to_targets(messages: list[dict]) -> list[RequestTarget]:
    seen: set[tuple] = set()
    targets: list[RequestTarget] = []

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

        # 파라미터 위치(query/body)별로 따로 수집, 같은 이름의 파라미터(HPP 등)는 값 전부 보존
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        sites: list[tuple[dict, str]] = []
        if method == "GET":
            if query_params:
                sites.append((query_params, "query"))
        else:  # POST
            content_type = req_headers.get("content-type", "")
            if "application/x-www-form-urlencoded" in content_type:  # JSON/multipart 바디는 추후 구현
                body_params = _parse_form_body(msg.get("requestBody", "") or "")
                if body_params:
                    sites.append((body_params, "body"))
            if query_params:  # POST여도 URL 쿼리에 지점이 있으면 content-type과 무관하게 별도 수집
                sites.append((query_params, "query"))
        if not sites:
            continue

        cookies = _parse_cookies(req_headers.get("cookie", ""))
        headers_clean = {k: v for k, v in req_headers.items() if k != "cookie"}

        # status: msg 필드 우선, 없으면 responseHeader 파싱
        response_status = _safe_int(msg.get("statusCode")) or _parse_response_status(resp_header_raw)

        # 인증·기능 차이 보존용으로 쿠키 이름(값 제외)과 응답 상태 코드도 중복 제거 기준에 포함
        cookie_names = tuple(sorted(cookies.keys()))

        for params, param_location in sites:
            param_shape = tuple(sorted((name, len(values)) for name, values in params.items()))
            dedup_key = (method, base_url, param_location, param_shape, cookie_names, response_status)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            targets.append(RequestTarget(
                method=method,
                url=url,
                base_url=base_url,
                params=params,
                param_location=param_location,
                headers=headers_clean,
                cookies=cookies,
                request_body=msg.get("requestBody", "") or "",
                response_status=response_status,
                response_headers=_parse_headers_block(resp_header_raw),
                response_body=msg.get("responseBody", "") or "",
                zap_message_id=str(msg.get("id", "")),
            ))

    return targets
