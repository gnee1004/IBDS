"""
target + ScanPoint 정보 -> MutationCase 생성
payload를 실제 요청(URL 쿼리 또는 폼 바디)에 삽입해 변형 케이스를 만드는 부분임.
"""

from __future__ import annotations
import urllib.parse
from scan.models import MutationCase


# URL 쿼리스트링에서 param_name 값을 new_value로 교체
def _mutate_query(url: str, param_name: str, new_value: str) -> str:
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    result = []
    for k, v in params:
        if k == param_name and not replaced:
            result.append((k, new_value))
            replaced = True
        else:
            result.append((k, v))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(result)))


# 폼 바디(x-www-form-urlencoded)에서 param_name 값을 new_value로 교체
def _mutate_form(body: str, param_name: str, new_value: str) -> str:
    params = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
    replaced = False
    result = []
    for k, v in params:
        if k == param_name and not replaced:
            result.append((k, new_value))
            replaced = True
        else:
            result.append((k, v))
    return urllib.parse.urlencode(result)


# location("form"/"query"/"json")을 body_type("form" or "query")으로 판정
def _body_type(location: str) -> str:
    return "form" if location == "form" else "query"


# DOM 계열 payload를 URL fragment(#뒤)로 주입. 기존 fragment는 버리고 교체.
# payload가 이미 "#"로 시작하면 중복 방지 위해 앞의 "#"만 제거 후 다시 붙임.
def _inject_fragment(url: str, payload: str) -> str:
    base = url.split("#", 1)[0]
    return f"{base}#{payload.lstrip('#')}"


_STORED_VERIFY_STEP = "stored_verify"  # 저장형 XSS: POST 주입 후 저장분을 되읽는 GET 재조회 case의 step


# 저장형 XSS 재조회 대상 URL 결정.
# target.verify_url(명시적 표시 페이지) > base_url(제출 엔드포인트 재-GET) > url 순.
# 게시판류의 "POST /board 제출 -> GET /board 목록에서 노출" 패턴을 base_url 재-GET로 기본 커버하고,
# 수집기가 실제 노출 페이지를 알려주면 verify_url로 재정의할 수 있게 열어둠.
def stored_verify_url(target: dict) -> str:
    return target.get("verify_url") or target.get("base_url") or target.get("url", "")


# 저장형 XSS 검증용 GET 재조회 case 생성.
# payload를 요청에 싣지 않는 "깨끗한 GET"이지만, judge가 무엇을 찾아야 하는지 알 수 있도록
# 검증 대상 payload 문자열을 payload 필드에 태깅해 둔다. (요청 본문/URL에는 주입하지 않음)
def build_stored_verify_case(target: dict, attack_case: MutationCase) -> MutationCase:
    return MutationCase(
        case_id=f"{attack_case.case_id}_verify",
        step=_STORED_VERIFY_STEP,
        method="GET",
        url=stored_verify_url(target),
        headers=dict(target.get("headers") or {}),
        cookies=dict(target.get("cookies") or {}),
        body_type="query",
        body="",
        payload=attack_case.payload,             # 검증 대상 payload 태깅 (judge_xss가 이 값을 재조회 응답에서 탐색)
        original_value=attack_case.original_value,
    )


# 원본 target 요청 그대로의 baseline MutationCase 생성
def build_baseline_case(target: dict, location: str, case_id: str) -> MutationCase:
    return MutationCase(
        case_id=case_id,
        step="baseline",
        method=target.get("method", "GET").upper(),
        url=target.get("url", target.get("base_url", "")),
        headers=dict(target.get("headers") or {}),
        cookies=dict(target.get("cookies") or {}),
        body_type=_body_type(location),
        body=target.get("request_body") or "",
    )


# param_name 위치에 payload를 삽입한 mutation MutationCase 생성
def build_mutation_case(
    target: dict,
    location: str,
    param_name: str,
    original_value: str,
    payload: str,
    step: str,
    case_id: str,
    inject_fragment: bool = False,
) -> MutationCase:
    method = target.get("method", "GET").upper()
    base_url = target.get("base_url", "")
    url = target.get("url", base_url)
    body = target.get("request_body") or ""
    body_type = _body_type(location)

    if inject_fragment:  # DOM 계열: 파라미터 값이 아니라 URL fragment로 주입 (location.hash용)
        mutated_url = _inject_fragment(url, payload)
        mutated_body = body
    elif body_type == "form":
        mutated_url = base_url
        mutated_body = _mutate_form(body, param_name, payload)
    else:
        mutated_url = _mutate_query(url, param_name, payload)
        mutated_body = body

    return MutationCase(
        case_id=case_id,
        step=step,
        method=method,
        url=mutated_url,
        headers=dict(target.get("headers") or {}),
        cookies=dict(target.get("cookies") or {}),
        body_type=body_type,
        body=mutated_body,
        payload=payload,
        original_value=original_value,
    )