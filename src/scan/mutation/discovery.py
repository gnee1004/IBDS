from __future__ import annotations

from bs4 import BeautifulSoup, NavigableString

from scan.models import DiscoveryResult, ScanPoint
from scan.mutation.variant import build_mutation_case
from scan.requester import requester

_CANDIDATE_SPECIALS = ["<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"]
_SPECIALS_MARK_START = "ibdsA"
_SPECIALS_MARK_END = "ibdsZ"
_SAFE_TAGS = {"textarea", "title", "noscript", "xmp", "plaintext"}
_URL_ATTRS = {"src", "href", "action", "data"}


# 파라미터 값이 응답에 그대로 반사되는지 marker 문자열로 확인, body도 함께 반환
def probe_reflected(sp: ScanPoint, target: dict, zap) -> tuple[bool, str]:
    marker = f"ibdsreflect{sp.target_id}{sp.name}"
    case = build_mutation_case(
        target, sp.location, sp.name, sp.original_value, marker,
        "discovery_reflect", f"{sp.target_id}_{sp.name}_discovery_reflect",
    )
    result = requester.send(case, zap)
    body = result.get("response_body") or ""
    return marker in body, body


# 반사 지점에서 이스케이프 없이 살아남는 특수문자 집합 확인
def probe_specials(sp: ScanPoint, target: dict, zap) -> set[str]:
    payload = f"{_SPECIALS_MARK_START}{''.join(_CANDIDATE_SPECIALS)}{_SPECIALS_MARK_END}"
    case = build_mutation_case(
        target, sp.location, sp.name, sp.original_value, payload,
        "discovery_specials", f"{sp.target_id}_{sp.name}_discovery_specials",
    )
    result = requester.send(case, zap)
    body = result.get("response_body") or ""

    start = body.find(_SPECIALS_MARK_START)
    end = body.find(_SPECIALS_MARK_END)
    if start == -1 or end == -1 or end < start:
        return set()  # marker 자체가 안 보이면 특수문자 확인 불가 -> 안전하게 빈 집합

    reflected_segment = body[start + len(_SPECIALS_MARK_START):end]
    return {ch for ch in _CANDIDATE_SPECIALS if ch in reflected_segment}


# 마커가 반사된 위치의 HTML 컨텍스트 탐지
# 반환값: "inHTML" / "inAttr" / "inAttrUrl" / "inScript" / None(억제 컨텍스트 또는 미탐지)
def detect_injection_context(body: str, marker: str) -> str | None:
    if marker not in body:
        return None

    soup = BeautifulSoup(body, "html.parser")

    for tag in soup.find_all(True):
        # 속성값에서 탐색
        for attr_name, attr_value in tag.attrs.items():
            if isinstance(attr_value, list):
                attr_value = " ".join(attr_value)
            if marker not in attr_value:
                continue
            if attr_name.startswith("on"):
                return "inScript"
            if attr_name in _URL_ATTRS:
                return "inAttrUrl"
            return "inAttr"

        # 텍스트 노드에서 탐색
        for child in tag.children:
            if isinstance(child, NavigableString) and marker in str(child):
                tag_name = tag.name.lower()
                if tag_name == "script":
                    return "inScript"
                if tag_name in _SAFE_TAGS:
                    return None
                return "inHTML"

    return None


# 반사 확인 -> 반사 안 되면 특수문자 probe 생략 -> DiscoveryResult
def run_discovery(sp: ScanPoint, target: dict, zap) -> DiscoveryResult:
    reflected, body = probe_reflected(sp, target, zap)
    if not reflected:
        return DiscoveryResult(reflected=False, valid_specials=set())
    marker = f"ibdsreflect{sp.target_id}{sp.name}"
    return DiscoveryResult(
        reflected=True,
        valid_specials=probe_specials(sp, target, zap),
        injection_context=detect_injection_context(body, marker),
    )
