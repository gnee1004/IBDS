from __future__ import annotations

import re
from difflib import SequenceMatcher

from bs4 import BeautifulSoup, NavigableString

from scan.models import DiscoveryResult, ScanPoint
from scan.mutation.variant import build_baseline_case, build_mutation_case
from scan.requester import requester

_CANDIDATE_SPECIALS = ["<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"]
_SPECIALS_MARK_START = "ibdsA"
_SPECIALS_MARK_END = "ibdsZ"
_RAW_TEXT_TAGS = {"textarea", "title", "noscript", "xmp"}
_SUPPRESSED_TAGS = {"plaintext"}
_URL_ATTRS = {"src", "href", "action", "data"}

_MARKER_CONTEXT_LEN = 6  # 흔들리는 구간 앞뒤로 이만큼의 고정 글자를 "경계"로 삼음
_TOKEN_RE = re.compile(r"[0-9A-Za-z가-힣]+|[^0-9A-Za-z가-힣]+")  # 값 덩어리 단위로 토큰화 (글자 단위 diff는 숫자 하나만 달라도 우연히 겹쳐 보임)


# 파라미터 값이 응답에 그대로 반사되는지 marker 문자열로 확인, body도 함께 반환
def probe_reflected(sp: ScanPoint, target: dict, zap) -> tuple[bool, str]:
    marker = f"ibdsreflect{sp.target_id}{sp.tag}"
    case = build_mutation_case(
        target, sp.location, sp.name, sp.original_value, marker,
        "discovery_reflect", f"{sp.target_id}_{sp.tag}_discovery_reflect",
        value_index=sp.value_index,
    )
    result = requester.send(case, zap)
    body = result.get("response_body") or ""
    return marker in body, body


# 반사 지점에서 이스케이프 없이 살아남는 특수문자 집합 확인
def probe_specials(sp: ScanPoint, target: dict, zap) -> set[str]:
    payload = f"{_SPECIALS_MARK_START}{''.join(_CANDIDATE_SPECIALS)}{_SPECIALS_MARK_END}"
    case = build_mutation_case(
        target, sp.location, sp.name, sp.original_value, payload,
        "discovery_specials", f"{sp.target_id}_{sp.tag}_discovery_specials",
        value_index=sp.value_index,
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
def detect_injection_context(body: str, marker: str) -> str | None:
    if marker not in body:
        return None

    soup = BeautifulSoup(body, "html.parser")

    contexts: set[str] = set()
    for tag in soup.find_all(True):
        # 속성값에서 탐색
        for attr_name, attr_value in tag.attrs.items():
            if isinstance(attr_value, list):
                attr_value = " ".join(attr_value)
            if marker not in attr_value:
                continue
            if attr_name.startswith("on"):
                contexts.add("inScript")
            elif attr_name in _URL_ATTRS:
                contexts.add("inAttrUrl")
            else:
                contexts.add("inAttr")

        # 텍스트 노드에서 탐색
        for child in tag.children:
            if isinstance(child, NavigableString) and marker in str(child):
                tag_name = tag.name.lower()
                if tag_name == "script":
                    contexts.add("inScript")
                elif tag_name in _RAW_TEXT_TAGS:
                    contexts.add("inRawText")
                elif tag_name in _SUPPRESSED_TAGS:
                    contexts.add("suppressed")
                else:
                    contexts.add("inHTML")

    attackable = contexts - {"suppressed"}
    if len(attackable) == 1:
        return next(iter(attackable))
    if not attackable and contexts == {"suppressed"}:
        return "suppressed"
    return None


# idxs 순서대로 토큰을 이어붙여 길이 _MARKER_CONTEXT_LEN을 채움. 토큰이 모자라 못 채우면 None(경계 불안정 -> 제외)
def _take_tokens(tokens: list[str], idxs: range) -> str | None:
    collected: list[str] = []
    length = 0
    for idx in idxs:
        collected.append(tokens[idx])
        length += len(tokens[idx])
        if length >= _MARKER_CONTEXT_LEN:
            if idxs.step < 0:  # prefix는 뒤에서부터 모았으므로 원래 순서로 되돌림
                collected.reverse()
            return "".join(collected)
    return None


def _extract_dynamic_markers(body1: str, body2: str) -> list[tuple[str, str]]:
    tokens1 = _TOKEN_RE.findall(body1)
    tokens2 = _TOKEN_RE.findall(body2)

    markers: set[tuple[str, str]] = set()
    for tag, i1, i2, _j1, _j2 in SequenceMatcher(None, tokens1, tokens2).get_opcodes():
        if tag == "equal":
            continue
        prefix = _take_tokens(tokens1, range(i1 - 1, -1, -1))
        suffix = _take_tokens(tokens1, range(i2, len(tokens1)))
        if prefix is not None and suffix is not None:
            markers.add((prefix, suffix))
    return list(markers)


# 같은 baseline을 두 번 보내 응답을 비교, 이 타겟이 원래 갖고 있는 "흔들리는 자리"를 찾음 (ScanPoint당 1회).
# 두 응답의 전체 유사도(match_ratio)도 같이 반환 — "완전히 같은 요청인데도 원래 이만큼은 달라 보인다"는
# 이 타겟만의 기준점(sqlmap의 matchRatio와 동일한 발상)이 되어, boolean 판정의 고정 절대 임계값을 대체함.
def measure_dynamic_markers(sp: ScanPoint, target: dict, zap) -> tuple[list[tuple[str, str]], float]:
    case1 = build_baseline_case(target, sp.location, f"{sp.target_id}_{sp.tag}_noise1")
    case2 = build_baseline_case(target, sp.location, f"{sp.target_id}_{sp.tag}_noise2")
    body1 = requester.send(case1, zap).get("response_body") or ""
    body2 = requester.send(case2, zap).get("response_body") or ""
    markers = _extract_dynamic_markers(body1, body2)
    match_ratio = SequenceMatcher(None, body1, body2).ratio()
    return markers, match_ratio


# 반사 확인 -> 반사 안 되면 특수문자 probe 생략 -> DiscoveryResult
def run_discovery(sp: ScanPoint, target: dict, zap) -> DiscoveryResult:
    reflected, body = probe_reflected(sp, target, zap)
    if not reflected:
        return DiscoveryResult(reflected=False, valid_specials=set())
    marker = f"ibdsreflect{sp.target_id}{sp.tag}"
    return DiscoveryResult(
        reflected=True,
        valid_specials=probe_specials(sp, target, zap),
        injection_context=detect_injection_context(body, marker),
    )
