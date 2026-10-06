from __future__ import annotations

import re
from dataclasses import dataclass

_SCRIPT_OPEN_RE   = re.compile(r'<script[\s>/]', re.IGNORECASE)
_SCRIPT_CLOSE_RE  = re.compile(r'</script\s*>', re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r'\bon\w+\s*=', re.IGNORECASE)

_EVENT_WINDOW = 40  # 이벤트핸들러(onerror=alert(1) 등)는 alert 바로 앞에 붙음


# alert(1)이 아직 안 닫힌 <script> 안에 있는지 (page 자체 스크립트는 그 전에 </script>로 닫혀 제외됨)
def _in_open_script(prefix: str) -> bool:
    last_open = None
    for last_open in _SCRIPT_OPEN_RE.finditer(prefix):
        pass
    if last_open is None:
        return False
    return not _SCRIPT_CLOSE_RE.search(prefix, last_open.end())  # 열린 뒤 닫힘 없음


# 이벤트핸들러 속성(onX=)이 태그 안에서 alert 바로 앞에 있는지 (textarea 등 이스케이프 반사 제외)
def _in_event_handler(prefix: str) -> bool:
    window = prefix[-_EVENT_WINDOW:]
    m = None
    for m in _EVENT_HANDLER_RE.finditer(window):
        pass
    if m is None:
        return False
    return ">" not in window[m.end():]  # 핸들러 뒤로 태그가 안 닫힘 = 아직 속성 안


# alert(1) 반사 위치가 실제 실행 문맥(열린 script / 이벤트핸들러 속성) 안인지 (페이지 자체 스크립트 오탐 배제)
def _has_local_exec_context(body: str) -> bool:
    for m in re.finditer(re.escape("alert(1)"), body):
        prefix = body[:m.start()]
        if _in_open_script(prefix) or _in_event_handler(prefix):
            return True
    return False


@dataclass
class XssVerdict:
    vulnerable: bool
    confidence: str
    evidence: str


def judge_xss(response_body: str, payload: str) -> XssVerdict:
    body = response_body or ""

    # payload 그대로 반사
    if payload in body:
        return XssVerdict(True, "high", "XSS: payload가 비이스케이프 상태로 그대로 반사됨")

    if "alert(1)" in body:
        # textarea 등 raw text 문맥에 갇혀 breakout 못 하면, 근처에 실행 태그가 없어 medium 이하
        if _has_local_exec_context(body):
            return XssVerdict(True, "high", "XSS: 실행 가능한 태그/이벤트핸들러와 함께 반사됨")
        return XssVerdict(True, "medium", "XSS: alert(1) 반사됨 — JS 컨텍스트 수동 확인 필요")

    return XssVerdict(False, "", "XSS payload 반사 없음")
