from __future__ import annotations

import re
from dataclasses import dataclass

_SCRIPT_TAG_RE    = re.compile(r'<script[\s>/]', re.IGNORECASE)
_EVENT_HANDLER_RE = re.compile(r'\bon\w+\s*=', re.IGNORECASE)


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
        if _SCRIPT_TAG_RE.search(body) or _EVENT_HANDLER_RE.search(body):
            return XssVerdict(True, "high", "XSS: 실행 가능한 태그/이벤트핸들러와 함께 반사됨")
        return XssVerdict(True, "medium", "XSS: alert(1) 반사됨 — JS 컨텍스트 수동 확인 필요")

    return XssVerdict(False, "", "XSS payload 반사 없음")
