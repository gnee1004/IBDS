from __future__ import annotations

import html
from dataclasses import dataclass
from urllib.parse import quote

from .payloads import DB_ERROR_KEYWORDS, UNION_ERROR_KEYWORDS

# Time-based 기준
SLEEP_THRESHOLD = 4.5   # 공격 응답이 이 값(초) 이상이어야 지연으로 인정
DELAY_MARGIN = 4.0      # baseline 대비 최소 추가 지연(초) — 원래 느린 페이지 오탐 방지
MIN_REPEAT_CONFIRM = 2


@dataclass
class SqliVerdict:
    vulnerable: bool
    confidence: str
    evidence: str


# 응답 본문에서 payload/입력값 반사분을 제거 (동적 diff 비교 시 반사 노이즈 제거용)
def _strip_value(body: str, value: str) -> str:
    if not value:
        return body
    variants = {value, quote(value), html.escape(value), html.escape(quote(value))}
    for v in variants:
        if v:
            body = body.replace(v, "")
    return body


def judge_union_sqli(baseline_body: str, attack_body: str) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()
    for kw in UNION_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(True, "medium", f"UNION-based SQLi: 컬럼 수 불일치 에러 노출 ('{kw}')")
    return SqliVerdict(False, "", "UNION 에러 시그니처 없음")


def judge_error_based_sqli(baseline_body: str, attack_body: str) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()

    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(True, "high", f"Error-based SQLi: baseline에는 없던 DB 에러 노출 ('{kw}')")

    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw in base_lower:
            return SqliVerdict(False, "", f"DB 에러 문구가 baseline에도 있음 — 이 페이지의 정상 동작 ('{kw}')")

    return SqliVerdict(False, "", "DB 에러 시그니처 없음")


def judge_time_based_sqli(baseline_elapsed: float, attack_elapsed_list: list[float]) -> SqliVerdict:
    # 절대 임계(SLEEP_THRESHOLD)와 baseline 대비 증분(DELAY_MARGIN)을 모두 만족해야 지연으로 인정
    # → 원래부터 느린 엔드포인트에서 baseline까지 느린 경우의 오탐을 방지
    def _is_delayed(e: float) -> bool:
        return e >= SLEEP_THRESHOLD and (e - baseline_elapsed) >= DELAY_MARGIN

    slow_count = sum(1 for e in attack_elapsed_list if _is_delayed(e))

    if slow_count == 0:
        return SqliVerdict(
            False, "",
            f"지연 응답 없음 (baseline {baseline_elapsed:.2f}s 대비 +{DELAY_MARGIN:.0f}s 초과 없음)"
        )

    if slow_count >= MIN_REPEAT_CONFIRM:
        avg = sum(attack_elapsed_list) / len(attack_elapsed_list)
        return SqliVerdict(
            True, "high",
            f"Time-based SQLi (confirmed): {slow_count}/{len(attack_elapsed_list)}회 지연 재현 "
            f"(평균 {avg:.2f}s, baseline {baseline_elapsed:.2f}s, +{DELAY_MARGIN:.0f}s 이상)"
        )

    return SqliVerdict(
        True, "medium",
        f"Time-based SQLi (suspected): {slow_count}/{len(attack_elapsed_list)}회만 baseline+{DELAY_MARGIN:.0f}s 초과 — "
        f"재현성 부족, 추가 검증 필요"
    )
