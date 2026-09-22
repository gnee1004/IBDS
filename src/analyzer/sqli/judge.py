from __future__ import annotations

import html
import re
from dataclasses import dataclass
from urllib.parse import quote

# 응답 본문에서 이 문구가 나오면 SQLi로 판정 (error-based / union 판정용 시그니처)
UNION_ERROR_KEYWORDS: tuple[str, ...] = (
    "the used select statements have a different number of columns",
    "column count doesn't match",
)

DB_ERROR_KEYWORDS: tuple[str, ...] = (
    "you have an error in your sql syntax",
    "warning: mysql",
    "unknown column",
    "mysql_fetch",
    "mysqli_",
    "sql syntax",
    "mariadb server version",
    "supplied argument is not a valid mysql",
    "division by zero",
    "duplicate entry",
    "xpath syntax error",
    "the used select statements have a different number of columns",
    "column count doesn't match",
)

# Time-based 기준 — rules_sqli.py 의 _SLEEP 과 짝. (_SLEEP - 0.5 여유 권장)
SLEEP_THRESHOLD = 2.5   # 공격 응답이 이 값(초) 이상이어야 지연으로 인정
DELAY_MARGIN = 2.0      # baseline 대비 최소 추가 지연(초) — 원래 느린 페이지 오탐 방지 (_SLEEP=3 기준)
MIN_REPEAT_CONFIRM = 2

# Error-based 정보추출 마커 — 값 양쪽을 이 구분자로 감싸 응답에서 추출. hex 0x7e7e.
EXTRACT_MARKER = "~~"


@dataclass
class SqliVerdict:
    vulnerable: bool
    confidence: str
    evidence: str
    # "vulnerable" | "error_exposed" | "safe"
    final_status: str = "vulnerable"


_MIN_STRIP_LEN = 4


# 응답 본문에서 payload/입력값 반사분을 제거 (동적 diff 비교 시 반사 노이즈 제거용)
def _strip_value(body: str, value: str) -> str:
    if not value:
        return body
    variants = {value, quote(value), html.escape(value), html.escape(quote(value))}
    for v in variants:
        if v and len(v) >= _MIN_STRIP_LEN:
            body = body.replace(v, "")
    return body


def _strip_dynamic(body: str, markers: list[tuple[str, str]]) -> str:
    for prefix, suffix in markers:
        if not prefix or not suffix:
            continue
        pattern = re.escape(prefix) + r".*?" + re.escape(suffix)
        body = re.sub(pattern, prefix + suffix, body, flags=re.DOTALL)
    return body


def judge_union_sqli(baseline_body: str, attack_body: str) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()
    for kw in UNION_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(True, "medium", f"UNION-based SQLi: 컬럼 수 불일치 에러 노출 ('{kw}')")
    return SqliVerdict(False, "", "UNION 에러 시그니처 없음")


# 마커로 감싼 값이 공격 응답에만 있고 baseline엔 없으면 그 값을 반환 (정보추출 근거)
def _extract_marked_value(baseline_body: str, attack_body: str, marker: str) -> str | None:
    if not marker:
        return None
    m = re.escape(marker)
    pattern = re.compile(m + r"(.+?)" + m, re.DOTALL)
    for match in pattern.finditer(attack_body):
        if match.group(0) not in baseline_body:
            return match.group(1)
    return None


# Error-based 3분기: 마커 노출→vulnerable / DB에러만→error_exposed / 그 외→safe. 기본 structural.
def judge_error_based_sqli(
    baseline_body: str,
    attack_body: str,
    *,
    extract_marker: str = EXTRACT_MARKER,
    judgment: str = "structural",
) -> SqliVerdict:
    base_lower   = (baseline_body or "").lower()
    attack_lower = (attack_body or "").lower()

    # 1) extraction만 마커 확인
    if judgment == "extraction":
        value = _extract_marked_value(baseline_body or "", attack_body or "", extract_marker)
        if value is not None:
            return SqliVerdict(
                True, "high",
                f"Error-based SQLi (정보추출): 마커 {extract_marker}로 감싼 값 '{value}' 이 공격 응답에만 노출",
                final_status="vulnerable",
            )

    # 2) baseline엔 없던 DB 에러만 → error_exposed
    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw not in base_lower:
            return SqliVerdict(
                False, "low",
                f"Error-based 신호 (정보추출 미확인): baseline에 없던 DB 에러 노출 ('{kw}')",
                final_status="error_exposed",
            )

    # 3) baseline에도 DB 에러 → 정상 동작
    for kw in DB_ERROR_KEYWORDS:
        if kw in attack_lower and kw in base_lower:
            return SqliVerdict(
                False, "", f"DB 에러 문구가 baseline에도 있음 — 이 페이지의 정상 동작 ('{kw}')",
                final_status="safe",
            )

    return SqliVerdict(False, "", "DB 에러·마커 시그니처 없음", final_status="safe")


def judge_time_based_sqli(baseline_elapsed: float, attack_elapsed_list: list[float]) -> SqliVerdict:

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
