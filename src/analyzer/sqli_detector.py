from __future__ import annotations

from difflib import SequenceMatcher

from .finding import Finding
from .sqli.judge import (
    MIN_REPEAT_CONFIRM,
    judge_error_based_sqli,
    judge_time_based_sqli,
    judge_union_sqli,
    _strip_dynamic,
    _strip_value,
)

# Boolean 판정 문턱
_TRUE_GATE = 0.85
_GATE_MARGIN = 0.05
_STATIC_EPS = 0.002


def _successful(result: dict | None) -> bool:
    return bool(result) and result.get("status") == "ok"


def _body(result: dict | None) -> str:
    if result is None or not _successful(result):
        return ""
    return result.get("response_body") or ""


def _finding(family: dict, result: dict, confidence: str, evidence: str) -> Finding:
    case = result.get("case") or {}
    return Finding(
        vuln_type="sqli",
        family_id=family.get("family_id"),
        target_id=family.get("target_id"),
        param=family.get("param"),
        attack_id=family.get("attack_id"),
        technique=family.get("technique"),
        case_id=case.get("case_id"),
        method=case.get("method"),
        url=case.get("url"),
        location=case.get("body_type"),
        payload=case.get("payload"),
        raw_verdict={"vulnerable": True, "confidence": confidence, "evidence": evidence},
        headless_checked=False,
        headless_verdict=None,
        final_status="vulnerable",
    )


def _payload_of(mutation: dict) -> str:
    return str((mutation.get("case") or {}).get("payload") or "")


def _clean_body(family: dict, result: dict | None) -> str:
    # 응답에서 payload 반사분 + 이 타겟이 원래 흔들리는 자리(dynamic_markers)를 제거해 diff 비교의 노이즈를 걷어냄
    body = _strip_value(_body(result), _payload_of(result or {}))
    return _strip_dynamic(body, family.get("dynamic_markers") or [])


def _analyze_boolean(family: dict) -> list[Finding]:
    base_clean = _clean_body(family, family.get("baseline"))
    true_results = []
    false_results = []
    for mutation in family.get("mutations", []):
        if not _successful(mutation):
            continue
        step = str((mutation.get("case") or {}).get("step") or "")
        if step == "true_attack":
            true_results.append(mutation)
        elif step == "false_attack":
            false_results.append(mutation)

    if not base_clean or not true_results or not false_results:
        return []


    baseline_match_ratio = family.get("baseline_match_ratio")
    true_gate = max(0.0, baseline_match_ratio - _GATE_MARGIN) if baseline_match_ratio is not None else _TRUE_GATE


    hits: list[tuple[dict, float, float, float]] = []  # (true_result, gap, true_score, false_score)
    for true_result in true_results:
        # 같은 주입 스타일의 false 짝 찾기 — payload 문자열이 가장 유사한 것 (1=1 ↔ 1=2 차이만)
        true_payload = _payload_of(true_result)
        false_result = max(
            false_results,
            key=lambda f: SequenceMatcher(None, true_payload, _payload_of(f)).ratio(),
        )
        true_score = SequenceMatcher(None, base_clean, _clean_body(family, true_result)).ratio()
        false_score = SequenceMatcher(None, base_clean, _clean_body(family, false_result)).ratio()


        hi = max(true_score, false_score)
        lo = min(true_score, false_score)

        # (1) 게이트
        if hi < true_gate:
            continue
        # (2) noise-aware 문턱
        noise = 1.0 - hi
        threshold = hi - max(noise, _STATIC_EPS)
        gap = hi - lo
        if lo < threshold:
            hits.append((true_result, gap, true_score, false_score))

    if not hits:
        return []

    best_result, best_gap, best_true_score, best_false_score = max(hits, key=lambda h: h[1])
    confirmed = len(hits) >= MIN_REPEAT_CONFIRM
    confidence = "high" if confirmed else "medium"
    status = "confirmed" if confirmed else "suspected, 재현성 부족 - 추가 검증 필요"
    evidence = (
        f"Boolean SQLi ({status}): true/false 응답 분기, "
        f"{len(hits)}/{len(true_results)}개 injection 스타일에서 재현 "
        f"(true={best_true_score:.3f}, false={best_false_score:.3f}, gap={best_gap:.3f})"
    )
    return [_finding(family, best_result, confidence, evidence)]


def _analyze_sqli(family: dict) -> list[Finding]:
    technique = str(family.get("technique") or "")
    if technique.startswith("boolean"):
        return _analyze_boolean(family)

    # order_by 는 ORDER BY <큰수> payload가 컬럼 에러를 유발 → 아래 error-based 판정기로 처리
    baseline = family.get("baseline") or {}
    baseline_body = _body(baseline)
    baseline_elapsed = float(baseline.get("elapsed") or 0.0)
    mutations = [item for item in family.get("mutations", []) if _successful(item)]
    if technique.startswith("time"):
        elapsed = [float(item.get("elapsed") or 0.0) for item in mutations]
        verdict = judge_time_based_sqli(baseline_elapsed, elapsed)
        if verdict.vulnerable and mutations:
            slowest = max(mutations, key=lambda item: float(item.get("elapsed") or 0.0))
            return [_finding(family, slowest, verdict.confidence, verdict.evidence)]
        return []

    # union → 컬럼 수 불일치 에러, 그 외(error_meta·order_by 등) → DB 에러 시그니처로 판정.
    # order_by 는 "ORDER BY {큰수}" 가 Unknown column 에러를 유발하므로 error 판정기로 낙하한다.
    judge = judge_union_sqli if technique == "union" else judge_error_based_sqli
    for mutation in mutations:
        verdict = judge(baseline_body, _body(mutation))
        if verdict.vulnerable:
            return [_finding(family, mutation, verdict.confidence, verdict.evidence)]
    return []


def analyze_family(family: dict) -> list[Finding]:
    if not _successful(family.get("baseline")):
        return []
    if str(family.get("vuln_type") or "").lower() == "sqli":
        return _analyze_sqli(family)
    return []
