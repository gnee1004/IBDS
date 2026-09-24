from __future__ import annotations

from difflib import SequenceMatcher

from .finding import Finding
from .sqli.judge import (
    EXTRACT_MARKER,
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


def _finding(family: dict, result: dict, confidence: str, evidence: str,
             final_status: str = "inconclusive") -> Finding:
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
        raw_verdict={"vulnerable": final_status == "vulnerable", "confidence": confidence, "evidence": evidence},
        headless_checked=False,
        headless_verdict=None,
        final_status=final_status,
    )


def _payload_of(mutation: dict) -> str:
    return str((mutation.get("case") or {}).get("payload") or "")


def _clean_body(family: dict, result: dict | None) -> str:
    # 응답에서 payload 반사분 + 이 타겟이 원래 흔들리는 자리(dynamic_markers)를 제거해 diff 비교의 노이즈를 걷어냄
    body = _strip_value(_body(result), _payload_of(result or {}))
    return _strip_dynamic(body, family.get("dynamic_markers") or [])


# safe·inconclusive finding의 식별 필드용 대표 case — 첫 mutation, 없으면 baseline
def _representative_result(family: dict) -> dict:
    mutations = family.get("mutations") or []
    return mutations[0] if mutations else (family.get("baseline") or {})


def _family_finding(family: dict, final_status: str, evidence: str) -> Finding:
    return _finding(family, _representative_result(family), "", evidence, final_status)


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

    # true/false 짝을 못 만들거나 baseline 비교 불가 → 검사 미완료 (safe 금지)
    if not true_results or not false_results:
        return [_family_finding(family, "inconclusive", "true/false 공격 응답 부족으로 검사 미완료")]
    if not base_clean:
        return [_family_finding(family, "inconclusive", "baseline 본문 비어 비교 불가")]


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
        return [_family_finding(family, "safe", "true/false 응답 분기 없음")]

    best_result, best_gap, best_true_score, best_false_score = max(hits, key=lambda h: h[1])
    confirmed = len(hits) >= MIN_REPEAT_CONFIRM
    confidence = "high" if confirmed else "medium"
    status = "confirmed" if confirmed else "suspected, 재현성 부족 - 추가 검증 필요"
    evidence = (
        f"Boolean SQLi ({status}): true/false 응답 분기, "
        f"{len(hits)}/{len(true_results)}개 injection 스타일에서 재현 "
        f"(true={best_true_score:.3f}, false={best_false_score:.3f}, gap={best_gap:.3f})"
    )
    return [_finding(family, best_result, confidence, evidence, "vulnerable")]


def _analyze_sqli(family: dict) -> list[Finding]:
    technique = str(family.get("technique") or "")
    if technique.startswith("boolean"):
        return _analyze_boolean(family)

    baseline = family.get("baseline") or {}
    baseline_body = _body(baseline)
    baseline_elapsed = float(baseline.get("elapsed") or 0.0)
    raw_mutations = family.get("mutations") or []
    mutations = [item for item in raw_mutations if _successful(item)]

    # 성공한 공격 응답이 없음: 공격이 있었는데 전부 전송 실패면 검사 미완료(safe 금지), 애초에 없었으면 스킵
    if not mutations:
        if raw_mutations:
            return [_family_finding(family, "inconclusive", "공격 요청 전송 실패로 검사 미완료")]
        return []

    if technique.startswith("time"):
        elapsed = [float(item.get("elapsed") or 0.0) for item in mutations]
        verdict = judge_time_based_sqli(baseline_elapsed, elapsed)
        if verdict.vulnerable:
            slowest = max(mutations, key=lambda item: float(item.get("elapsed") or 0.0))
            return [_finding(family, slowest, verdict.confidence, verdict.evidence, "vulnerable")]
        return [_family_finding(family, "safe", verdict.evidence)]

    # UNION 계열: 컬럼 수 불일치 DB 에러 시그니처가 공격 응답에만 있으면 취약, 없으면 안전 (2분기, 정보추출 없음)
    if technique == "union":
        for mutation in mutations:
            verdict = judge_union_sqli(baseline_body, _body(mutation))
            if verdict.vulnerable:
                return [_finding(family, mutation, verdict.confidence, verdict.evidence, "vulnerable")]
        return [_family_finding(family, "safe", "UNION 에러 시그니처 없음")]

    # error 계열: 마커로 값이 노출되면 vulnerable, 하나도 없으면 safe (DB 에러만 뜬 경우도 safe로 처리)
    # judgment/extract_marker 메타가 아직 룰에 안 실려서, error_extract technique면 정보추출(extraction) 판정으로 연결
    judgment = "extraction" if technique == "error_extract" else str(family.get("judgment") or "structural")
    marker = family.get("extract_marker") or EXTRACT_MARKER
    for mutation in mutations:
        verdict = judge_error_based_sqli(
            baseline_body, _body(mutation), extract_marker=marker, judgment=judgment,
            payload=_payload_of(mutation),
        )
        if verdict.final_status == "vulnerable":
            return [_finding(family, mutation, verdict.confidence, verdict.evidence, "vulnerable")]
    return [_family_finding(family, "safe", "DB 에러·마커 시그니처 없음")]


def analyze_family(family: dict) -> list[Finding]:
    if str(family.get("vuln_type") or "").lower() != "sqli":
        return []
    # baseline 전송 실패 → 비교 기준 없음 → 검사 미완료 (safe 금지)
    if not _successful(family.get("baseline")):
        return [_family_finding(family, "inconclusive", "baseline 전송 실패로 비교 불가")]
    return _analyze_sqli(family)
