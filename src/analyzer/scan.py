from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from difflib import SequenceMatcher

from utilities.file_utils import save_json
from .sqli.judge import judge_error_based_sqli, judge_time_based_sqli, judge_union_sqli, _strip_value
from .xss.judge import judge_xss

# diff 비교 시 동적 페이지 노이즈 허용 폭 (true끼리의 자기 유사도 바닥 대비)
_NOISE_MARGIN = 0.05


def _load_results(results_path: str) -> list[dict]:
    families = []
    with open(results_path, encoding="utf-8") as file:
        for line_number, line in enumerate(file, 1):
            if not line.strip():
                continue
            try:
                families.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSONL at line {line_number}: {exc}") from exc
    return families


def _successful(result: dict | None) -> bool:
    return bool(result) and result.get("status") == "ok"


def _body(result: dict | None) -> str:
    if result is None or not _successful(result):
        return ""
    return result.get("response_body") or ""


def _header(result: dict | None, name: str) -> str:
    if result is None or not _successful(result):
        return ""
    headers = result.get("response_headers") or {}
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value or ""
    return ""


def _finding(family: dict, result: dict, confidence: str, evidence: str) -> dict:
    case = result.get("case") or {}
    return {
        "family_id": family.get("family_id"),
        "target_id": family.get("target_id"),
        "vuln_type": family.get("vuln_type"),
        "technique": family.get("technique"),
        "method": case.get("method"),
        "url": case.get("url"),
        "param": family.get("param"),
        "location": case.get("body_type"),
        "payload": case.get("payload"),
        "confidence": confidence,
        "evidence": evidence,
        "response_status": result.get("response_status"),
        "elapsed": result.get("elapsed"),
        "timestamp": datetime.now().isoformat(timespec="seconds"),
    }


def _analyze_xss(family: dict) -> list[dict]:
    baseline_body = _body(family.get("baseline"))
    for mutation in family.get("mutations", []):
        if not _successful(mutation):
            continue
        payload = str((mutation.get("case") or {}).get("payload") or "")
        if not payload:
            continue
        verdict = judge_xss(_body(mutation), payload)
        baseline_verdict = judge_xss(baseline_body, payload)
        if verdict.vulnerable and not baseline_verdict.vulnerable:
            return [_finding(family, mutation, verdict.confidence, verdict.evidence)]
    return []


def _payload_of(mutation: dict) -> str:
    return str((mutation.get("case") or {}).get("payload") or "")


def _clean_body(result: dict | None) -> str:
    # 응답에서 payload 반사분을 제거해 diff 비교의 결정적 노이즈 제거
    return _strip_value(_body(result), _payload_of(result or {}))


def _analyze_boolean(family: dict) -> list[dict]:
    base_clean = _clean_body(family.get("baseline"))
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

    # true 응답들은 baseline과 논리적으로 동일 → 그 최저 유사도가 이 페이지의 노이즈 바닥(floor).
    # (user_token 등 요청마다 바뀌는 값 때문에 완전 일치가 안 되는 동적 페이지 대응)
    true_scores = [(m, SequenceMatcher(None, base_clean, _clean_body(m)).ratio()) for m in true_results]
    floor = min(score for _, score in true_scores)

    best = None
    best_gap = 0.0
    best_scores = (0.0, 0.0)
    for true_result, true_score in true_scores:
        for false_result in false_results:
            false_score = SequenceMatcher(None, base_clean, _clean_body(false_result)).ratio()
            gap = true_score - false_score
            # false가 노이즈 바닥보다 확실히 더 다를 때만 인정 (동적 노이즈로 인한 오탐 차단)
            if false_score < floor - _NOISE_MARGIN and gap > best_gap:
                best = true_result
                best_gap = gap
                best_scores = (true_score, false_score)

    if best is None:
        return []
    evidence = (
        f"Boolean SQLi: true≈baseline({best_scores[0]:.3f}), false 다름({best_scores[1]:.3f}), "
        f"floor={floor:.3f}, gap={best_gap:.3f}"
    )
    return [_finding(family, best, "high", evidence)]


def _analyze_order_by(family: dict) -> list[dict]:
    # ORDER BY 주입은 에러가 아니라 "정렬 방향 변화"로 드러남 → ASC 응답과 DESC 응답을 직접 비교
    def _payload(mutation: dict) -> str:
        return str((mutation.get("case") or {}).get("payload") or "").lower()

    asc_results = [m for m in family.get("mutations", []) if _successful(m) and " asc" in _payload(m)]
    desc_results = [m for m in family.get("mutations", []) if _successful(m) and " desc" in _payload(m)]
    for asc_result in asc_results:
        asc_body = _clean_body(asc_result)  # ASC/DESC 문자열 등 payload 반사분 제거 후 비교
        if not asc_body:
            continue
        for desc_result in desc_results:
            desc_body = _clean_body(desc_result)
            if not desc_body:
                continue
            ratio = SequenceMatcher(None, asc_body, desc_body).ratio()
            if ratio < 0.95:  # ASC≠DESC → 정렬 절이 주입에 영향받음
                evidence = f"Order-by SQLi: ASC/DESC 응답 정렬 차이 확인 (ratio={ratio:.3f})"
                return [_finding(family, asc_result, "medium", evidence)]
    return []


def _redirects_to_payload(location: str, payload: str) -> bool:
    loc = location.strip()
    payload = payload.strip()
    if not loc or not payload:
        return False
    if loc == payload or loc.startswith(payload):
        return True
    # 선행 슬래시/백슬래시 정규화 (//, ///, \\ 우회 대응)
    payload_norm = payload.lstrip("/\\")
    return bool(payload_norm) and loc.lstrip("/\\").startswith(payload_norm)


def _analyze_open_redirect(family: dict) -> list[dict]:
    base_location = _header(family.get("baseline"), "location")
    for mutation in family.get("mutations", []):
        if not _successful(mutation):
            continue
        payload = str((mutation.get("case") or {}).get("payload") or "")
        location = _header(mutation, "location")
        if not location or location == base_location:
            continue  # 리다이렉트 없음 or baseline과 동일 → 안전
        if _redirects_to_payload(location, payload):
            evidence = f"Open Redirect: Location 헤더가 공격 URL로 이동 ('{location}')"
            return [_finding(family, mutation, "high", evidence)]
    return []


def _analyze_sqli(family: dict) -> list[dict]:
    technique = str(family.get("technique") or "")
    if technique.startswith("boolean"):
        return _analyze_boolean(family)
    if technique == "order_by":
        return _analyze_order_by(family)

    baseline = family.get("baseline") or {}
    baseline_body = _body(baseline)
    baseline_elapsed = float(baseline.get("elapsed") or 0.0)
    mutations = [item for item in family.get("mutations", []) if _successful(item)]
    if technique.startswith("time") or technique == "stacked":
        elapsed = [float(item.get("elapsed") or 0.0) for item in mutations]
        verdict = judge_time_based_sqli(baseline_elapsed, elapsed)
        if verdict.vulnerable and mutations:
            slowest = max(mutations, key=lambda item: float(item.get("elapsed") or 0.0))
            return [_finding(family, slowest, verdict.confidence, verdict.evidence)]
        return []

    judge = judge_union_sqli if technique == "union" else judge_error_based_sqli
    for mutation in mutations:
        verdict = judge(baseline_body, _body(mutation))
        if verdict.vulnerable:
            return [_finding(family, mutation, verdict.confidence, verdict.evidence)]
    return []


def analyze_family(family: dict) -> list[dict]:
    if not _successful(family.get("baseline")):
        return []
    vuln_type = str(family.get("vuln_type") or "").lower()
    if vuln_type == "sqli":
        return _analyze_sqli(family)
    if vuln_type == "xss":
        return _analyze_xss(family)
    if vuln_type == "open_redirect":
        return _analyze_open_redirect(family)
    return []


def analyze_results(results_path: str) -> str:
    findings = []
    for family in _load_results(results_path):
        findings.extend(analyze_family(family))
    output_path = os.path.join(os.path.dirname(os.path.abspath(results_path)), "findings.json")
    save_json(output_path, findings)
    print(f"[ANALYZE] findings.json -> {output_path} ({len(findings)} findings)")
    return output_path


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python -m analyzer.scan <request_results.jsonl>")
    analyze_results(sys.argv[1])


if __name__ == "__main__":
    main()
