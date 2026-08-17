from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from difflib import SequenceMatcher

from utilities.file_utils import save_json
from .sqli.judge import judge_error_based_sqli, judge_time_based_sqli, judge_union_sqli, _strip_value
from .xss.judge import judge_xss

# Boolean 판정 문턱
_TRUE_GATE = 0.85    # true 응답이 baseline과 최소 이만큼 유사해야 "주입이 참으로 해석됨" (AND-true 게이트)
_STATIC_EPS = 0.002  # 정적 페이지에서 false를 "다르다"고 볼 최소 차이 (blind SQLi 대응)


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

    best = None
    best_gap = 0.0
    best_scores = (0.0, 0.0)
    for true_result in true_results:
        # 같은 주입 스타일의 false 짝 찾기 — payload 문자열이 가장 유사한 것 (1=1 ↔ 1=2 차이만)
        true_payload = _payload_of(true_result)
        false_result = max(
            false_results,
            key=lambda f: SequenceMatcher(None, true_payload, _payload_of(f)).ratio(),
        )
        true_score = SequenceMatcher(None, base_clean, _clean_body(true_result)).ratio()
        false_score = SequenceMatcher(None, base_clean, _clean_body(false_result)).ratio()

        # 방향 무관 처리 — AND 패턴은 true≈baseline·false 다름, OR 패턴은 그 반대.
        # 한쪽(hi)이 baseline과 같은 "정상 응답"이고 다른쪽(lo)이 벗어나면 boolean 분기로 본다.
        hi = max(true_score, false_score)
        lo = min(true_score, false_score)

        # (1) 게이트: 한 쪽은 baseline과 충분히 같아야 주입이 SQL 논리로 해석된 것 → 아니면 안전
        if hi < _TRUE_GATE:
            continue
        # (2) noise-aware 문턱: 정상 쪽이 baseline에서 벗어난 만큼(=페이지 노이즈)만 허용.
        #     정적 페이지(노이즈≈0)에선 아주 작은 차이도 유의미(_STATIC_EPS) → blind SQLi 커버
        noise = 1.0 - hi
        threshold = hi - max(noise, _STATIC_EPS)
        gap = hi - lo
        if lo < threshold and gap > best_gap:
            best = true_result
            best_gap = gap
            best_scores = (true_score, false_score)

    if best is None:
        return []
    evidence = (
        f"Boolean SQLi: true/false 응답 분기 (true={best_scores[0]:.3f}, "
        f"false={best_scores[1]:.3f}, gap={best_gap:.3f})"
    )
    return [_finding(family, best, "high", evidence)]


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

    # order_by 는 ORDER BY <큰수> payload가 컬럼 에러를 유발 → 아래 error-based 판정기로 처리
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
