from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from difflib import SequenceMatcher

from utilities.file_utils import save_json
from .sqli.judge import judge_error_based_sqli, judge_time_based_sqli, judge_union_sqli
from .xss.judge import judge_xss


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


def _analyze_boolean(family: dict) -> list[dict]:
    baseline_body = _body(family.get("baseline"))
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

    best = None
    best_gap = 0.0
    best_scores = (0.0, 0.0)
    for true_result in true_results:
        true_score = SequenceMatcher(None, baseline_body, _body(true_result)).ratio()
        for false_result in false_results:
            false_score = SequenceMatcher(None, baseline_body, _body(false_result)).ratio()
            gap = true_score - false_score
            if gap > best_gap:
                best = true_result
                best_gap = gap
                best_scores = (true_score, false_score)

    if best is None or best_gap < 0.05 or best_scores[0] < 0.90:
        return []
    evidence = f"Boolean SQLi: true={best_scores[0]:.3f}, false={best_scores[1]:.3f}, gap={best_gap:.3f}"
    return [_finding(family, best, "high", evidence)]


def _analyze_sqli(family: dict) -> list[dict]:
    technique = str(family.get("technique") or "")
    if technique.startswith("boolean"):
        return _analyze_boolean(family)

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
