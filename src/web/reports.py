import json
import re
from pathlib import Path
from utilities.file_utils import load_json
from web.runs import run_metadata
from attack_requests import RULES
from metrics import HIGH, MEDIUM, LOW, INCONCLUSIVE, _STAGE_PROGRESS, build_points, compute

_CATEGORY_BY_TECHNIQUE = {rule["technique"]: rule["category"] for rule in RULES}

# 화면 나열 순서 (높음, 관찰, 미확인, 판단 보류)
_STATUS_ORDER = [HIGH, MEDIUM, LOW, INCONCLUSIVE]
_VULN_TYPES = ("xss", "sqli")


# technique -> 결과 상세 옆에 표시할 카테고리 이름
def _technique_category(technique):
    # 정의에 없는 값(레거시 데이터 등)은 technique 이름을 그대로 노출
    return _CATEGORY_BY_TECHNIQUE.get(technique, technique)


# JSONL 레코드 조회와 불완전한 마지막 줄 제외
def read_jsonl(path):
    if not path.is_file():
        return
    with path.open(encoding="utf-8") as stream:
        for line in stream:
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    yield item
            except json.JSONDecodeError:
                continue


# 요청 실패와 판정 오류 목록 (오류 상세 패널용)
def _collect_errors(directory, target_info):
    errors, error_keys, family_urls = [], set(), {}

    # 동일 오류의 중복 집계 방지
    def add_error(item):
        stage = item.get("stage", "request")
        case_id = item.get("case_id")
        if stage == "baseline":
            match = re.match(r"^(.*__occ\d+)_", case_id or item.get("family_id") or "")
            case_id = match.group(1) if match else None
        elif not case_id and not item.get("family_id"):
            errors.append(item)
            return
        else:
            case_id = case_id or item.get("family_id")
        key = (item.get("target_id"), item.get("param"), stage, case_id, item.get("error"))
        if key not in error_keys:
            error_keys.add(key)
            errors.append(item)

    for family in read_jsonl(directory / "request_results.jsonl"):
        fid = family.get("family_id")
        if not fid:
            continue
        baseline = family.get("baseline") or {}
        target = target_info.get(family.get("target_id"), {})
        family_urls[fid] = target.get("url") or (baseline.get("case") or {}).get("url")
        for result in [baseline, *(family.get("mutations") or [])]:
            if (result.get("send_status") or result.get("status")) != "error":  # 옛 결과 폴더는 status 이름 사용
                continue
            add_error({"target_id": family.get("target_id"), "param": family.get("param"),
                       "family_id": fid, "case_id": (result.get("case") or {}).get("case_id"),
                       "url": family_urls[fid], "stage": "baseline" if result is baseline else "request",
                       "error": result.get("error") or "요청 실패"})

    for finding in read_jsonl(directory / "findings.jsonl"):
        if finding.get("status") == "error":
            url = (target_info.get(finding.get("target_id"), {}).get("url")
                   or family_urls.get(finding.get("family_id")) or finding.get("url") or "")
            add_error({**finding, "url": url})
    return errors


# 판정 기록 하나와 같은 case_id의 시도 결과를 합친 근거 카드
def _finding_card(finding, attempt):
    case = attempt.get("case") or {}
    technique = finding.get("technique")
    hv = finding.get("headless_verdict") or {}
    return {
        "case_id": finding.get("case_id") or case.get("case_id"),
        "final_status": finding["final_status"],
        "technique": technique,
        # 서버 반사로 발화한 DOM 쿼리 결과는 Reflected로 표시 (technique은 dom 유지)
        "category": ("reflected (DOM 쿼리 payload)" if finding.get("server_reflected")
                     else _technique_category(technique) if technique else None),
        "progress_status": attempt.get("progress_status") or _STAGE_PROGRESS.get(finding.get("stage")),
        "reason": attempt.get("reason") or finding.get("reason"),  # 먼저 발생한 시도 단계 사유 우선
        "reason_note": attempt.get("reason_note") or finding.get("reason_note"),
        "payload": finding.get("payload") or case.get("payload"),
        "exec_token": case.get("exec_token"),
        "browser": {"executed": hv.get("executed"), "evidence": hv.get("evidence")} if finding.get("headless_checked") else None,
        "probe_marker": finding.get("probe_marker"),
        "revisit_url": finding.get("revisit_url") or attempt.get("revisit_url_used"),
        "revisit_found": attempt.get("revisit_found"),
        "evidence": finding.get("evidence") or finding.get("sink_note") or (finding.get("raw_verdict") or {}).get("evidence") or "",
        "raw": finding,
    }


# 판정 없이 사유만 남은 시도 카드 (실패, 미실행, 준비 실패)
def _attempt_card(attempt):
    case = attempt.get("case") or {}
    return {
        "case_id": case.get("case_id"),
        "final_status": None,
        "technique": None,
        "category": attempt.get("stage"),
        "progress_status": attempt.get("progress_status"),
        "reason": attempt.get("reason"),
        "reason_note": attempt.get("reason_note") or attempt.get("error"),
        "payload": case.get("payload"),
        "exec_token": case.get("exec_token"),
        "browser": None, "probe_marker": None, "revisit_url": None, "revisit_found": None,
        "evidence": "",
        "raw": {k: v for k, v in attempt.items() if "body" not in k and k != "response_headers"},  # 응답 본문은 화면에 안 보냄
    }


def _cards(point):
    attempts = {a["case"]["case_id"]: a for a in point["attempts"] if (a.get("case") or {}).get("case_id")}
    cards = [_finding_card(f, attempts.get(f.get("case_id")) or {}) for f in point["findings"]]
    judged = {f.get("case_id") for f in point["findings"]}
    cards += [_attempt_card(a) for a in point["attempts"]
              if a.get("reason") and ((a.get("case") or {}).get("case_id") not in judged or not a.get("case"))]
    order = {s: i for i, s in enumerate(_STATUS_ORDER)}
    return sorted(cards, key=lambda c: order.get(c["final_status"], len(order)))


# 검사 지점 단위 보고서 (지점 판정과 지표는 metrics.py와 같은 계산)
def build_report(out_dir):
    directory = Path(out_dir)
    targets = load_json(str(directory / "scan_targets.json"), default=[]) or []
    target_info = {f"t{i}": t for i, t in enumerate(targets)}
    points, reason_counts, totals = build_points(str(directory), targets)
    summary = compute(points, reason_counts, totals)

    groups = []
    for (target_id, location, param, value_index, vuln_type), p in points.items():
        groups.append({
            "target_id": target_id, "url": p["url"] or "", "method": target_info.get(target_id, {}).get("method") or "",
            "param": param, "location": location, "value_index": value_index, "vuln_type": vuln_type,
            "final_status": p["verdict"], "progress_status": p["progress_status"], "reason": p["reason"],
            "discovery_filtered": p["discovery_filtered"], "items": _cards(p),
        })

    errors = _collect_errors(directory, target_info)
    counts = summary["by_verdict"]
    return {"groups": groups, "errors": errors, "counts": counts, "error_count": len(errors),
            "statuses": [s for s in _STATUS_ORDER if counts.get(s)],
            "filter_groups": [v for v in _VULN_TYPES if any(g["vuln_type"] == v for g in groups)],
            "rates": {"points": summary["points"], "completion": summary["completion_rate"],
                      "inconclusive": summary["inconclusive_rate"], "silent_negatives": summary["silent_negatives"]},
            "meta": run_metadata(directory)}
