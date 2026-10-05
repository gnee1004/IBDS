# 검사 지점 단위 완료율, 판단보류율, 침묵 음성, 오귀속 양성 집계 
import argparse
import csv
import json
import os
import re
import sys

_SRC_ROOT = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC_ROOT)
sys.path.insert(0, _SRC_ROOT)

from utilities.file_utils import save_json
from web.runs import latest_out_dir

# 임시 정의 — 10/6 회의에서 정책 문서 기준으로 확정 후 수정, 판정이 여러 개면 가장 높은 것을 지점 판정으로 사용
_VERDICT_RANK = {"potential_high": 3, "potential_medium": 2, "potential_low": 1, "inconclusive": 0}
_SILENT_NEGATIVE_VERDICTS = {"potential_low"}  # 실제 취약인데 이 판정이면 침묵 음성 ("검사 완료, 근거 없음"으로 조용히 놓침)
_POSITIVE_VERDICTS = {"potential_high"}        # 오귀속 양성 검사 대상 판정
# findings만 있고 시도 결과가 없는 기록의 진행 상태 (stage별)
_STAGE_PROGRESS = {"probe": "partial", "stop": "partial", "request": "failed",
                   "route": "failed", "xss_prepare": "failed", "sqli_prepare": "failed", "judge": "partial"}


# JSONL 로드 (없으면 빈 리스트, 기록 도중 끊긴 마지막 줄 무시)
def _load_jsonl(path):
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


# 검사 지점 식별 키 — 대상·위치·파라미터·순번·취약점 종류
def _point_key(rec):
    return (rec.get("target_id"), rec.get("location"), rec.get("param"), rec.get("value_index"), rec.get("vuln_type"))


# 시도 하나의 진행 상태 (progress_status 없는 옛 결과는 전송 성공 여부로 대체)
def _case_progress(case_result):
    if case_result.get("progress_status"):
        return case_result["progress_status"]
    send = case_result.get("send_status") or case_result.get("status")
    return "completed" if send == "ok" else "failed"


# 여러 진행 상태를 지점 하나의 진행 상태로 합침 — 전부 같으면 그 값, 섞이면 부분 완료
def _merge_progress(statuses):
    unique = set(statuses)
    if not unique:
        return "not_run"
    return unique.pop() if len(unique) == 1 else "partial"


# 결과 폴더를 검사 지점 단위로 묶음: {키: {progress: [...], verdicts: [...], reasons: [...], url}}
def build_points(out_dir):
    points = {}
    family_keys = {}  # family_id -> 지점 키 (XSS 판정의 location은 요청 방식이라 family 쪽 키를 따름)

    def point(key):
        return points.setdefault(key, {"progress": [], "verdicts": [], "reasons": [], "url": None})

    for fam in _load_jsonl(os.path.join(out_dir, "request_results.jsonl")):
        family_keys[fam.get("family_id")] = _point_key(fam)
        p = point(_point_key(fam))
        # 진행 상태는 공격 시도 기준 — 기준 요청 실패는 orchestrator가 이미 공격 시도에 baseline_failed로 반영
        for cr in fam.get("mutations") or [fam.get("baseline") or {}]:
            p["progress"].append(_case_progress(cr))
            if cr.get("reason"):
                p["reasons"].append(cr["reason"])
        p["url"] = p["url"] or (fam.get("baseline") or {}).get("case", {}).get("url")

    for fd in _load_jsonl(os.path.join(out_dir, "findings.jsonl")):
        p = point(family_keys.get(fd.get("family_id")) or _point_key(fd))
        if fd.get("final_status"):
            p["verdicts"].append(fd["final_status"])
        if fd.get("reason"):
            p["reasons"].append(fd["reason"])
        if fd.get("stage") in _STAGE_PROGRESS:  # 판정 대신 남은 중단·실패 기록도 지점 진행 상태에 반영
            p["progress"].append(_STAGE_PROGRESS[fd["stage"]])
        p["url"] = p["url"] or fd.get("url")

    for p in points.values():
        p["progress_status"] = _merge_progress(p["progress"])
        # 판정이 하나도 없으면 판단보류 — 집계에서 지점이 사라지지 않게
        p["verdict"] = max(p["verdicts"], key=lambda v: _VERDICT_RANK.get(v, 0), default="inconclusive")
    return points


# 정답표 로드 — 열: url_pattern, vuln_type, param(비우면 전체), vulnerable(true/false)
def load_truth(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return [dict(pattern=re.compile(r["url_pattern"]), vuln_type=r["vuln_type"].strip(),
                     param=(r.get("param") or "").strip(), vulnerable=r["vulnerable"].strip().lower() == "true")
                for r in csv.DictReader(f) if r.get("url_pattern") and not r["url_pattern"].startswith("#")]


# 지점에 해당하는 정답 행 목록
def _truth_for(key, p, truth):
    _, _, param, _, vuln_type = key
    return [t for t in truth
            if t["vuln_type"] == vuln_type and (not t["param"] or t["param"] == param)
            and p["url"] and t["pattern"].search(p["url"])]


# 지표 계산
def compute(points, truth=None):
    total = len(points)
    by_progress = {s: 0 for s in ("completed", "partial", "failed", "not_run")}
    by_verdict = {v: 0 for v in _VERDICT_RANK}
    reasons = {}
    for p in points.values():
        by_progress[p["progress_status"]] = by_progress.get(p["progress_status"], 0) + 1
        by_verdict[p["verdict"]] = by_verdict.get(p["verdict"], 0) + 1
        for r in set(p["reasons"]):
            reasons[r] = reasons.get(r, 0) + 1

    result = {
        "points": total,
        "completion_rate": round(by_progress["completed"] / total, 3) if total else 0.0,
        "inconclusive_rate": round(by_verdict["inconclusive"] / total, 3) if total else 0.0,
        "by_progress": by_progress,
        "by_verdict": by_verdict,
        "reasons": dict(sorted(reasons.items(), key=lambda kv: -kv[1])),
        "silent_negatives": None,
        "misattributed_positives": None,
    }
    if truth is None:
        return result

    silent, misattributed, unknown_positive = [], [], []
    for key, p in points.items():
        rows = _truth_for(key, p, truth)
        real = any(t["vulnerable"] for t in rows)
        if real and p["verdict"] in _SILENT_NEGATIVE_VERDICTS:
            silent.append(key)
        if p["verdict"] in _POSITIVE_VERDICTS:
            if not rows:
                unknown_positive.append(key)  # 정답표 밖 지점 — 오귀속인지 판단 불가
            elif not real:
                misattributed.append(key)
    result.update(silent_negatives=len(silent), misattributed_positives=len(misattributed),
                  positives_without_truth=len(unknown_positive),
                  silent_negative_points=[list(k) for k in silent],
                  misattributed_points=[list(k) for k in misattributed])
    return result


def main():
    parser = argparse.ArgumentParser(description="검사 지점 단위 집계")
    parser.add_argument("out_dir", nargs="?", help="결과 폴더 (생략 시 최신)")
    parser.add_argument("--truth", help="정답표 CSV (url_pattern,vuln_type,param,vulnerable)")
    args = parser.parse_args()

    out_dir = args.out_dir or latest_out_dir(_PROJECT_ROOT)
    if out_dir is None:
        sys.exit("[ERROR] results/collection_* 폴더 없음")
    out_dir = str(out_dir)

    truth = load_truth(args.truth) if args.truth else None
    m = compute(build_points(out_dir), truth)
    save_json(os.path.join(out_dir, "metrics.json"), m)

    print(f"[METRICS] 결과 폴더: {out_dir}")
    print(f"검사 지점 {m['points']}개 | 완료율 {m['completion_rate']:.1%} | 판단보류율 {m['inconclusive_rate']:.1%}")
    print(f"진행 상태: {m['by_progress']}")
    print(f"판정: {m['by_verdict']}")
    print(f"사유: {m['reasons']}")
    if truth is None:
        print("침묵 음성·오귀속 양성: 정답표 없음, 계산 생략 (--truth 지정)")
    else:
        print(f"침묵 음성 {m['silent_negatives']}건 | 오귀속 양성 {m['misattributed_positives']}건 "
              f"| 정답표 밖 양성 {m['positives_without_truth']}건")
    print(f"[METRICS] metrics.json -> {os.path.join(out_dir, 'metrics.json')}")


if __name__ == "__main__":
    main()
