# 검사 지점 집계와 채점 지표 계산, python src/metrics.py [결과 폴더] [--truth 정답표.csv]
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

HIGH, MEDIUM, LOW, INCONCLUSIVE = "potential_high", "potential_medium", "potential_low", "inconclusive"
_RANK = {HIGH: 3, MEDIUM: 2, LOW: 1, INCONCLUSIVE: 0}
PROGRESS_STATUSES = ("completed", "partial", "failed", "not_run")
# findings에만 남은 기록의 진행 상태
_STAGE_PROGRESS = {"probe": "partial", "judge": "partial", "stop": "not_run", "request": "failed",
                   "route": "failed", "xss_prepare": "failed", "sqli_prepare": "failed"}


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


def _point_key(rec, vuln_type=None):
    return (rec.get("target_id"), rec.get("location"), rec.get("param"), rec.get("value_index"),
            vuln_type or rec.get("vuln_type"))


# progress_status 없는 옛 결과는 전송 성공 여부로 대체
def _case_progress(case_result):
    if case_result.get("progress_status"):
        return case_result["progress_status"]
    send = case_result.get("send_status") or case_result.get("status")
    return "completed" if send == "ok" else "failed"


def _merge_progress(statuses):
    unique = set(statuses)
    if not unique:
        return "not_run"
    return unique.pop() if len(unique) == 1 else "partial"


# 미확인은 모든 시도가 완료된 지점에만 허용
def _point_verdict(verdicts, progress_status):
    if HIGH in verdicts:
        return HIGH
    if MEDIUM in verdicts:
        return MEDIUM
    if LOW in verdicts and progress_status == "completed":
        return LOW
    return INCONCLUSIVE


def _new_point():
    return {"progress": [], "verdicts": [], "reasons": [], "case_ids": [], "url": None,
            "discovery_filtered": None, "discovery_filtered_reasons": None,
            "request_count": None, "browser_runs": None}


def build_points(out_dir):
    points = {}
    family_keys = {}      # XSS 판정의 location은 요청 방식이라 family_id로 지점을 찾음
    reason_counts = {}
    attempt_reason = {}   # 판정 쪽 사유 중복 집계 방지

    def count_reason(reason):
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    for fam in _load_jsonl(os.path.join(out_dir, "request_results.jsonl")):
        key = _point_key(fam)
        family_keys[fam.get("family_id")] = key
        p = points.setdefault(key, _new_point())
        # baseline은 공격 시도로 세지 않음
        for cr in fam.get("mutations") or [fam.get("baseline") or {}]:
            case_id = (cr.get("case") or {}).get("case_id")
            p["progress"].append(_case_progress(cr))
            p["case_ids"].append(case_id)
            if cr.get("reason"):
                p["reasons"].append(cr["reason"])
                attempt_reason[case_id] = cr["reason"]
                count_reason(cr["reason"])
        p["url"] = p["url"] or (fam.get("baseline") or {}).get("case", {}).get("url")

    for fd in _load_jsonl(os.path.join(out_dir, "findings.jsonl")):
        key = family_keys.get(fd.get("family_id")) or _point_key(fd)
        p = points.setdefault(key, _new_point())
        if fd.get("final_status"):
            p["verdicts"].append(fd["final_status"])
        if fd.get("stage") in _STAGE_PROGRESS:
            p["progress"].append(_STAGE_PROGRESS[fd["stage"]])
        if fd.get("reason") and fd.get("case_id") not in attempt_reason:
            p["reasons"].append(fd["reason"])
            count_reason(fd["reason"])
        p["url"] = p["url"] or fd.get("url")

    # metrics.jsonl은 vuln_type 없이 지점당 한 줄
    totals = {"request_count": 0, "browser_runs": 0, "discovery_filtered": 0}
    for mr in _load_jsonl(os.path.join(out_dir, "metrics.jsonl")):
        for name in totals:  # sqli, xss 지점에 같은 값이 붙어 합계는 원본 줄에서 셈
            totals[name] += mr.get(name) or 0
        xss_key = _point_key(mr, vuln_type="xss")
        if xss_key not in points and mr.get("discovery_filtered"):
            # Discovery가 전부 거른 지점은 완료와 미확인으로 기록
            points[xss_key] = _new_point()
            points[xss_key]["progress"].append("completed")
            points[xss_key]["verdicts"].append(LOW)
        for key, p in points.items():
            if key[:4] == xss_key[:4]:
                p["request_count"] = mr.get("request_count")
                p["browser_runs"] = mr.get("browser_runs")
                if key == xss_key:
                    p["discovery_filtered"] = mr.get("discovery_filtered")
                    p["discovery_filtered_reasons"] = mr.get("discovery_filtered_reasons")

    for p in points.values():
        p["progress_status"] = _merge_progress(p["progress"])
        p["raw_verdict"] = max(p["verdicts"], key=lambda v: _RANK.get(v, 0), default=INCONCLUSIVE)
        p["verdict"] = _point_verdict(p["verdicts"], p["progress_status"])
        p["reason"] = p["reasons"][0] if p["reasons"] else None  # 가장 먼저 발생한 사유가 대표
    return points, reason_counts, totals


# param을 비우면 전체 파라미터
def load_truth(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return [dict(pattern=re.compile(r["url_pattern"]), vuln_type=r["vuln_type"].strip(),
                     param=(r.get("param") or "").strip(), vulnerable=r["vulnerable"].strip().lower() == "true")
                for r in csv.DictReader(f) if r.get("url_pattern") and not r["url_pattern"].startswith("#")]


def _truth_matches(t, key, p):
    return (t["vuln_type"] == key[4] and (not t["param"] or t["param"] == key[2])
            and bool(p["url"]) and bool(t["pattern"].search(p["url"])))


def _rate(num, den):
    return round(num / den, 3) if den else 0.0


def compute(points, reason_counts, totals, truth=None):
    by_progress = {s: 0 for s in PROGRESS_STATUSES}
    by_verdict = {v: 0 for v in _RANK}
    silent = []
    for key, p in points.items():
        by_progress[p["progress_status"]] = by_progress.get(p["progress_status"], 0) + 1
        by_verdict[p["verdict"]] += 1
        if p["progress_status"] != "completed" and p["raw_verdict"] == LOW:
            silent.append(key)  # 미완료인데 미확인으로 기록된 지점

    collection_missed = 0
    if truth is not None:
        collection_missed = sum(1 for t in truth if not any(_truth_matches(t, k, p) for k, p in points.items()))
    intended = len(points) + collection_missed  # 수집 실패는 분모에서 빼지 않음

    result = {
        "points": len(points),
        "collection_missed": collection_missed if truth is not None else None,
        "intended_points": intended,
        "completion_rate": _rate(by_progress["completed"], intended),
        "inconclusive_rate": _rate(by_verdict[INCONCLUSIVE], intended),
        "silent_negatives": len(silent),
        "silent_negative_points": [list(k) for k in silent],
        "by_progress": by_progress,
        "by_verdict": by_verdict,
        "reasons": dict(sorted(reason_counts.items(), key=lambda kv: -kv[1])),
        **totals,
    }
    if truth is None:
        return result

    # 판단 보류는 TP, FN, FP, TN에 넣지 않고 따로 셈
    score = {"TP": 0, "FN": 0, "FP": 0, "TN": 0, "inconclusive_real": 0, "inconclusive_safe": 0, "no_truth": 0}
    misattributed = []
    for key, p in points.items():
        rows = [t for t in truth if _truth_matches(t, key, p)]
        if not rows:
            score["no_truth"] += 1
            continue
        real = any(t["vulnerable"] for t in rows)
        if p["verdict"] == INCONCLUSIVE:
            score["inconclusive_real" if real else "inconclusive_safe"] += 1
        elif p["verdict"] == HIGH:
            score["TP" if real else "FP"] += 1
            if not real:
                misattributed.append(key)
        else:
            score["FN" if real else "TN"] += 1

    highs = score["TP"] + score["FP"]
    inconclusive = score["inconclusive_real"] + score["inconclusive_safe"]
    result.update(
        score=score,
        detection_rate=_rate(score["TP"], score["TP"] + score["FN"]),
        detection_rate_inconclusive_as_fn=_rate(score["TP"], score["TP"] + score["FN"] + score["inconclusive_real"]),
        misattributed_positives=len(misattributed),
        misattributed_points=[list(k) for k in misattributed],
        high_error_rate=_rate(score["FP"], highs),
        inconclusive_real_ratio=_rate(score["inconclusive_real"], inconclusive),
    )
    return result


def point_rows(points, run_id):
    rows = []
    for key, p in points.items():
        target_id, location, param, value_index, vuln_type = key
        rows.append({
            "run_id": run_id,
            "scan_point_id": f"{target_id}_{location}_{param}__occ{value_index}",
            "target_id": target_id, "location": location, "param": param, "value_index": value_index,
            "vuln_type": vuln_type, "url": p["url"],
            "progress_status": p["progress_status"], "final_status": p["verdict"], "reason": p["reason"],
            "case_ids": [c for c in p["case_ids"] if c],
            "discovery_filtered": p["discovery_filtered"],
            "discovery_filtered_reasons": p["discovery_filtered_reasons"],
            "request_count": p["request_count"], "browser_runs": p["browser_runs"],
        })
    return rows


def main():
    parser = argparse.ArgumentParser(description="검사 지점 단위 집계")
    parser.add_argument("out_dir", nargs="?", help="결과 폴더, 생략하면 최신 폴더")
    parser.add_argument("--truth", help="정답표 CSV, 열은 url_pattern,vuln_type,param,vulnerable")
    args = parser.parse_args()

    out_dir = args.out_dir or latest_out_dir(_PROJECT_ROOT)
    if out_dir is None:
        sys.exit("[ERROR] results/collection_* 폴더 없음")
    out_dir = str(out_dir)
    run_id = os.path.basename(os.path.normpath(out_dir))

    truth = load_truth(args.truth) if args.truth else None
    points, reason_counts, totals = build_points(out_dir)
    m = compute(points, reason_counts, totals, truth)
    m["run_id"] = run_id

    summary_path = os.path.join(out_dir, "metrics_summary.json")
    rows_path = os.path.join(out_dir, "point_results.jsonl")
    save_json(summary_path, m)
    with open(rows_path, "w", encoding="utf-8") as f:
        for row in point_rows(points, run_id):
            f.write(json.dumps(row, ensure_ascii=False) + "\n")

    print(f"[METRICS] run_id: {run_id}")
    print(f"검사 지점 {m['points']}개 | 완료율 {m['completion_rate']:.1%} | 검토 필요율 {m['inconclusive_rate']:.1%} "
          f"| 침묵 음성 {m['silent_negatives']}건")
    print(f"진행 상태: {m['by_progress']}")
    print(f"판정: {m['by_verdict']}")
    print(f"사유: {m['reasons']}")
    print(f"요청 수 {m['request_count']} | 브라우저 실행 수 {m['browser_runs']} | Discovery 걸러낸 수 {m['discovery_filtered']}")
    if truth is None:
        print("정답 기반 지표: 정답표 없음, --truth로 지정")
    else:
        print(f"수집 실패 {m['collection_missed']}개 | 채점 {m['score']}")
        print(f"검출률 {m['detection_rate']:.1%} | 검토 필요를 놓침으로 본 검출률 {m['detection_rate_inconclusive_as_fn']:.1%} "
              f"| 오귀속 양성 {m['misattributed_positives']}건 | 높음 판정 오류율 {m['high_error_rate']:.1%} "
              f"| 검토 필요 내 실제 취약 비율 {m['inconclusive_real_ratio']:.1%}")
    print(f"[METRICS] {summary_path}")
    print(f"[METRICS] {rows_path}")


if __name__ == "__main__":
    main()
