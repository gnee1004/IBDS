# OWASP Benchmark 채점, python test/benchmark_backup/benchmark_score.py [결과 폴더] [--exclude 범위밖.txt]
import argparse
import csv
import json
import os
import re
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.join(_PROJECT_ROOT, "src"))  # metrics, web.runs, param_filter import용

from metrics import HIGH, MEDIUM, LOW, INCONCLUSIVE, build_points
from scan.normalize.param_filter import has_destructive_action
from web.runs import latest_out_dir

_EXPECTED_CSV = os.path.join(_HERE, "benchmark_expected.csv")  # expectedresults-1.2.csv 복사본
_CATEGORIES = ("sqli", "xss")  # 정답표 카테고리 = 판정기 vuln_type
_TEST_RE = re.compile(r"BenchmarkTest(\d{5})")
_STRICT = {HIGH}           # 엄격 기준: 높음만 취약으로 인정
_LOOSE = {HIGH, MEDIUM}    # 완화 기준: 관찰까지 취약으로 인정


# 정답표 로드: {테스트번호: (카테고리, 실제취약여부)}, sqli/xss만 유지
def load_expected(path):
    expected = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3 or row[0].startswith("#"):  # 헤더 주석 제외
                continue
            m = _TEST_RE.search(row[0])
            if m and row[1].strip() in _CATEGORIES:
                expected[m.group(1)] = (row[1].strip(), row[2].strip().lower() == "true")
    return expected


# 범위 밖 입력 경로(쿠키, 헤더 등) 테스트번호 목록, 한 줄에 하나
def load_exclude(path):
    if not path:
        return set()
    with open(path, encoding="utf-8-sig") as f:
        return {m.group(1) for line in f if not line.startswith("#") and (m := re.search(r"(\d{5})", line))}


# 테스트번호별 수집 타겟 분류: 검사 대상 target_id 집합과 정책 제외 여부
def load_targets(out_dir):
    path = os.path.join(out_dir, "scan_targets.json")
    targets = json.load(open(path, encoding="utf-8")) if os.path.exists(path) else []
    scanned, policy_only = {}, set()
    for idx, t in enumerate(targets):
        m = _TEST_RE.search(t.get("base_url") or t.get("url") or "")
        if not m or not t.get("params"):  # 파라미터 없는 페이지(DOM fragment 검사용 안내 .html)는 수집 지점 아님
            continue
        num = m.group(1)
        scannable = t.get("scannable_params")
        if has_destructive_action(t["params"]) or (scannable is not None and not scannable):
            policy_only.add(num)  # 파괴적 액션 또는 검사 가능 파라미터 없음
            continue
        scanned.setdefault(num, set()).add(f"t{idx}")
    return scanned, policy_only - set(scanned)  # 다른 타겟으로 검사된 테스트는 정책 제외 아님


# 테스트 하나의 최종 판정, 6장 규칙을 지점 묶음에 한 번 더 적용
def test_verdict(verdicts):
    if HIGH in verdicts:
        return HIGH
    if MEDIUM in verdicts:
        return MEDIUM
    if verdicts and all(v == LOW for v in verdicts):
        return LOW
    return INCONCLUSIVE


# 테스트번호와 카테고리별 지점 판정 모음
def collect_verdicts(points, scanned):
    test_of = {tid: num for num, tids in scanned.items() for tid in tids}
    verdicts = {}
    for key, p in points.items():
        target_id, vuln_type = key[0], key[4]
        num = test_of.get(target_id)
        if num:
            verdicts.setdefault((num, vuln_type), []).append(p["verdict"])
    return verdicts


def _rate(num, den):
    return round(num / den, 3) if den else 0.0


# 카테고리별 채점, 판단 보류와 수집 실패는 TP, FN, FP, TN과 별도 칸
def score(expected, scanned, policy_only, excluded, verdicts, positive):
    rows = {}
    for cat in _CATEGORIES:
        r = dict(expected=0, excluded_scope=0, excluded_policy=0, missed_real=0, missed_safe=0,
                 TP=0, FN=0, FP=0, TN=0, inconclusive_real=0, inconclusive_safe=0, no_record=0)
        for num, (c, real) in expected.items():
            if c != cat:
                continue
            r["expected"] += 1
            if num in excluded:
                r["excluded_scope"] += 1
                continue
            if num in policy_only:
                r["excluded_policy"] += 1
                continue
            if num not in scanned:
                r["missed_real" if real else "missed_safe"] += 1  # 수집 실패는 분모에 남김
                continue
            found = verdicts.get((num, cat))
            if not found:
                # Discovery가 다 거른 지점은 metrics.jsonl로 미확인이 들어오므로, 기록 없음은 검사 못 한 것
                r["no_record"] += 1
            verdict = test_verdict(found) if found else INCONCLUSIVE
            if verdict == INCONCLUSIVE:
                r["inconclusive_real" if real else "inconclusive_safe"] += 1
            elif verdict in positive:
                r["TP" if real else "FP"] += 1
            else:
                r["FN" if real else "TN"] += 1
        real_total = r["TP"] + r["FN"] + r["missed_real"]
        r.update(
            TPR=_rate(r["TP"], real_total),
            TPR_inconclusive_as_fn=_rate(r["TP"], real_total + r["inconclusive_real"]),
            FPR=_rate(r["FP"], r["FP"] + r["TN"]),
        )
        r["score"] = round(r["TPR"] - r["FPR"], 3)
        rows[cat] = r
    return rows


def main():
    parser = argparse.ArgumentParser(description="OWASP Benchmark 채점")
    parser.add_argument("out_dir", nargs="?", help="결과 폴더, 생략하면 최신 폴더")
    parser.add_argument("--expected", default=_EXPECTED_CSV, help="정답표 CSV")
    parser.add_argument("--exclude", help="범위 밖 입력 경로 테스트번호 목록, 분모에서 제외")
    args = parser.parse_args()

    if not os.path.exists(args.expected):
        sys.exit(f"[ERROR] 정답표 없음: {args.expected}")
    out_dir = args.out_dir or latest_out_dir(_PROJECT_ROOT)
    if out_dir is None:
        sys.exit("[ERROR] results/collection_* 폴더 없음")
    out_dir = str(out_dir)

    expected = load_expected(args.expected)
    excluded = load_exclude(args.exclude)
    scanned, policy_only = load_targets(out_dir)
    points, _, _ = build_points(out_dir)
    verdicts = collect_verdicts(points, scanned)

    print(f"[BENCH] 결과 폴더: {out_dir}")
    for label, positive in (("엄격(높음만)", _STRICT), ("완화(높음+관찰)", _LOOSE)):
        print(f"\n== {label} ==")
        for cat, r in score(expected, scanned, policy_only, excluded, verdicts, positive).items():
            print(f"[{cat}] 정답 {r['expected']} | 제외 범위밖 {r['excluded_scope']} 정책 {r['excluded_policy']} "
                  f"| 수집 실패 취약 {r['missed_real']} 안전 {r['missed_safe']}")
            print(f"       TP={r['TP']} FN={r['FN']} FP={r['FP']} TN={r['TN']} "
                  f"| 판단 보류 취약 {r['inconclusive_real']} 안전 {r['inconclusive_safe']} | 기록 없음 {r['no_record']}")
            print(f"       검출률 {r['TPR']} | 판단 보류를 놓침으로 본 검출률 {r['TPR_inconclusive_as_fn']} "
                  f"| 오탐률 {r['FPR']} | 점수 {r['score']}")


if __name__ == "__main__":
    main()
