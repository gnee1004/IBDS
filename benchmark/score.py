"""
OWASP Benchmark 채점 (로컬 실행용, 단독 — web 모듈 import 없음)

판정 변환(정책 기준):
  - potential_high (취약 가능성 높음)  -> "탐지함"
  - potential_medium/low, inconclusive -> "못 잡음"
결과 파일에 아예 없는 케이스 -> "스캔되지 않음"(별도 집계, 못 잡음과 구분)

지표(sqli / xss / 합계):
  - 탐지율  = 탐지함 / (정답 취약인 수)
  - 오탐률  = 탐지로 잘못 판정 / (정답 취약 아님인 수)
  - 점수    = 탐지율 - 오탐률 (Benchmark 관례)
  - 혼동행렬(정답취약/비취약 x 탐지/못잡음), 스캔되지 않음
  - 참고: medium/inconclusive로 빠진 케이스 중 정답 취약/비취약 수 (판정 기준 바꿔볼 때용)

외부 의존성 없음(표준 라이브러리만). 옛 safe/vulnerable 표기는 안 씀(정답표 값만 "정답: 취약 / 취약 아님").
"""
from __future__ import annotations

import argparse
import csv
import glob
import json
import os
import re
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # 리포 루트 (benchmark/ 의 상위)
_CATEGORIES = ("sqli", "xss")
_TEST_RE = re.compile(r"BenchmarkTest(\d{5})")
_RANK = {"potential_high": 3, "potential_medium": 2, "potential_low": 1, "inconclusive": 0}
_DETECTED = {"potential_high"}                 # 탐지함으로 보는 판정 (정책: high만)
_REVIEW = {"potential_medium", "inconclusive"}  # 참고 집계용 (기준 바꿀 때)


# 최신 결과 폴더 (results/collection_*) 중 가장 최근
def _latest_out_dir() -> str | None:
    dirs = sorted(glob.glob(os.path.join(_ROOT, "results", "collection_*")))
    return dirs[-1] if dirs else None


def _load_jsonl(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    continue  # 기록 중 끊긴 마지막 줄 무시
    return rows


def _load_json(path: str):
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


# 정답표: sqli/xss 행만 {번호: (종류, 정답취약여부)}
def load_expected(path: str) -> dict[str, tuple[str, bool]]:
    expected = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3 or row[0].startswith("#"):
                continue
            m = _TEST_RE.search(row[0])
            if m and row[1].strip() in _CATEGORIES:
                expected[m.group(1)] = (row[1].strip(), row[2].strip().lower() == "true")
    return expected


# 결과 폴더에서 (수집된 테스트 집합, {(번호,종류): 대표 판정})
def load_results(out_dir: str) -> tuple[set[str], dict[tuple[str, str], str]]:
    collected: set[str] = set()
    for t in _load_json(os.path.join(out_dir, "scan_targets.json")):
        if not t.get("params"):  # 파라미터 없는 지점(폼 안내 페이지 등)은 수집 지점 아님
            continue
        m = _TEST_RE.search(t.get("base_url") or t.get("url") or "")
        if m:
            collected.add(m.group(1))

    best: dict[tuple[str, str], str] = {}
    for fd in _load_jsonl(os.path.join(out_dir, "findings.jsonl")):
        m = _TEST_RE.search(fd.get("url") or "")
        status = fd.get("final_status")
        if not (m and fd.get("family_id") and status):  # probe/오류 등 판정 아닌 줄 제외
            continue
        key = (m.group(1), fd.get("vuln_type"))
        # 같은 케이스 여러 판정이면 가장 높은 것을 대표로
        if key not in best or _RANK.get(status, -1) > _RANK.get(best[key], -1):
            best[key] = status
    return collected, best


def score(expected, collected, best):
    out = {}
    for cat in _CATEGORIES:
        tests = {n: real for n, (c, real) in expected.items() if c == cat}
        tp = fn = fp = tn = 0
        not_judged_collected = not_collected = 0  # "스캔되지 않음" 세부: 수집만 됨 / 아예 미수집
        review_real = review_safe = 0
        misses, false_alarms = [], []
        for n, real in tests.items():
            status = best.get((n, cat))
            if status is None:  # 결과 파일에 판정 없음 = 스캔되지 않음 (중단·미수집). 미탐으로 세지 않음
                if n in collected:
                    not_judged_collected += 1  # 수집은 됐는데 공격·판정 못 감(중단 등)
                else:
                    not_collected += 1          # 크롤링이 못 찾음
                continue
            detected = status in _DETECTED
            if real and detected:
                tp += 1
            elif real and not detected:
                fn += 1
                misses.append((n, status))
            elif (not real) and detected:
                fp += 1
                false_alarms.append((n, status))
            else:
                tn += 1
            if status in _REVIEW:  # 참고: medium/inconclusive로 빠진 것
                review_real += int(real)
                review_safe += int(not real)
        tpr = tp / (tp + fn) if tp + fn else 0.0
        fpr = fp / (fp + tn) if fp + tn else 0.0
        out[cat] = dict(
            expected=len(tests), judged=tp + fn + fp + tn,
            not_scanned=not_judged_collected + not_collected,
            not_judged_collected=not_judged_collected, not_collected=not_collected,
            TP=tp, FN=fn, FP=fp, TN=tn, 탐지율=round(tpr, 3), 오탐률=round(fpr, 3),
            점수=round(tpr - fpr, 3), 참고_medium_inconclusive=dict(정답취약=review_real, 정답취약아님=review_safe),
            misses=misses, false_alarms=false_alarms,
        )
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description="OWASP Benchmark 채점 (sqli/xss)")
    ap.add_argument("out_dir", nargs="?", help="결과 폴더 (생략 시 results/ 최신)")
    ap.add_argument("--expected", default=os.path.join(_ROOT, "test", "benchmark_backup", "benchmark_expected.csv"),
                    help="정답표 CSV")
    args = ap.parse_args()

    out_dir = args.out_dir or _latest_out_dir()
    if not out_dir or not os.path.isdir(out_dir):
        sys.exit("[ERROR] 결과 폴더 없음 (results/collection_* 가 없거나 경로 틀림)")
    if not os.path.exists(args.expected):
        sys.exit(f"[ERROR] 정답표 없음: {args.expected}")

    expected = load_expected(args.expected)
    collected, best = load_results(out_dir)
    rows = score(expected, collected, best)

    print(f"[BENCH] 결과 폴더: {out_dir}")
    print(f"[BENCH] 정답표 sqli/xss {len(expected)}개 | 판정 기준: 취약 가능성 높음(potential_high)만 '탐지함'")
    print("[BENCH] 탐지율·오탐률은 '실제로 판정된 케이스'만 분모. 스캔되지 않음은 제외(중단·미수집 → 미탐 아님)")
    for cat, r in rows.items():
        print(f"\n== {cat} ==")
        print(f"  정답표 {r['expected']} | 판정됨 {r['judged']} | "
              f"스캔되지 않음 {r['not_scanned']} (수집만 됨 {r['not_judged_collected']} / 미수집 {r['not_collected']})")
        print(f"  TP(정답취약·탐지) {r['TP']} | FN(정답취약·못잡음) {r['FN']} | "
              f"FP(취약아님·탐지) {r['FP']} | TN(취약아님·못잡음) {r['TN']}")
        print(f"  탐지율 {r['탐지율']:.1%} | 오탐률 {r['오탐률']:.1%} | 점수 {r['점수']:+.3f}  (판정된 {r['judged']}개 기준)")
        print(f"  참고(medium/검토필요로 빠짐): 정답취약 {r['참고_medium_inconclusive']['정답취약']} "
              f"/ 취약아님 {r['참고_medium_inconclusive']['정답취약아님']}")

    # 틀린 케이스 목록 파일로
    with open(os.path.join(out_dir, "benchmark_misses.csv"), "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["종류", "구분", "test", "판정"])
        for cat, r in rows.items():
            for n, st in r["misses"]:
                w.writerow([cat, "미탐(FN)", f"BenchmarkTest{n}", st])
            for n, st in r["false_alarms"]:
                w.writerow([cat, "오탐(FP)", f"BenchmarkTest{n}", st])
    print(f"\n[BENCH] 미탐·오탐 목록 -> {os.path.join(out_dir, 'benchmark_misses.csv')}")


if __name__ == "__main__":
    main()
