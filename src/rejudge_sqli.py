import csv
import json
import os
import re
from collections import Counter
from dataclasses import asdict

from analyzer.sqli_detector import analyze_family
from utilities.file_utils import append_jsonl

# 재판정할 실행 결과 폴더 (None이면 results 아래 가장 최근 폴더)
RUN_DIR = None
STAGES = (0, 1, 2, 3)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RESULTS_ROOT = os.path.join(_PROJECT_ROOT, "results")
_EXPECTED_CSV = os.path.join(_PROJECT_ROOT, "expectedresults-1.2.csv")
_TEST_RE = re.compile(r"BenchmarkTest(\d{5})")
_STRICT = {"potential_high"}  # 엄격 기준: 취약 가능성 높음만 탐지로 인정
_LOOSE = _STRICT | {"potential_medium"}  # 완화 기준: 취약 신호 관찰까지 인정


# 정답표에서 sqli 항목만 로드: {테스트번호: 실제취약여부}
def _load_expected() -> dict[str, bool]:
    expected = {}
    with open(_EXPECTED_CSV, encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            m = _TEST_RE.search(row[0]) if len(row) >= 3 and not row[0].startswith("#") else None
            if m and row[1].strip() == "sqli":
                expected[m.group(1)] = row[2].strip().lower() == "true"
    return expected


# 수집된 검사 대상(파라미터 있는 것)의 테스트번호 집합
def _collected_tests(run_dir: str) -> set[str]:
    with open(os.path.join(run_dir, "scan_targets.json"), encoding="utf-8") as f:
        targets = json.load(f)
    found = (_TEST_RE.search(t.get("base_url") or t.get("url") or "") for t in targets if t.get("params"))
    return {m.group(1) for m in found if m}


# 판정 결과를 (테스트번호, 기법) 단위 판정값 집합으로 묶음 (같은 테스트의 여러 family 중 하나라도 해당 판정이면 탐지로 취급)
def _statuses_by_test(findings_path: str) -> dict[tuple[str, str], set]:
    statuses: dict[tuple[str, str], set] = {}
    with open(findings_path, encoding="utf-8") as f:
        for line in f:
            fd = json.loads(line)
            m = _TEST_RE.search(fd.get("url") or "")
            if m:
                statuses.setdefault((m.group(1), fd.get("technique") or ""), set()).add(fd.get("final_status"))
    return statuses


# 공격 요청을 실제로 보낸 테스트 집합 (기법별). 변형 요청이 하나라도 미실행이 아니면 스캔한 것으로 취급
def _scanned_tests(families: list[dict]) -> dict[str, set[str]]:
    scanned: dict[str, set[str]] = {}
    for fam in families:
        if all(m.get("progress_status") == "not_run" for m in fam["mutations"]):
            continue
        m = _TEST_RE.search((fam["mutations"][0].get("case") or {}).get("url") or "")
        if m:
            scanned.setdefault(str(fam.get("technique") or ""), set()).add(m.group(1))
    return scanned


# 판정값 집합을 테스트번호 단위로 합침 (technique을 주면 해당 기법만)
def _merge(statuses: dict[tuple[str, str], set], technique: str | None = None) -> dict[str, set]:
    merged: dict[str, set] = {}
    for (n, tech), s in statuses.items():
        if technique is None or tech == technique:
            merged.setdefault(n, set()).update(s)
    return merged


# 엄격·완화 두 기준으로 채점
def _score_both(expected: dict[str, bool], tests: set[str], statuses: dict[str, set]) -> dict:
    return {"strict": _score(expected, tests, statuses, _STRICT), "loose": _score(expected, tests, statuses, _LOOSE)}


# tests에 속한 테스트만 대상으로 TP/FN/FP/TN과 TPR, FPR, 점수(TPR-FPR) 계산
def _score(expected: dict[str, bool], collected: set[str], statuses: dict[str, set], positive: set) -> dict:
    tp = fn = fp = tn = 0
    for n, real in expected.items():
        if n not in collected:
            continue
        hit = bool(statuses.get(n, set()) & positive)
        tp += real and hit
        fn += real and not hit
        fp += (not real) and hit
        tn += (not real) and not hit
    tpr = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0
    return dict(TP=tp, FN=fn, FP=fp, TN=tn, TPR=round(tpr, 3), FPR=round(fpr, 3), score=round(tpr - fpr, 3))


# RUN_DIR이 비어 있으면 results 아래 가장 최근 collection_* 폴더 선택
def _resolve_run_dir() -> str:
    if RUN_DIR:
        return RUN_DIR
    names = sorted(n for n in os.listdir(_RESULTS_ROOT) if n.startswith("collection_"))
    return os.path.join(_RESULTS_ROOT, names[-1])


# 단계별로 판정이 실제로 읽는 응답 목록 (기준 응답 + 공격 응답, E1부터 기준 2회 비교용 1건 추가, E2부터 대조 응답 포함)
# 판정부 호출이 아니라 판정부 코드 읽기 기준의 집계라, 판정부가 바뀌면 이 규칙도 함께 확인 필요
def _used_responses(fam: dict, stage: int) -> list[dict]:
    ok = [m for m in fam.get("mutations", []) if m.get("send_status") == "ok"]
    technique = str(fam.get("technique") or "")
    if technique.startswith("boolean"):
        is_control = lambda m: (m.get("case") or {}).get("role") == "control"
    elif technique.startswith("time"):
        is_control = lambda m: ((m.get("case") or {}).get("role") or (m.get("case") or {}).get("step")) == "control"
    else:
        is_control = lambda _: False  # 오류 계열은 대조 응답 개념이 없고 모든 단계에서 같은 응답을 사용
    used = [m for m in ok if stage >= 2 or not is_control(m)]
    baseline = [fam["baseline"]] if fam.get("baseline") else []
    if technique.startswith("boolean") and stage >= 1 and fam.get("baseline_match_ratio") is not None:
        baseline.append(fam["baseline"])  # 기준 응답 2회 비교분 (두 번째 기준 응답은 별도 저장이 없어 같은 응답으로 대신 계수)
    return baseline + used


# request_results.jsonl의 SQLi family를 단계별로 다시 판정해 findings_E{n}.jsonl로 저장
def rejudge(run_dir: str) -> dict[int, Counter]:
    with open(os.path.join(run_dir, "request_results.jsonl"), encoding="utf-8") as f:
        families = [fam for fam in map(json.loads, f) if fam.get("vuln_type") == "sqli" and fam.get("mutations")]  # 준비 실패 줄 등 변형 없는 줄 제외

    expected = _load_expected()
    collected = _collected_tests(run_dir) & expected.keys()
    if not collected:
        print("[REJUDGE] 벤치마크 테스트 대상이 없어 TP/FP 채점은 건너뜀")
    scanned = _scanned_tests(families)
    summary = {}
    for stage in STAGES:
        out_path = os.path.join(run_dir, f"findings_E{stage}.jsonl")
        if os.path.exists(out_path):
            os.remove(out_path)  # append_jsonl은 이어쓰기라 재실행 시 중복 방지
        counts = Counter()
        used_requests, used_elapsed = 0, 0.0
        for fam in families:
            try:
                findings = analyze_family(fam, stage=stage)
            except Exception as e:  # 한 family 실패가 전체 재판정을 막지 않도록 기록 후 계속
                print(f"[ERROR] E{stage} 재판정 실패: family={fam.get('family_id')} - {e}")
                counts["error"] += 1
                continue
            for finding in findings:
                append_jsonl(out_path, {**asdict(finding), "sqli_stage": f"E{stage}"})
                counts[finding.final_status] += 1
            used = _used_responses(fam, stage)
            used_requests += len(used)
            used_elapsed += sum(float(r.get("elapsed") or 0.0) for r in used)
        summary[stage] = {"verdicts": dict(counts), "used_requests": used_requests, "used_elapsed": round(used_elapsed, 2)}
        if collected and os.path.exists(out_path):  # 벤치마크 대상이 아니면 채점 생략
            statuses = _statuses_by_test(out_path)
            all_scanned = set().union(*scanned.values()) & expected.keys() if scanned else set()
            summary[stage]["score_collected"] = _score_both(expected, collected, _merge(statuses))  # 분모: 수집된 테스트 전부
            summary[stage]["score_scanned"] = _score_both(expected, all_scanned, _merge(statuses))  # 분모: 공격 요청을 보낸 테스트만
            summary[stage]["by_technique"] = {  # 기법별: 해당 기법으로 공격 요청을 보낸 테스트만 분모
                tech: _score_both(expected, tests & expected.keys(), _merge(statuses, tech))
                for tech, tests in sorted(scanned.items())
            }
        print(f"[REJUDGE] E{stage} -> {out_path} {summary[stage]}")
    with open(os.path.join(run_dir, "sqli_stage_summary.json"), "w", encoding="utf-8") as f:
        json.dump({f"E{s}": v for s, v in summary.items()}, f, ensure_ascii=False, indent=2)
    return summary


if __name__ == "__main__":
    rejudge(_resolve_run_dir())
