"""
OWASP Benchmark 케이스 필터·분류 (로컬 실행용)

하는 일
  1) 정답표(expectedresults CSV)에서 sqli(CWE-89)·xss(CWE-79) 케이스만 추린다.
  2) 각 케이스의 .java 소스를 읽어 입력 위치를 분류한다.
       - parameter (getParameter/getParameterValues/getQueryString)  -> 우리 스캐너 범위 안
       - cookie    (getCookies)                                      -> 범위 밖
       - header    (getHeader/getHeaders)                            -> 범위 밖
       - other     (servletPath/pathInfo 등)                         -> 범위 밖
  3) 범위 안(parameter) 케이스만 대상으로, 정답 취약/취약 아님 비율을 맞춰 시드 고정 표본을 뽑는다.
  4) 산출물
       - kept_cases.csv     : 남긴 케이스 (이름, 종류, 정답, 입력 위치, URL)
       - excluded_cases.csv : 제외 케이스 (이름, 종류, 정답, 입력 위치, 제외 사유)
       - zap_scope_includes.txt : ZAP Context include 정규식 후보 (남긴 케이스 경로만)

용어: 판정은 코드 쪽에서만 쓰므로 여기선 정답만 다룬다. 정답표 값은 "정답: 취약 / 정답: 취약 아님"으로 표기한다.
외부 의존성 없음(표준 라이브러리만).
"""
from __future__ import annotations

import argparse
import csv
import os
import random
import re
import sys

_CATEGORIES = ("sqli", "xss")          # 우리 스캐너가 다루는 종류 (CWE-89 / CWE-79)
_TEST_RE = re.compile(r"BenchmarkTest(\d{5})")
_WEBSERVLET_RE = re.compile(r'@WebServlet\s*\(\s*value\s*=\s*"([^"]+)"')
_WEBSERVLET_RE2 = re.compile(r'@WebServlet\s*\(\s*"([^"]+)"')  # value= 없이 바로 경로를 주는 형태 대비

# 입력 위치 판정용 — 우선순위: header > cookie > parameter (한 테스트는 보통 한 소스만 씀)
_SRC_PATTERNS = [
    ("header", re.compile(r"\.getHeaders?\s*\(")),
    ("cookie", re.compile(r"\.getCookies\s*\(")),
    ("parameter", re.compile(r"\.getParameter(?:Values)?\s*\(|\.getQueryString\s*\(")),
]
_IN_SCOPE = {"parameter"}  # 쿼리/폼만 스캐너가 변조 가능. 쿠키·헤더·기타는 범위 밖


# 소스에서 서블릿 URL 경로 추출 (예: /sqli-00/BenchmarkTest00008)
def _servlet_path(src: str) -> str | None:
    m = _WEBSERVLET_RE.search(src) or _WEBSERVLET_RE2.search(src)
    return m.group(1) if m else None


# 소스에서 입력 위치 판정 (header/cookie/parameter/other)
def classify_source(src: str) -> str:
    for name, pat in _SRC_PATTERNS:
        if pat.search(src):
            return name
    return "other"


# 정답표 로드: sqli/xss 행만 {번호: (종류, 정답취약여부)}
def load_expected(path: str) -> dict[str, tuple[str, bool]]:
    expected: dict[str, tuple[str, bool]] = {}
    with open(path, encoding="utf-8-sig", newline="") as f:
        for row in csv.reader(f):
            if len(row) < 3 or row[0].startswith("#"):
                continue
            m = _TEST_RE.search(row[0])
            cat = row[1].strip()
            if m and cat in _CATEGORIES:
                expected[m.group(1)] = (cat, row[2].strip().lower() == "true")
    return expected


# 케이스별 .java 를 읽어 입력 위치·URL 분류. testcode 폴더에서 BenchmarkTestNNNNN.java 를 찾음
def classify_cases(expected: dict, testcode_dir: str, base_url: str) -> list[dict]:
    base = base_url.rstrip("/")
    cases = []
    for num, (cat, real) in sorted(expected.items()):
        java = os.path.join(testcode_dir, f"BenchmarkTest{num}.java")
        if not os.path.exists(java):
            cases.append(dict(test=f"BenchmarkTest{num}", type=cat, truth=real,
                              source="missing", url=None, in_scope=False, reason="소스 파일 없음"))
            continue
        with open(java, encoding="utf-8", errors="replace") as f:
            src = f.read()
        source = classify_source(src)
        path = _servlet_path(src)
        url = (base + path) if path else None
        in_scope = source in _IN_SCOPE and url is not None
        reason = "" if in_scope else (f"입력 위치 {source} (스캐너 범위 밖)" if not url else "URL 파싱 실패")
        cases.append(dict(test=f"BenchmarkTest{num}", type=cat, truth=real,
                          source=source, url=url, in_scope=in_scope, reason=reason))
    return cases


# 범위 안 케이스를 종류별로 정답 취약/취약아님 균형 맞춰 표본 추출 (시드 고정)
def sample_balanced(cases: list[dict], per_type: int, seed: int) -> list[dict]:
    rng = random.Random(seed)
    picked: list[dict] = []
    for cat in _CATEGORIES:
        pool = [c for c in cases if c["type"] == cat and c["in_scope"]]
        pos = [c for c in pool if c["truth"]]
        neg = [c for c in pool if not c["truth"]]
        rng.shuffle(pos)
        rng.shuffle(neg)
        half = per_type // 2
        take_pos, take_neg = pos[:half], neg[: per_type - half]
        # 한쪽이 모자라면 다른 쪽에서 채움
        short = per_type - len(take_pos) - len(take_neg)
        if short > 0:
            take_pos += pos[len(take_pos):len(take_pos) + short]
            short = per_type - len(take_pos) - len(take_neg)
            take_neg += neg[len(take_neg):len(take_neg) + short]
        picked += take_pos + take_neg
    return picked


def _truth_ko(real: bool) -> str:
    return "정답: 취약" if real else "정답: 취약 아님"


def _write_csv(path: str, rows: list[dict], cols: list[str]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for r in rows:
            w.writerow([r.get(c, "") for c in cols])


def main() -> None:
    ap = argparse.ArgumentParser(description="OWASP Benchmark sqli/xss 케이스 필터·분류")
    ap.add_argument("--testcode", required=True, help="BenchmarkTestNNNNN.java 들이 있는 폴더")
    ap.add_argument("--expected", required=True, help="expectedresults CSV 경로")
    ap.add_argument("--base-url", default="https://localhost:8443/benchmark", help="Benchmark 접속 주소 (기본 https://localhost:8443/benchmark)")
    ap.add_argument("--per-type", type=int, default=50, help="종류별 표본 수 (기본 50). 0이면 범위 안 전체")
    ap.add_argument("--seed", type=int, default=42, help="표본 시드 (기본 42)")
    ap.add_argument("--out-dir", default=".", help="산출물 저장 폴더")
    args = ap.parse_args()

    if not os.path.isdir(args.testcode):
        sys.exit(f"[ERROR] testcode 폴더 없음: {args.testcode}")
    if not os.path.exists(args.expected):
        sys.exit(f"[ERROR] 정답표 없음: {args.expected}")
    os.makedirs(args.out_dir, exist_ok=True)

    expected = load_expected(args.expected)
    cases = classify_cases(expected, args.testcode, args.base_url)
    in_scope = [c for c in cases if c["in_scope"]]
    out_scope = [c for c in cases if not c["in_scope"]]

    picked = in_scope if args.per_type == 0 else sample_balanced(in_scope, args.per_type, args.seed)
    picked_set = {c["test"] for c in picked}
    # 범위 안이지만 표본에서 빠진 것도 제외 목록에 사유를 달아 남김
    excluded = [dict(c, reason=c["reason"] or "표본 미선정") for c in cases if c["test"] not in picked_set]

    kept_rows = [dict(c, truth=_truth_ko(c["truth"])) for c in picked]
    exc_rows = [dict(c, truth=_truth_ko(c["truth"])) for c in excluded]
    _write_csv(os.path.join(args.out_dir, "kept_cases.csv"), kept_rows,
               ["test", "type", "truth", "source", "url"])
    _write_csv(os.path.join(args.out_dir, "excluded_cases.csv"), exc_rows,
               ["test", "type", "truth", "source", "reason"])
    with open(os.path.join(args.out_dir, "zap_scope_includes.txt"), "w", encoding="utf-8") as f:
        for c in picked:
            f.write(re.escape(c["url"]) + r"(?:$|[/?#].*)" + "\n")
    # 스캐너 축소용: 남긴 케이스 이름 목록 (config의 scan_keep_file 로 지정하면 공격을 이 케이스만 돌림)
    with open(os.path.join(args.out_dir, "kept_tests.txt"), "w", encoding="utf-8") as f:
        for c in picked:
            f.write(c["test"] + "\n")

    # 요약 출력
    print(f"[FILTER] 정답표 sqli/xss 케이스 {len(cases)}개")
    for cat in _CATEGORIES:
        total = [c for c in cases if c["type"] == cat]
        ins = [c for c in total if c["in_scope"]]
        srcs: dict[str, int] = {}
        for c in total:
            if not c["in_scope"]:
                srcs[c["source"]] = srcs.get(c["source"], 0) + 1
        pk = [c for c in picked if c["type"] == cat]
        print(f"  [{cat}] 전체 {len(total)} | 범위 안(parameter) {len(ins)} | "
              f"범위 밖 {len(total) - len(ins)} {srcs} | 표본 {len(pk)}"
              f"(취약 {sum(c['truth'] for c in pk)}/취약아님 {sum(not c['truth'] for c in pk)})")
    print(f"[FILTER] kept_cases.csv / excluded_cases.csv / zap_scope_includes.txt -> {args.out_dir}")


if __name__ == "__main__":
    main()
