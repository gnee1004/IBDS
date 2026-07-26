"""
variant.py end-to-end 테스트

generate_families() → baseline + mutation HTTP 전송 → 응답 분석 → findings 출력
"""

from __future__ import annotations

import dataclasses
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from models import RequestFamily
from scan.mutation.variant import generate_families

# ── 설정 ──────────────────────────────────────────────────────────────────────
SESSION_DIR = Path("results/collection_20260718_165152")
RULES_PATH  = Path("attack_request_list.json")
TIMEOUT     = 10
MAX_WORKERS = 3
VULN_TYPES  = None   # None=전체, ["sqli"], ["xss"]

# ── SQLi 오류 시그니처 ─────────────────────────────────────────────────────────
_SQLI_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "syntax error",
    "ora-01756",
    "microsoft ole db provider for sql server",
    "pg::syntaxerror",
]


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )
    })
    retry = Retry(total=1, connect=1, read=0, status=0, backoff_factor=0)
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def _send(case: dict) -> dict:
    session = _make_session()
    started = time.perf_counter()
    try:
        if case["method"] == "POST":
            resp = session.post(
                case["url"],
                data=case["body"],
                headers=case["headers"],
                cookies=case["cookies"],
                timeout=TIMEOUT,
                allow_redirects=False,
            )
        else:
            resp = session.get(
                case["url"],
                headers=case["headers"],
                cookies=case["cookies"],
                timeout=TIMEOUT,
                allow_redirects=False,
            )
        return {
            **case,
            "status":        resp.status_code,
            "elapsed":       round(time.perf_counter() - started, 3),
            "response_body": resp.text[:10_000],
            "error":         None,
        }
    except requests.Timeout:
        return {**case, "status": None, "elapsed": round(time.perf_counter() - started, 3),
                "response_body": None, "error": "timeout"}
    except Exception as e:
        return {**case, "status": None, "elapsed": round(time.perf_counter() - started, 3),
                "response_body": None, "error": str(e)}


def _analyze(family: RequestFamily, baseline_result: dict, mutation_result: dict) -> str | None:
    body    = (mutation_result.get("response_body") or "").lower()
    vuln    = family.vuln_type
    payload = mutation_result.get("payload", "")

    if vuln == "sqli":
        for sig in _SQLI_SIGNATURES:
            if sig in body:
                return f"SQL_ERROR: {sig!r}"

    elif vuln == "xss":
        if payload and payload.lower() in body:
            return f"REFLECTED: {payload!r}"

    return None


def run(targets_path: Path, rules_path: Path) -> None:
    print("[1] family 생성 중...")
    families = generate_families(targets_path, rules_path, vuln_types=VULN_TYPES)
    total_cases = sum(1 + len(f.mutations) for f in families)
    print(f"[1] {len(families)}개 family, {total_cases}개 요청 (baseline 포함, vuln_types={VULN_TYPES})")

    # ── 전송할 케이스 목록 구성 (family_id, role 태깅) ─────────────────────────
    tagged: list[dict] = []
    for f in families:
        tagged.append({**dataclasses.asdict(f.baseline), "family_id": f.family_id, "role": "baseline"})
        for m in f.mutations:
            tagged.append({**dataclasses.asdict(m), "family_id": f.family_id, "role": "mutation",
                           "vuln_type": f.vuln_type})

    # ── 병렬 전송 ──────────────────────────────────────────────────────────────
    results: list[dict] = [None] * len(tagged)
    print(f"[2] 전송 중... (max_workers={MAX_WORKERS}, timeout={TIMEOUT}s)")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        future_to_idx = {pool.submit(_send, c): i for i, c in enumerate(tagged)}
        done = 0
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                results[idx] = {**tagged[idx], "status": None, "elapsed": 0,
                                "response_body": None, "error": str(e)}
            done += 1
            if done % 100 == 0 or done == len(tagged):
                print(f"  {done}/{len(tagged)}", end="\r")

    print()

    # ── family 단위로 결과 묶기 ────────────────────────────────────────────────
    baseline_map: dict[str, dict] = {}
    mutation_results: list[dict] = []

    for r in results:
        if r["role"] == "baseline":
            baseline_map[r["family_id"]] = r
        else:
            mutation_results.append(r)

    # ── 분석 ───────────────────────────────────────────────────────────────────
    family_map = {f.family_id: f for f in families}
    errors   = [r for r in results if r.get("error")]
    findings = []

    for r in mutation_results:
        fid      = r["family_id"]
        family   = family_map.get(fid)
        if family is None:
            continue
        baseline = baseline_map.get(fid)
        evidence = _analyze(family, baseline, r)
        if evidence:
            findings.append({**r, "evidence": evidence})

    # ── 출력 ───────────────────────────────────────────────────────────────────
    print(f"\n[3] 결과")
    print(f"  전송: {len(results)}  오류: {len(errors)}  발견: {len(findings)}")

    if findings:
        print(f"\n[findings]")
        for f in findings:
            print(f"  [{f['vuln_type'].upper()}] {f['method']} {f['url']}")
            fam = family_map.get(f['family_id'])
            print(f"    param={fam.param if fam else '?'}  payload={f.get('payload')!r}")
            print(f"    evidence={f['evidence']}")

    # ── family 단위 결과 저장 ──────────────────────────────────────────────────
    family_results = []
    for f in families:
        fid = f.family_id
        family_results.append({
            "family_id":  fid,
            "target_id":  f.target_id,
            "param":      f.param,
            "vuln_type":  f.vuln_type,
            "attack_id":  f.attack_id,
            "baseline":   baseline_map.get(fid),
            "mutations":  [r for r in mutation_results if r["family_id"] == fid],
        })

    out = SESSION_DIR / "variant_test_results.json"
    with open(out, "w", encoding="utf-8") as fp:
        json.dump(family_results, fp, ensure_ascii=False, indent=2)
    print(f"\n결과 저장: {out}")


if __name__ == "__main__":
    t_path = Path(sys.argv[1]) if len(sys.argv) > 1 else SESSION_DIR / "scan_targets.json"
    r_path = Path(sys.argv[2]) if len(sys.argv) > 2 else RULES_PATH
    run(t_path, r_path)

