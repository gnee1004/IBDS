"""
request_results.jsonl 요약 (로컬 실행용)

큰 파일을 통째로 올릴 필요 없이, 보고서에 필요한 숫자만 뽑는다.
  - 총 요청 수 / 총 소요 시간(초) / 요청 실패 수(send_status error·not_sent)
  - baseline 등에서 서버 오류(500) 난 건수 (있으면)

사용: python benchmark\summarize_requests.py results\collection_YYYYMMDD_HHMMSS\request_results.jsonl
스키마가 조금 달라도 동작하도록 키 이름을 여러 개 받아 처리한다. 외부 의존성 없음.
"""
from __future__ import annotations

import json
import sys


def _num(v):
    return v if isinstance(v, (int, float)) else 0


def main() -> None:
    if len(sys.argv) < 2:
        sys.exit("사용: python benchmark\\summarize_requests.py <request_results.jsonl 경로>")
    path = sys.argv[1]

    lines = total_req = total_elapsed = fail = err500 = 0
    statuses: dict[str, int] = {}

    def walk(obj):
        """중첩된 FamilyResult/CaseResult 어디에 있든 request_count·elapsed·status를 긁어모은다."""
        nonlocal total_req, total_elapsed, fail, err500
        if isinstance(obj, dict):
            total_req += _num(obj.get("request_count"))
            total_elapsed += _num(obj.get("elapsed") or obj.get("elapsed_seconds"))
            stt = obj.get("send_status") or obj.get("status")
            if isinstance(stt, str):
                statuses[stt] = statuses.get(stt, 0) + 1
                if stt in ("error", "not_sent"):
                    fail += 1
            code = obj.get("status_code") or obj.get("http_status")
            if code == 500:
                err500 += 1
            for v in obj.values():
                if isinstance(v, (dict, list)):
                    walk(v)
        elif isinstance(obj, list):
            for v in obj:
                walk(v)

    for ln in open(path, encoding="utf-8"):
        ln = ln.strip()
        if not ln:
            continue
        lines += 1
        try:
            walk(json.loads(ln))
        except json.JSONDecodeError:
            continue

    print(f"[REQ] 파일 줄 수 {lines}")
    print(f"[REQ] 총 요청 수(집계) {total_req}")
    print(f"[REQ] 총 소요 시간 {total_elapsed:.1f}초 ({total_elapsed/60:.1f}분)")
    print(f"[REQ] 요청 실패(error·not_sent) {fail}건")
    print(f"[REQ] 서버 오류(500) {err500}건")
    print(f"[REQ] status 분포 {statuses}")


if __name__ == "__main__":
    main()
