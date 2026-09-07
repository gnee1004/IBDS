#!/usr/bin/env python3
"""
rules_xss.py PL-XSS-STORED 마커 미포함 확인 스크립트 (근희 9/5 산출물용, 읽기 전용)

목적:
  Phase 2 stored 공격 payload에 Phase 1 프로브 '마커'(설계상 ibds+4hex+카운터)가
  섞여 있지 않은지 '읽기'로만 확인한다. 룰 정의는 절대 수정하지 않는다 (CLAUDE.md #3).

왜:
  Phase 1은 param 값을 마커로 통째 교체해 sink 반사 여부로 sink 존재를 판정한다.
  Phase 2 공격 payload에 마커가 섞이면 마커 반사/diff 로직이 공격 payload를 프로브
  마커로 오인할 수 있다. 그래서 stored 공격 payload는 마커-free 여야 한다.

사용 (IBDS 루트에서):
  python check_stored_marker.py
  python check_stored_marker.py src/attack_requests/rules_xss.py   # 경로 지정

주의:
  ast.literal_eval로 룰 리터럴만 읽는다. 룰 파일을 import/실행하지도, 수정하지도 않는다.
"""
import ast
import re
import sys

DEFAULT_PATH = "src/attack_requests/rules_xss.py"

# 설계상 마커 = 'ibds' + 회차난수 4hex 프리픽스 + param별 카운터
MARKER_PATTERNS = [
    ("ibds 프리픽스",             re.compile(r"ibds", re.I)),
    ("ibds+4hex 형태",            re.compile(r"ibds[0-9a-f]{4}", re.I)),
    ("marker/probe 플레이스홀더", re.compile(r"\{\{?\s*(marker|probe)\s*\}?\}|__MARKER__|\bMARKER\b", re.I)),
]


def load_rules(path: str) -> list[dict]:
    """모듈을 실행하지 않고 최상위 룰 리스트 리터럴만 안전하게 읽는다."""
    src = open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):  # XSS_RULES: list[dict] = [...]
            try:
                val = ast.literal_eval(node.value)
            except Exception:
                continue
            if isinstance(val, list) and any(isinstance(x, dict) and "attack_id" in x for x in val):
                return val
    raise SystemExit("[ERROR] 룰 리스트를 찾지 못함")


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PATH
    rules = load_rules(path)
    stored = [r for r in rules if r.get("technique") == "stored"]

    print(f"대상: {path}")
    print(f"전체 룰 {len(rules)}개 / technique=='stored': {[r['attack_id'] for r in stored]}\n")

    problems = 0
    for r in stored:
        payloads = r.get("payload_templates", {}).get("attack", [])
        print(f"[{r['attack_id']}] attack payload {len(payloads)}개")
        for i, p in enumerate(payloads):
            hits = [name for name, rx in MARKER_PATTERNS if rx.search(p)]
            if hits:
                problems += 1
                print(f"  {i:2d}. ⚠️ 마커혼입 {hits} :: {p[:70]}")
            else:
                print(f"  {i:2d}. OK :: {p[:70]}")

    print("\n" + "=" * 55)
    if problems == 0:
        print("✅ 통과: stored 공격 payload 전부 마커 미포함 (clean)")
        sys.exit(0)
    else:
        print(f"❌ {problems}건 마커 혼입 — 룰 담당자에게 보고 (여기서 직접 수정 금지)")
        sys.exit(1)


if __name__ == "__main__":
    main()
