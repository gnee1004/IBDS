"""
request_results.jsonl -> XSS 판정(raw) + headless confirm -> xss_findings.jsonl
analyzer/xss/judge.py는 수정하지 안하고 사용. sqli는 아직 제대로 merge 할 수 있는 상태가 아니라서 건너뜀.
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass

from scan.models import RequestFamily, CaseResult
from utilities.file_utils import append_jsonl
from .headless import HeadlessSession
from .xss.judge import judge_xss

_DOM_TECHNIQUE = "dom"


@dataclass
class Finding:  # xss_findings.jsonl 한 줄에 대응하는 case 단위 판정 결과
    family_id: str
    target_id: str
    param: str
    attack_id: str
    technique: str
    case_id: str
    payload: str | None
    raw_verdict: dict              # judge_xss 결과 (asdict)
    headless_checked: bool         # headless 대상이었는지
    headless_verdict: dict | None  # headless 결과 (asdict), 대상 아니면 None
    final_status: str              # "vulnerable" | "reflected_only" | "safe"


# raw 판정에서 걸렸거나, raw로는 원천적으로 확인이 안 되는 기법(dom)이면 headless 대상
def _is_headless_target(vulnerable: bool, technique: str) -> bool:
    return vulnerable or technique == _DOM_TECHNIQUE


# headless 확인 결과까지 반영한 최종 상태 판정
def _final_status(raw_vulnerable: bool, headless_checked: bool, executed: bool) -> str:
    if not headless_checked:
        return "safe"
    if executed:
        return "vulnerable"
    return "reflected_only" if raw_vulnerable else "safe"


# mutation case 1건에 대한 raw 판정 + (필요시) headless 확인
def _judge_case(family: dict, case_result: dict, headless: HeadlessSession) -> Finding:
    case = case_result["case"]
    technique = family["technique"]
    payload = case.get("payload") or ""

    if case_result.get("status") == "error":  # 요청 자체가 실패한 case는 judge_xss/headless 호출 없이 즉시 safe 처리
        return Finding(
            family_id=family["family_id"],
            target_id=family["target_id"],
            param=family["param"],
            attack_id=family["attack_id"],
            technique=technique,
            case_id=case["case_id"],
            payload=case.get("payload"),
            raw_verdict={"vulnerable": False, "confidence": "", "evidence": "요청 실패로 판정 불가"},
            headless_checked=False,
            headless_verdict=None,
            final_status="safe",
        )

    raw_verdict = judge_xss(case_result.get("response_body") or "", payload)
    headless_checked = _is_headless_target(raw_verdict.vulnerable, technique)

    headless_verdict = None
    if headless_checked:
        if technique == _DOM_TECHNIQUE:
            headless_verdict = headless.confirm_via_navigate(
                case["url"], case_result.get("effective_cookies") or {}, case["method"],
            )
        else:
            headless_verdict = headless.confirm_via_render(case_result.get("response_body") or "")

    return Finding(
        family_id=family["family_id"],
        target_id=family["target_id"],
        param=family["param"],
        attack_id=family["attack_id"],
        technique=technique,
        case_id=case["case_id"],
        payload=case.get("payload"),
        raw_verdict=asdict(raw_verdict),
        headless_checked=headless_checked,
        headless_verdict=asdict(headless_verdict) if headless_verdict else None,
        final_status=_final_status(
            raw_verdict.vulnerable, headless_checked,
            headless_verdict.executed if headless_verdict else False,
        ),
    )


# RequestFamily/CaseResult 객체를 파일 경유 없이 그대로 받아 즉시 판정 (오케스트레이터 라이브 루프용)
def judge_case_live(family: RequestFamily, case_result: CaseResult, headless: HeadlessSession) -> Finding:
    return _judge_case(asdict(family), asdict(case_result), headless)


# request_results.jsonl을 읽어 XSS family만 판정, xss_findings.jsonl 생성
def run(results_path: str, headless: HeadlessSession | None = None) -> str:
    out_path = os.path.join(os.path.dirname(results_path), "xss_findings.jsonl")
    if os.path.exists(out_path):
        os.remove(out_path)  # append_jsonl은 이어쓰기라 재실행 시 중복 방지

    owns_headless = headless is None
    headless = headless or HeadlessSession()
    non_xss_skipped = 0

    try:
        with open(results_path, encoding="utf-8") as f:
            for line in f:
                family = json.loads(line)
                if family["vuln_type"] != "xss":
                    non_xss_skipped += 1
                    continue
                for case_result in family["mutations"]:
                    try:  # 개별 case 판정 실패는 로그만 남기고 계속 진행
                        finding = _judge_case(family, case_result, headless)
                    except Exception as e:
                        print(f"[ERROR] XSS 판정 실패: family={family['family_id']} case={case_result.get('case', {}).get('case_id')} - {e}")
                        continue
                    append_jsonl(out_path, asdict(finding))
    finally:
        if owns_headless:
            headless.close()

    print(f"[JUDGE] xss_findings.jsonl -> {out_path} ({non_xss_skipped}건 non-XSS family는 판정 로직 미연결 - 건너뜀)")
    return out_path
