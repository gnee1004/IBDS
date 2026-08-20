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
_STORED_TECHNIQUE = "stored"       # 저장형 XSS: POST 주입 + GET 재조회 쌍으로 판정
_STORED_VERIFY_STEP = "stored_verify"  # 재조회 GET case의 step (request_builder가 주입 case 뒤에 붙임)


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


# family dict 공통 필드를 채운 Finding 생성 (저장형 판정에서 반복 서술 줄이기용)
def _stored_finding(
    family: dict, attack_case: dict, raw_verdict: dict,
    headless_checked: bool, headless_verdict, final_status: str,
) -> Finding:
    return Finding(
        family_id=family["family_id"],
        target_id=family["target_id"],
        param=family["param"],
        attack_id=family["attack_id"],
        technique=family["technique"],
        case_id=attack_case["case_id"],
        payload=attack_case.get("payload"),
        raw_verdict=raw_verdict,
        headless_checked=headless_checked,
        headless_verdict=asdict(headless_verdict) if headless_verdict else None,
        final_status=final_status,
    )


# 저장형 family의 mutations를 (주입 POST, 재조회 GET) 쌍으로 묶는다.
# 재조회 case의 case_id는 "{attack_case_id}_verify" (build_stored_verify_case 규약)
def _pair_stored_cases(mutations: list[dict]) -> list[tuple[dict, dict | None]]:
    verify_by_id: dict[str, dict] = {}
    attacks: list[dict] = []
    for case_result in mutations:
        case = case_result.get("case") or {}
        if case.get("step") == _STORED_VERIFY_STEP:
            verify_by_id[case.get("case_id")] = case_result
        else:
            attacks.append(case_result)
    return [
        (atk, verify_by_id.get(f"{(atk.get('case') or {}).get('case_id')}_verify"))
        for atk in attacks
    ]


# (주입 POST, 재조회 GET) 한 쌍을 판정.
# 핵심: POST 응답의 즉시 반사가 아니라 "GET 재조회 응답에 payload가 남아 있는지"로 저장 여부를 결정한다.
def _judge_stored_pair(family: dict, attack: dict, verify: dict | None, headless: HeadlessSession) -> Finding:
    attack_case = attack.get("case") or {}
    payload = attack_case.get("payload") or ""

    if attack.get("status") == "error":  # 주입 자체가 실패 → 재조회 의미 없음, 즉시 safe
        return _stored_finding(
            family, attack_case,
            {"vulnerable": False, "confidence": "", "evidence": "주입 요청 실패로 판정 불가"},
            headless_checked=False, headless_verdict=None, final_status="safe",
        )

    post_verdict = judge_xss(attack.get("response_body") or "", payload)
    verify_ok = verify is not None and verify.get("status") == "ok"
    verify_body = verify.get("response_body") or "" if verify_ok else ""
    verify_verdict = judge_xss(verify_body, payload)

    # 1) GET 재조회 응답에 payload가 살아 있음 → 실제 저장 확인 (가장 강한 근거)
    if verify_ok and verify_verdict.vulnerable:
        headless_verdict = headless.confirm_via_render(verify_body)  # 저장분이 실제 실행되는지까지 확인
        executed = headless_verdict.executed
        return _stored_finding(
            family, attack_case,
            {
                "vulnerable": True,
                "confidence": "high" if executed else "medium",
                "evidence": f"저장형 XSS: GET 재조회 응답에서 payload 저장 확인 ({verify_verdict.evidence})",
            },
            headless_checked=True, headless_verdict=headless_verdict,
            final_status="vulnerable" if executed else "stored_reflected",
        )

    # 2) POST 응답에는 즉시 반사되지만 재조회에는 없음 → 저장 미확인 (반사형 의심, 저장형 아님)
    if post_verdict.vulnerable:
        reason = "GET 재조회 미검출" if verify_ok else "GET 재조회 실패/누락"
        return _stored_finding(
            family, attack_case,
            {
                "vulnerable": False,
                "confidence": "low",
                "evidence": f"POST 응답에만 즉시 반사, {reason} → 저장 미확인 ({post_verdict.evidence})",
            },
            headless_checked=False, headless_verdict=None, final_status="reflected_only",
        )

    # 3) 어느 쪽에도 없음 → safe
    return _stored_finding(
        family, attack_case,
        {"vulnerable": False, "confidence": "", "evidence": "POST/GET 재조회 모두 payload 반사 없음"},
        headless_checked=False, headless_verdict=None, final_status="safe",
    )


# 저장형 family 전체를 판정 → 주입 payload 1건당 Finding 1건
def _judge_stored_family(family: dict, headless: HeadlessSession) -> list[Finding]:
    findings: list[Finding] = []
    for attack, verify in _pair_stored_cases(family.get("mutations") or []):
        findings.append(_judge_stored_pair(family, attack, verify, headless))
    return findings


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

                # 저장형: (주입 POST, 재조회 GET) 쌍 단위로 판정 → payload당 Finding 1건
                if family.get("technique") == _STORED_TECHNIQUE:
                    try:
                        for finding in _judge_stored_family(family, headless):
                            append_jsonl(out_path, asdict(finding))
                    except Exception as e:
                        print(f"[ERROR] 저장형 XSS 판정 실패: family={family['family_id']} - {e}")
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
