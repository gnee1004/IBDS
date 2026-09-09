"""
ver2 오케스트레이터.
"""

import io
import json
import os
import sys
from dataclasses import asdict, replace

for _stream in (sys.stdout, sys.stderr):
    if isinstance(_stream, io.TextIOWrapper):
        _stream.reconfigure(encoding="utf-8", errors="backslashreplace")

from collector.main_collector import run_collection
from scan.match.rules_builder import get_rules
from scan.mutation.discovery import measure_dynamic_markers, run_discovery
from scan.mutation.request_builder import generate_sqli_families, generate_stored_xss_families, generate_xss_families
from scan.mutation.scan_point import build_scan_points
from scan.normalize.param_filter import has_destructive_action
from scan.requester import requester
from scan.models import CaseResult, FamilyResult, RequestFamily, ScanPoint
from utilities.file_utils import append_jsonl
from analyzer import family_pipeline
from analyzer.headless import HeadlessSession
from analyzer.revisit import probe_sink, new_run_marker_factory
from analyzer.scan import analyze_family


# ScanPoint 하나를 value_type에 따라 sqli, xss_stored, xss_reflected 경로로 라우팅
def _route_scan_point(sp: ScanPoint, target: dict, zap, marker_factory=None, findings_path: str | None = None) -> list[RequestFamily]:
    if has_destructive_action(target.get("params", {})):
        return []   # 파괴적 액션 있는 타겟은 검사 안함

    families: list[RequestFamily] = []

    if sp.value_type == "string":  # XSS는 문자열 파라미터만 대상
        discovery = run_discovery(sp, target, zap) # 특수문자가 반사되는 것들만 filtering.
        families.extend(generate_xss_families(sp, target, discovery)) # discovery에서 살아남은 것들 중에  xss_stored 가 아닌 것들만 extend로 풀어서 넣음

        # Phase 1: form 파라미터에만 sink probe — 마커가 저장·반사되면 stored XSS family 생성
        if marker_factory is not None and sp.location == "form":
            marker = marker_factory(sp.name)
            try:
                probe_result = probe_sink(sp, target, marker, requester, zap)
            except Exception as e:
                probe_result = None
                print(f"[WARN] probe_sink 실패, stored XSS 스킵: target={sp.target_id} param={sp.name} - {e}")
            if probe_result is not None and probe_result.sink_confirmed:
                stored = generate_stored_xss_families(sp, target)
                for f in stored:
                    f.sink_confirmed = probe_result.sink_confirmed
                    f.revisit_url = probe_result.revisit_url
                    f.probe_marker = probe_result.probe_marker
                families.extend(stored)
            elif probe_result is not None and probe_result.inconclusive and findings_path:
                append_jsonl(findings_path, {
                    "target_id": sp.target_id, "param": sp.name,
                    "stage": "probe", "status": "inconclusive",
                    "probe_marker": probe_result.probe_marker,
                    "revisit_url": probe_result.revisit_url,
                    "sink_note": "revisit_url GET 미반사 (base_url 강등 재시도 포함)",
                })
        else:
            families.extend(generate_stored_xss_families(sp, target))

    # SQLi boolean 판정용 — 이 ScanPoint가 원래 흔들리는 자리 + baseline 2회 요청의 유사도(이 타겟의 정상 기준점)를 실측 (family마다 X, ScanPoint당 1회)
    dynamic_markers, baseline_match_ratio = measure_dynamic_markers(sp, target, zap)
    families.extend(generate_sqli_families(sp, target, dynamic_markers, baseline_match_ratio))  # SQLi는 string/number 공통 대상, value_type 제한 없음

    return families


# collector ->  ScanPoint 라우팅 -> 요청 전송 -> 판정 -> findings.jsonl까지 ScanPoint 단위로 실행
def run_pipeline() -> str:
    out_dir, targets_path = run_collection() # 수집 시작
    with open(targets_path, encoding="utf-8") as f:
        targets = json.load(f)
    target_by_id = {f"t{idx}": target for idx, target in enumerate(targets)} # targets에 ID 부여 (ex. t0)
    scan_points = build_scan_points(targets) # Targets를 파라미터 단위로 쪼갬.

    requester.clear_cookie_store()  # 스캔 시작 시 1회, origin별 쿠키 초기화 (캡쳐 원본 쿠키는 지워지지 않음 -- 이전 스캔에서 누적된 쿠키 상태를 지우기 위함.)
    zap = requester.get_zap_client()
    marker_factory = new_run_marker_factory()  # 이번 스캔 실행 전체에서 고유 마커를 발급하는 팩토리 (ScanPoint당 1개)
    headless = HeadlessSession()  # 최초 headless 대상이 나올 때까지 실제 브라우저는 안 뜸 (lazy)

    results_path = os.path.join(out_dir, "request_results.jsonl") # 실행 결과 (요청, 응답 raw)
    findings_path = os.path.join(out_dir, "findings.jsonl") # 판정 결과
    total_count = 0
    fail_count = 0

    try:
        for sp in scan_points:
            target = target_by_id[sp.target_id]
            try:
                families = _route_scan_point(sp, target, zap, marker_factory=marker_factory, findings_path=findings_path)
            except Exception as e:  # 라우팅(Discovery 포함) 실패는 findings.jsonl에 에러 레코드만 남기고 다음 ScanPoint로 넘김.
                append_jsonl(findings_path, {
                    "target_id": sp.target_id, "param": sp.name,
                    "status": "error", "stage": "route", "error": str(e),
                })
                print(f"[ERROR] ScanPoint 라우팅 실패: target={sp.target_id} param={sp.name} - {e}")
                continue

            # 같은 ScanPoint의 모든 family는 baseline이 완전히 동일한 요청(같은 target/location, payload 없음)이므로
            # ScanPoint당 한 번만 실제로 보내고, 각 family는 자기 case_id를 붙인 채로 그 결과를 재사용.
            baseline_result: CaseResult | None = None
            if families:
                baseline_case = families[0].baseline
                try:
                    sent = requester.send(baseline_case, zap)
                except Exception as e:  # baseline 요청 실패는 이 ScanPoint의 모든 family에 동일하게 반영
                    baseline_result = CaseResult(case=baseline_case, status="error", error=str(e))
                    print(f"[ERROR] baseline 요청 실패: target={sp.target_id} param={sp.name} - {e}")
                else:
                    baseline_result = CaseResult(
                        case=baseline_case, status="ok",
                        response_status=sent["response_status"],
                        response_headers=sent["response_headers"],
                        response_body=sent["response_body"],
                        elapsed=sent["elapsed"],
                        effective_cookies=sent["effective_cookies"],
                    )

            for family in families:
                assert baseline_result is not None  # families가 비어있지 않으면 위에서 반드시 채워짐
                # baseline 슬롯은 위에서 미리 보낸 결과를 family 고유 case_id로만 갈아끼워 재사용 (재요청 없음)
                case_results: list[CaseResult] = [replace(baseline_result, case=family.baseline)]
                if case_results[0].status == "error":
                    fail_count += 1

                for case in family.mutations: # 원형 -> 변형 순서로 순회하고 요청 전송.
                    try:
                        sent = requester.send(case, zap)
                    except Exception as e:  # 개별 요청 실패는 로그만 남기고 계속 진행
                        fail_count += 1
                        case_results.append(CaseResult(case=case, status="error", error=str(e)))
                        print(f"[ERROR] 요청 실패: family={family.family_id} case={case.case_id} - {e}")
                        continue

                    case_results.append(CaseResult(
                        case=case, status="ok",
                        response_status=sent["response_status"],
                        response_headers=sent["response_headers"],
                        response_body=sent["response_body"],
                        elapsed=sent["elapsed"],
                        effective_cookies=sent["effective_cookies"],  # headless가 재현 시 쓸 쿠키값
                    ))
                total_count += len(case_results)

                family_result = FamilyResult(
                    family_id=family.family_id, vuln_type=family.vuln_type, technique=family.technique,
                    target_id=family.target_id, param=family.param, attack_id=family.attack_id,
                    baseline=case_results[0], mutations=case_results[1:],
                    dynamic_markers=family.dynamic_markers,
                    baseline_match_ratio=family.baseline_match_ratio,
                    sink_confirmed=family.sink_confirmed,
                    revisit_url=family.revisit_url,
                    probe_marker=family.probe_marker,
                    sink_note=family.sink_note,
                )
                family_dict = asdict(family_result)
                append_jsonl(results_path, family_dict)

                # SQLi 판정.
                if family.vuln_type == "sqli":  
                    try:
                        for finding_dict in analyze_family(family_dict): 
                            append_jsonl(findings_path, finding_dict)
                    except Exception as e:  # 판정 실패는 로그만 남기고 계속 진행
                        print(f"[ERROR] 판정 실패: family={family.family_id} - {e}")
                    continue

                # XSS 판정
                for i, case in enumerate(family.mutations): # xss 전용. baseline은 판정 기준
                    try:
                        finding = family_pipeline.judge_case(family_dict, family_dict["mutations"][i], headless) # 미리 변환해둔 dict 재사용
                        append_jsonl(findings_path, asdict(finding))
                    except Exception as e:  # 판정 실패는 로그만 남기고 계속 진행
                        print(f"[ERROR] XSS 판정 실패: family={family.family_id} - {e}")

        print(f"[RUN] request_results.jsonl -> {results_path} ({total_count - fail_count}건 성공, {fail_count}건 실패)")
        print(f"[RUN] findings.jsonl -> {findings_path}")
    finally:
        headless.close()  # 스캔 전체가 끝나면 브라우저/Playwright 프로세스 정리

    return results_path


if __name__ == "__main__":
    run_pipeline()