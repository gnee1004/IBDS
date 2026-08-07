import os
from dataclasses import asdict

from collector.main_collector import run_collection
from scan. mutation.request_builder import generate_families
from scan.requester import requester
from scan.models import CaseResult, FamilyResult
from analyzer.scan import analyze_results
from utilities.file_utils import save_json, append_jsonl
from analyzer import family_pipeline


# collector -> normalize -> mutation -> requester 순서로 실행해 request_results.json 생성
def run_pipeline() -> str:
    out_dir, targets_path = run_collection()
    families = generate_families(targets_path)
    families_path = os.path.join(out_dir, "request_famliy.json")
    save_json(families_path, [asdict(f) for f in families])
    print(f"[RUN] families.json -> {families_path} ({len(families)}개 family)")

    requester.clear_cookie_store()  # 스캔 시작 시 1회, origin별 쿠키 초기화
    zap = requester.get_zap_client()

    results_path = os.path.join(out_dir, "request_results.jsonl")  # family 끝날 때마다 한 줄씩 append
    total_count = 0
    fail_count = 0
    for family in families:
        case_results: list[CaseResult] = []
        for case in [family.baseline, *family.mutations]:
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
                effective_cookies=sent["effective_cookies"], # 나중에 headless browser가 쓸 cookie값
            ))
        total_count += len(case_results)

        # case_results[0]은 항상 baseline (baseline을 맨 앞에 두고 순회해서)
        family_result = FamilyResult(
            family_id=family.family_id,
            vuln_type=family.vuln_type,
            technique=family.technique,
            target_id=family.target_id,
            param=family.param,
            attack_id=family.attack_id,
            baseline=case_results[0],
            mutations=case_results[1:],
        )
        append_jsonl(results_path, asdict(family_result))  # family 끝나는 즉시 기록. 중간에 실패해도 이전 family는 보존

    print(f"[RUN] request_results.jsonl -> {results_path} ({total_count - fail_count}건 성공, {fail_count}건 실패)")

    findings_path = analyze_results(results_path)          # sqli + xss 판정 -> findings.json
    xss_findings_path = family_pipeline.run(results_path)  # xss headless 확인 -> xss_findings.jsonl
    print(f"[RUN] xss_findings.jsonl -> {xss_findings_path}")

    return findings_path


if __name__ == "__main__":
    run_pipeline()
