import os
from dataclasses import asdict

from collector.main_collector import run_collection
from scan.mutation.variant import generate_families
from scan.requester import requester
from utilities.file_utils import save_json


# collector -> normalize -> mutation -> requester 순서로 실행해 request_results.json 생성
def run_pipeline() -> str:
    out_dir, targets_path = run_collection()
    families = generate_families(targets_path)
    families_path = os.path.join(out_dir, "request_famliy.json")
    save_json(families_path, [asdict(f) for f in families])
    print(f"[RUN] families.json -> {families_path} ({len(families)}개 family)")

    requester.clear_cookie_store()  # 스캔 시작 시 1회, origin별 쿠키 초기화
    zap = requester.get_zap_client()

    results = []
    fail_count = 0
    for family in families:
        for case in [family.baseline, *family.mutations]:
            try:
                result = requester.send(case, zap)
            except Exception as e:  # 개별 요청 실패는 로그만 남기고 계속 진행
                fail_count += 1
                print(f"[ERROR] 요청 실패: family={family.family_id} case={case.case_id} - {e}")
                continue
            results.append({"family_id": family.family_id, **result})

    results_path = os.path.join(out_dir, "request_results.json")
    save_json(results_path, results)
    print(f"[RUN] request_results.json -> {results_path} ({len(results)}건 성공, {fail_count}건 실패)")
    return results_path


if __name__ == "__main__":
    run_pipeline()
