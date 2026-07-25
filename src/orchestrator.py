import os
from dataclasses import asdict

from collector.main_collector import run_collection
from scan.mutation.variant import generate_families
from utilities.file_utils import save_json


# collector -> normalize -> mutation 순서로 실행해 families.json 생성, 그 경로를 반환
def run_pipeline() -> str:
    out_dir, targets_path = run_collection()
    families = generate_families(targets_path)
    families_path = os.path.join(out_dir, "request_famliy.json")
    save_json(families_path, [asdict(f) for f in families])
    print(f"[RUN] families.json -> {families_path} ({len(families)}개 family)")
    return families_path


if __name__ == "__main__":
    run_pipeline()
