from datetime import datetime
from pathlib import Path
from utilities.file_utils import load_json, save_json


# 실행 상태 파일의 교체 저장
def save_run(directory: Path, state: dict):
    directory.mkdir(parents=True, exist_ok=True)
    temporary = directory / "run_meta.tmp"
    save_json(str(temporary), state)
    temporary.replace(directory / "run_meta.json")


# 결과 디렉터리 밖 경로를 제외한 실행 폴더 목록
def run_dirs(project_root):
    base = Path(project_root) / "results"
    if not base.is_dir():
        return []
    return sorted(p for p in base.glob("collection_*")
                  if p.is_dir() and p.resolve().parent == base.resolve())


# 실행 식별자를 실제 결과 폴더로 연결
def resolve_run_dir(project_root, run_id):
    return next((p for p in run_dirs(project_root) if p.name == run_id), None)


# 가장 최근 실행 폴더 조회
def latest_out_dir(project_root):
    directories = run_dirs(project_root)
    return directories[-1] if directories else None


# 저장된 실행 상태 조회
def run_metadata(directory):
    return load_json(str(Path(directory) / "run_meta.json"), default={}) or {}


# 과거 실행과 중단 실행 목록 조회
def list_runs(project_root):
    runs = []
    for directory in reversed(run_dirs(project_root)):
        meta = run_metadata(directory)
        label = meta.get("started_at")
        if not label:
            try:
                label = datetime.strptime(directory.name[:26], "collection_%Y%m%d_%H%M%S").isoformat(sep=" ")
            except ValueError:
                label = directory.name
        runs.append({"id": directory.name, "label": label, "stage": meta.get("stage", "legacy"),
                     "failed": meta.get("failed", 0), "error": meta.get("error")})
    return runs
