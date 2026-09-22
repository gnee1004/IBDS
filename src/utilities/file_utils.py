import os
import json


# JSON 파일을 읽고 실패하면 기본값 반환
def load_json(path: str, default=None):
    if not os.path.exists(path):
        return default
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


# 파일의 부모 디렉터리를 생성
def ensure_parent_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)


# JSON 파일을 저장
def save_json(path: str, data, indent: int = 2) -> None:
    ensure_parent_dir(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=indent)


# JSONL 파일에 한 줄 append, 호출 시점마다 즉시 flush (중간 실패해도 이전 줄은 보존)
def append_jsonl(path: str, data) -> None:
    ensure_parent_dir(path)
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(data, ensure_ascii=False) + "\n")
        f.flush()


# base URL 끝의 슬래시를 제거하여 반환
def normalize_base_url(url: str) -> str:
    return (url or "").strip().rstrip("/")