import argparse
import os
import sys
from datetime import datetime
from pprint import pprint

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_SRC_ROOT = os.path.dirname(_THIS_DIR)  # src/
_PROJECT_ROOT = os.path.dirname(_SRC_ROOT)  # 리포 루트, src 밖 경로용
sys.path.insert(0, _SRC_ROOT)  # src 루트 패키지 import용

from utilities.file_utils import load_json, save_json, normalize_base_url
from collector.zap_collector import ZapCollector
from scan.normalize.importer import to_targets

_ZAP_CONFIG = os.path.join(_PROJECT_ROOT, "config", "zap_config.json")
_TARGET_CONFIG = os.path.join(_PROJECT_ROOT, "config", "target_config.json")
_DANGER_URL_FILE = os.path.join(_THIS_DIR, "spider_exclude.txt")

_DEFAULT_AJAX_TIMEOUT = 300  # Ajax spider timeout을 초 단위로 짧게 잡음. (ZAP 자체 제한시간은 60분)


# Ajax Spider는 SPA/JS-heavy 사이트 대응용 선택 옵션, 기본은 Spider only
def _parse_args():
    parser = argparse.ArgumentParser(description="ZAP 수집기")
    parser.add_argument("--ajax", action="store_true", help="Ajax Spider 추가 실행 (기본: 비활성)")
    parser.add_argument("--ajax-timeout", type=int, default=_DEFAULT_AJAX_TIMEOUT, help=f"Ajax Spider 최대 대기 시간(초), 기본 {_DEFAULT_AJAX_TIMEOUT}")
    return parser.parse_args()


# 위험 URL 정규식 목록 로드 (빈 줄/주석 제외)
def _load_danger_patterns(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# ZAP 수집 + normalize 실행, (out_dir, scan_targets.json 경로) 반환. 실패 시 예외를 그대로 던짐
def run_collection(ajax: bool = False, ajax_timeout: int = _DEFAULT_AJAX_TIMEOUT) -> tuple[str, str]:
    target_cfg = load_json(_TARGET_CONFIG, default={})
    target_url = normalize_base_url(target_cfg.get("target_url", ""))
    if not target_url:
        raise ValueError("target_config.json에 target_url이 없습니다.")

    danger_patterns = _load_danger_patterns(_DANGER_URL_FILE)

    out_dir = os.path.join(_PROJECT_ROOT, "results", datetime.now().strftime("collection_%Y%m%d_%H%M%S"))
    os.makedirs(out_dir, exist_ok=True)

    collector = ZapCollector.from_config(_ZAP_CONFIG)
    print(f"[ZAP] 버전: {collector.zap.core.version}")

    collector.restrict_to_target_domain(target_url)
    collector.setup_context(target_url)
    collector.exclude_danger_urls(danger_patterns)  # Spider 실행 전 필수 등록

    collector.access_target(target_url)
    collector.capture_session(target_url)  # 현재 세션 그대로 가져오기

    print(f"[COLLECT] Spider 시작: {target_url}")
    collector.run_spider(target_url)

    ajax_meta = {
        "ajax_spider_enabled": ajax,
        "ajax_spider_status": None,
        "ajax_spider_completed": None,
        "ajax_spider_timeout": ajax_timeout,
        "ajax_spider_elapsed_seconds": None,
    }
    if ajax:
        print(f"[COLLECT] Ajax Spider 시작 (최대 {ajax_timeout}초): {target_url}")
        result = collector.run_ajax_spider(target_url, ajax_timeout)  # 타임아웃 초과해도 실패 처리 안 함
        ajax_meta["ajax_spider_status"] = result["status"]
        ajax_meta["ajax_spider_completed"] = result["completed"]
        ajax_meta["ajax_spider_elapsed_seconds"] = result["elapsed_seconds"]

    sample = collector.get_messages_sample(target_url, count=3)
    print("[ZAP] raw 메시지 샘플 (3건):")
    pprint(sample)
    sample_path = os.path.join(out_dir, "zap_raw_messages_sample.json")
    save_json(sample_path, sample)
    print(f"[ZAP] zap_raw_messages_sample.json -> {sample_path}")

    messages = collector.get_all_messages(target_url)

    print(f"[ZAP] 전체 메시지 {len(messages)}건 수집")
    messages_path = os.path.join(out_dir, "zap_messages.json")
    save_json(messages_path, messages)
    print(f"[ZAP] zap_messages.json -> {messages_path}")

    # 수집된 raw 메시지를 scan target으로 정규화
    targets = to_targets(messages)
    targets_path = os.path.join(out_dir, "scan_targets.json")
    save_json(targets_path, [t.to_dict() for t in targets])
    print(f"[ZAP] scan_targets.json -> {targets_path} ({len(targets)}건)")

    meta_path = os.path.join(out_dir, "collection_meta.json")
    save_json(meta_path, ajax_meta)
    print(f"[ZAP] collection_meta.json -> {meta_path}")

    return out_dir, targets_path


# CLI 진입점 — 인자 파싱 후 run_collection() 호출, 실패 시 기존과 동일한 형식으로 출력 후 종료
def main():
    args = _parse_args()
    try:
        out_dir, targets_path = run_collection(ajax=args.ajax, ajax_timeout=args.ajax_timeout)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] ZAP API 연결 실패: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"[COLLECT] 완료: {targets_path}")


if __name__ == "__main__":
    main()
