"""
변형기 1단계 — RequestTarget(scan_targets.json) -> ScanPoint 목록 변환

normalize 단계(scan/normalize/target.py)에서 이미 걸러진 scannable_params를
받아, 파라미터 위치를 query/form/json으로 정규화한 ScanPoint를 타겟마다 생성한다.
"""

from __future__ import annotations

from .models import ScanPoint


# int() 변환 가능 여부로 value_type("number" 또는 "string") 판정
def _is_numeric(value: str) -> bool:
    try:
        int(value)
        return True
    except (TypeError, ValueError):
        return False


# param_location을 query/form/json으로 정규화 (body -> form, 나머지는 그대로 통과)
def _normalize_location(location: str) -> str:
    return "form" if location == "body" else location


# 타겟 목록에서 스캔 가능한 파라미터만 추출해 ScanPoint 목록으로 변환
def build_scan_points(targets: list[dict]) -> list[ScanPoint]:
    scan_points: list[ScanPoint] = []

    for idx, target in enumerate(targets):
        target_id = f"t{idx}"
        params = target.get("params") or {}
        scannable = set(target.get("scannable_params") or params.keys())
        location = _normalize_location(target.get("param_location", "query"))

        for name, value in params.items():
            if name not in scannable:
                continue

            scan_points.append(ScanPoint(
                target_id=target_id,
                name=name,
                location=location,
                original_value=str(value),
                value_type="number" if _is_numeric(value) else "string",
            ))

    return scan_points
