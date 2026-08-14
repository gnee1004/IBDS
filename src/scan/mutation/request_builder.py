from __future__ import annotations

import json
from pathlib import Path
from typing import Callable

from scan.match.matcher import AttackRule, match_and_render
from scan.match.rules_builder import get_rules
from ..models import DiscoveryResult, RequestFamily, ScanPoint
from .scan_point import build_scan_points
from .variant import build_baseline_case, build_mutation_case


# ScanPoint 하나 + 룰 목록 -> RequestFamily 목록. payload_filter가 있으면 조건을 만족하는 payload만 mutation으로 남김
def build_families_for_point(
    sp: ScanPoint,
    target: dict,
    rules: list[AttackRule],
    payload_filter: Callable[[str], bool] | None = None,
) -> list[RequestFamily]:
    families: list[RequestFamily] = []

    for matched in match_and_render(sp, rules):
        family_id = f"{sp.target_id}_{sp.name}_{matched.attack_id}"
        baseline = build_baseline_case(target, sp.location, f"{family_id}_baseline")

        mutations = []
        p_idx = 0
        for step in matched.sequence:
            if step == "baseline":
                continue
            for payload in matched.rendered_payloads.get(step, []):
                if payload_filter is not None and not payload_filter(payload):
                    continue  # Discovery 결과 등으로 실행 불가능하다고 판단된 payload 제외
                mutations.append(build_mutation_case(
                    target, sp.location, sp.name, sp.original_value,
                    payload, step, f"{family_id}_{step}_{p_idx}",
                ))
                p_idx += 1

        if not mutations:
            continue  # 살아남은 payload가 없으면 family 자체 미생성

        families.append(RequestFamily(
            family_id=family_id,
            target_id=sp.target_id,
            param=sp.name,
            attack_id=matched.attack_id,
            vuln_type=matched.vuln_type,
            technique=matched.technique,
            baseline=baseline,
            mutations=mutations,
        ))

    return families


# 타겟 목록 -> 모든 ScanPoint에 룰을 매칭해 RequestFamily 목록 생성 (기존 배치 진입점, 동작 변화 없음)
def generate_families(
    targets_path: str | Path,
    vuln_types: list[str] | None = None,
) -> list[RequestFamily]:
    with open(targets_path, encoding="utf-8") as f:
        targets = json.load(f)

    rules = get_rules()
    if vuln_types is not None:
        rules = [r for r in rules if r.vuln_type in vuln_types]

    target_by_id = {f"t{idx}": target for idx, target in enumerate(targets)}
    scan_points = build_scan_points(targets)

    families: list[RequestFamily] = []
    for sp in scan_points:
        families.extend(build_families_for_point(sp, target_by_id[sp.target_id], rules))
    return families


# discovery.py의 _CANDIDATE_SPECIALS와 반드시 같은 집합을 유지해야 함 — 한 쪽만 수정 시 issubset 비교가 어긋남
_SPECIAL_CHARS_WATCHLIST = ["<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"]


# payload 문자열에 실제로 등장하는 특수문자 집합 — 이 payload가 살아남으려면 필요한 최소 조건
def _required_specials(payload: str) -> set[str]:
    return {ch for ch in _SPECIAL_CHARS_WATCHLIST if ch in payload}


# reflected XSS 전용 family 생성 — Discovery 결과로 실행 불가능한 payload/family를 사전 제거
def generate_xss_families(sp: ScanPoint, target: dict, discovery: DiscoveryResult) -> list[RequestFamily]:
    if not discovery.reflected:
        return []  # 반사 자체가 안 되면 XSS family를 만들 이유가 없음

    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique != "stored"]
    return build_families_for_point(
        sp, target, rules,
        payload_filter=lambda payload: _required_specials(payload).issubset(discovery.valid_specials),
    )


# Stored XSS 전용 family 생성 — Discovery 없이, form(POST) 파라미터에만, PL-XSS-STORED 룰만 적용
def generate_stored_xss_families(sp: ScanPoint, target: dict) -> list[RequestFamily]:
    if sp.location != "form":
        return []
    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique == "stored"]
    return build_families_for_point(sp, target, rules)


if __name__ == "__main__":
    import sys
    from dataclasses import asdict

    t_path = sys.argv[1] if len(sys.argv) > 1 else "results/new/scan_targets.json"
    result = generate_families(t_path)
    print(json.dumps([asdict(f) for f in result], ensure_ascii=False, indent=2))
    print(f"\n총 {len(result)}개 family 생성", file=sys.stderr)
