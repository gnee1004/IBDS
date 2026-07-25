"""
변형기 — scan_targets.json + attack_request_list.json -> RequestFamily 목록

HTTP 전송 없음. ScanPoint 추출(1번) + 룰 매칭(2번) 후 request_builder(3번)로
요청을 조립해 family(baseline + mutations)를 반환
"""

from __future__ import annotations

import json
from pathlib import Path

from .models import RequestFamily
from .scan_point import build_scan_points
from .request_builder import build_baseline_case, build_mutation_case


# rule의 payload_templates를 {value}/{token}으로 치환한 (payload, step) 목록 반환, baseline step 제외
def _expand_payloads(
    payload_templates: dict,
    sequence: list,
    base_value: str,
) -> list[tuple[str, str]]:
    results = []
    for step in sequence:
        if step == "baseline":
            continue
        for tmpl in payload_templates.get(step, []):
            try:
                payload = tmpl.format(value=base_value, token="")
            except KeyError:
                payload = tmpl
            results.append((payload, step))
    return results


# 타겟 목록 + 룰 목록 -> ScanPoint마다 룰을 매칭해 RequestFamily 목록 생성
def generate_families(
    targets_path: str | Path,
    rules_path: str | Path,
    vuln_types: list[str] | None = None,
) -> list[RequestFamily]:
    with open(targets_path, encoding="utf-8") as f:
        targets = json.load(f)
    with open(rules_path, encoding="utf-8") as f:
        all_rules = json.load(f)["rules"]

    rules = all_rules if vuln_types is None else [
        r for r in all_rules if r["vuln_type"] in vuln_types
    ]

    target_by_id = {f"t{idx}": target for idx, target in enumerate(targets)}  # target_id -> 원본 target dict
    scan_points = build_scan_points(targets)

    families: list[RequestFamily] = []

    for sp in scan_points:
        target = target_by_id[sp.target_id]

        for rule in rules:
            family_id = f"{sp.target_id}_{sp.name}_{rule['attack_id']}"
            baseline = build_baseline_case(target, sp.location, f"{family_id}_baseline")

            mutations = [
                build_mutation_case(
                    target, sp.location, sp.name, sp.original_value,
                    payload, step, f"{family_id}_{step}_{p_idx}",
                )
                for p_idx, (payload, step) in enumerate(
                    _expand_payloads(rule["payload_templates"], rule["sequence"], sp.original_value)
                )
            ]

            families.append(RequestFamily(
                family_id=family_id,
                target_id=sp.target_id,
                param=sp.name,
                attack_id=rule["attack_id"],
                vuln_type=rule["vuln_type"],
                technique=rule["technique"],
                baseline=baseline,
                mutations=mutations,
            ))

    return families


if __name__ == "__main__":
    import sys
    from dataclasses import asdict

    t_path = sys.argv[1] if len(sys.argv) > 1 else "results/new/scan_targets.json"
    r_path = sys.argv[2] if len(sys.argv) > 2 else "attack_request_list.json"
    result = generate_families(t_path, r_path)
    print(json.dumps([asdict(f) for f in result], ensure_ascii=False, indent=2))
    print(f"\n총 {len(result)}개 family 생성", file=sys.stderr)
