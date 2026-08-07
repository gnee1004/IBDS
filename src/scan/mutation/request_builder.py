from __future__ import annotations

import json
from pathlib import Path

from scan.match.matcher import match_and_render
from scan.match.rules_builder import get_rules
from ..models import RequestFamily
from .scan_point import build_scan_points
from .variant import build_baseline_case, build_mutation_case

_DOM_TECHNIQUE = "dom"  # DOM 계열은 payload를 URL fragment로 주입 (파라미터 값 아님)


# case_id용 step 축약 — 모든 mutation step에 공통으로 붙는 "attack" 단어 제거
# 예: "true_attack"->"true", "error_attack"->"error", "attack"->"a"
def _short_step(step: str) -> str:
    s = step.removesuffix("attack").rstrip("_")
    return s or "a"


# 타겟 목록 -> ScanPoint마다 룰을 매칭(scan.match)해 RequestFamily 목록 생성
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
        target = target_by_id[sp.target_id]

        for matched in match_and_render(sp, rules):
            family_id = f"{sp.target_id}_{sp.name}_{matched.technique}"
            baseline = build_baseline_case(target, sp.location, f"{family_id}_base")
            is_dom = matched.technique == _DOM_TECHNIQUE

            mutations = []
            p_idx = 0
            for step in matched.sequence:
                if step == "baseline":
                    continue
                for payload in matched.rendered_payloads.get(step, []):
                    mutations.append(build_mutation_case(
                        target, sp.location, sp.name, sp.original_value,
                        payload, step, f"{family_id}_{_short_step(step)}{p_idx}",
                        inject_fragment=is_dom,
                    ))
                    p_idx += 1

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


if __name__ == "__main__":
    import sys
    from dataclasses import asdict

    t_path = sys.argv[1] if len(sys.argv) > 1 else "results/new/scan_targets.json"
    result = generate_families(t_path)
    print(json.dumps([asdict(f) for f in result], ensure_ascii=False, indent=2))
    print(f"\n총 {len(result)}개 family 생성", file=sys.stderr)