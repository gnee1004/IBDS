from __future__ import annotations

from attack_requests import RULES
from scan.match.matcher import AttackRule, rule_from_dict

# value_type 대상 정책은 orchestrator 라우팅에서 결정하므로 룰에는 위치·값 필터를 두지 않음
def _enrich(rule: dict) -> dict:
    return {
        "attack_id": rule["attack_id"],
        "vuln_type": rule["vuln_type"],
        "technique": rule["technique"],
        "sequence": rule["sequence"],
        "payload_templates": rule["payload_templates"],
    }


# 런타임용 — variant가 match_and_render에 넘길 AttackRule 목록
def get_rules() -> list[AttackRule]:
    return [rule_from_dict(_enrich(r)) for r in RULES]
