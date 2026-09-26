from __future__ import annotations

from attack_requests import RULES
from scan.match.matcher import AttackRule, rule_from_dict

_ALL_LOCATIONS = ["query", "form", "json"]


def _allowed(rule: dict) -> tuple[list[str], list[str]]:
    # value_type은 표기 힌트일 뿐이라 string/number 모두 허용 (실제 주입 가능 여부는 discovery가 판정)
    return _ALL_LOCATIONS, ["string", "number"]


def _enrich(rule: dict) -> dict:
    locations, value_types = _allowed(rule)
    return {
        "attack_id": rule["attack_id"],
        "vuln_type": rule["vuln_type"],
        "technique": rule["technique"],
        "sequence": rule["sequence"],
        "payload_templates": rule["payload_templates"],
        "allowed_locations": locations,
        "allowed_value_types": value_types,
    }


# 런타임용 — variant가 match_and_render에 넘길 AttackRule 목록
def get_rules() -> list[AttackRule]:
    return [rule_from_dict(_enrich(r)) for r in RULES]
