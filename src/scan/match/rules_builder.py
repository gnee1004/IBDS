from __future__ import annotations

from attack_requests import RULES
from scan.match.matcher import AttackRule, rule_from_dict

_ALL_LOCATIONS = ["query", "form", "json"]


def _allowed(rule: dict) -> tuple[list[str], list[str]]:
    # #13: value_type은 관측값의 표기 힌트일 뿐 서버 검증 보장이 아니므로, 검사 대상을
    # 표기(number/string)로 배제하지 않는다. 실제 반사·주입 여부는 discovery가 판정한다.
    # 현재 모든 vuln_type이 두 표기를 모두 허용하므로 rule별 분기가 없다.
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
