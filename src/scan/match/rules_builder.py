from __future__ import annotations

from payload.sqli import SQLI_RULES
from payload.xss import XSS_RULES
from scan.match.matcher import AttackRule, rule_from_dict

_ALL_LOCATIONS = ["query", "form", "json"]


def _allowed(rule: dict) -> tuple[list[str], list[str]]:
    if rule["vuln_type"] == "sqli":
        return _ALL_LOCATIONS, ["string", "number"]
    # xss / open_redirect 등 마크업 주입 계열 — 문자열 파라미터만
    return _ALL_LOCATIONS, ["string"]


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
    return [rule_from_dict(_enrich(r)) for r in SQLI_RULES + XSS_RULES]
