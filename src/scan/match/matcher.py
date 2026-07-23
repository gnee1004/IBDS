from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from models import MatchedRule, ScanPoint

# 룰 스키마
@dataclass
class AttackRule:
    attack_id: str                              
    vuln_type: str                              
    technique: str                             
    sequence: list[str]                         
    payload_templates: dict[str, list[str]]     
    allowed_locations: list[str] = field(default_factory=list)   
    allowed_value_types: list[str] = field(default_factory=list) 

# 룰 로드
# 룰 JSON 파일을 읽어서 AttackRule 리스트로 변환.
def load_rules(rules_path: str | Path) -> list[AttackRule]:
    with open(rules_path, encoding="utf-8") as f:
        raw = json.load(f)
 
    rules: list[AttackRule] = []
    for item in raw.get("rules", []):
        rules.append(AttackRule(
            attack_id=item["attack_id"],
            vuln_type=item["vuln_type"],
            technique=item["technique"],
            sequence=list(item.get("sequence", [])),
            payload_templates=dict(item.get("payload_templates", {})),
            allowed_locations=list(item.get("allowed_locations", [])),
            allowed_value_types=list(item.get("allowed_value_types", [])),
        ))
    return rules


# 매칭 판정
def _is_applicable(point: ScanPoint, rule: AttackRule) -> bool:

    if rule.allowed_locations and point.location not in rule.allowed_locations:
        return False
    if rule.allowed_value_types and point.value_type not in rule.allowed_value_types:
        return False
    return True


#치환
def _render_templates(
    payload_templates: dict[str, list[str]],
    original_value: str,
) -> dict[str, list[str]]:

    rendered: dict[str, list[str]] = {}
    for step, templates in payload_templates.items():
        rendered[step] = [
            tmpl.replace("{value}", str(original_value))
            for tmpl in templates
        ]
    return rendered

def match_and_render(
    point: ScanPoint,
    rules: list[AttackRule],
) -> list[MatchedRule]:

    matched: list[MatchedRule] = []
    for rule in rules:
        if not _is_applicable(point, rule):
            continue
        matched.append(MatchedRule(
            attack_id=rule.attack_id,
            vuln_type=rule.vuln_type,
            technique=rule.technique,
            sequence=list(rule.sequence),
            rendered_payloads=_render_templates(rule.payload_templates, point.original_value),
        ))
    return matched
