from __future__ import annotations

import json
from pathlib import Path

from payload import sqli, xss

RULES_PATH = Path(__file__).resolve().parents[3] / "attack_request_list.json"

_STRENGTH = "HIGH"


def _sqli_append(payloads: list[dict]) -> list[str]:
    return ["{value}" + p["payload"] for p in payloads]


def _xss_asis(payloads: list[dict]) -> list[str]:
    return [p["payload"] for p in payloads]


def _sqli_rules() -> list[dict]:
    error = sqli.get_by_category("error_meta", _STRENGTH)
    time = sqli.get_by_category("time", _STRENGTH)
    bool_and = sqli.get_by_category("bool_and", _STRENGTH)
    true = [p for p in bool_and if p["family"].endswith("_true")]
    false = [p for p in bool_and if p["family"].endswith("_false")]

    return [
        {
            "attack_id": "AR-SQLI-ERROR",
            "vuln_type": "sqli",
            "technique": "error",
            "sequence": ["baseline", "error"],
            "payload_templates": {"error": _sqli_append(error)},
            "allowed_locations": ["query", "body"],
            "allowed_value_types": ["string", "number"],
        },
        {
            "attack_id": "AR-SQLI-BOOLEAN",
            "vuln_type": "sqli",
            "technique": "boolean",
            "sequence": ["baseline", "bool_true", "bool_false"],
            "payload_templates": {
                "bool_true": _sqli_append(true),
                "bool_false": _sqli_append(false),
            },
            "allowed_locations": ["query", "body"],
            "allowed_value_types": ["string", "number"],
        },
        {
            "attack_id": "AR-SQLI-TIME",
            "vuln_type": "sqli",
            "technique": "time",
            "sequence": ["baseline", "time"],
            "payload_templates": {"time": _sqli_append(time)},
            "allowed_locations": ["query", "body"],
            "allowed_value_types": ["string", "number"],
        },
    ]


def _xss_rules() -> list[dict]:
    reflected = xss.get_by_context("reflected", _STRENGTH)
    return [
        {
            "attack_id": "AR-XSS-REFLECTED",
            "vuln_type": "xss",
            "technique": "reflected",
            "sequence": ["baseline", "reflect"],
            "payload_templates": {"reflect": _xss_asis(reflected)},
            "allowed_locations": ["query", "body"],
            "allowed_value_types": ["string"],
        },
    ]


def build_rule_list() -> dict:
    return {"version": 1, "rules": _sqli_rules() + _xss_rules()}


def write_rule_list(path: str | Path = RULES_PATH) -> Path:
    path = Path(path)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(build_rule_list(), f, ensure_ascii=False, indent=2)
    return path


if __name__ == "__main__":
    out = write_rule_list()
    doc = build_rule_list()
    total = sum(len(v) for r in doc["rules"] for v in r["payload_templates"].values())
    print(f"{out}  (룰 {len(doc['rules'])}개, payload {total}개)")
