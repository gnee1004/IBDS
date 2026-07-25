"""
scan_targets.json + attack_request_list.json → list[RequestFamily]

HTTP 전송 없음. 파라미터 하나씩 payload로 교체한 family(baseline + mutations)를 반환.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from scan.mutation.models import MutationCase, RequestFamily
from scan.mutation.request_mutator import mutate_form, mutate_query

_CONTROL_ACTION_WORDS = frozenset({
    "submit", "login", "search", "change", "update", "delete",
    "create", "register", "logout", "reset", "cancel", "sign",
    "upload", "clear", "add", "remove",
})
_HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]{16,}$')


def _is_control_param(name: str, value: str) -> bool:
    """값이 submit/login 등 액션 단어이거나 이름과 같으면 제외."""
    v = (value or "").strip().lower()
    if not v:
        return False
    if v == (name or "").strip().lower():
        return True
    words = set(v.replace("+", " ").split())
    return bool(words & _CONTROL_ACTION_WORDS)


def _is_security_token(value: str) -> bool:
    """16자리 이상 16진수 → CSRF/세션 토큰으로 판단해 제외."""
    return bool(_HEX_TOKEN_RE.match((value or "").strip()))


def _expand_payloads(
    payload_templates: dict,
    sequence: list,
    base_value: str,
) -> list[tuple[str, str]]:
    """sequence 순서대로 (완성된 payload, step 이름) 목록 반환. baseline은 제외."""
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

    families: list[RequestFamily] = []

    for t_idx, target in enumerate(targets):
        method    = target.get("method", "GET").upper()
        base_url  = target.get("base_url", "")
        url       = target.get("url", base_url)
        params    = target.get("params") or {}
        scannable = set(target.get("scannable_params") or params.keys())
        location  = target.get("param_location", "query")
        headers   = dict(target.get("headers") or {})
        cookies   = dict(target.get("cookies") or {})
        body      = target.get("request_body") or ""
        body_type = "form" if (location == "body" and method == "POST") else "query"
        target_id = target.get("target_id") or f"t{t_idx}"

        for param_name, param_value in params.items():
            if param_name not in scannable:
                continue
            if _is_control_param(param_name, param_value):
                continue
            if _is_security_token(param_value):
                continue

            for rule in rules:
                family_id = f"{target_id}_{param_name}_{rule['attack_id']}"

                baseline = MutationCase(
                    case_id=f"{family_id}_baseline",
                    step="baseline",
                    method=method,
                    url=url,
                    headers=headers,
                    cookies=cookies,
                    body_type=body_type,
                    body=body,
                )

                mutations: list[MutationCase] = []
                for p_idx, (payload, step) in enumerate(
                    _expand_payloads(rule["payload_templates"], rule["sequence"], param_value)
                ):
                    if body_type == "form":
                        mutated_url  = base_url
                        mutated_body = mutate_form(body, param_name, payload)
                    else:
                        mutated_url  = mutate_query(url, param_name, payload)
                        mutated_body = body

                    mutations.append(MutationCase(
                        case_id=f"{family_id}_{step}_{p_idx}",
                        step=step,
                        method=method,
                        url=mutated_url,
                        headers=headers,
                        cookies=cookies,
                        body_type=body_type,
                        body=mutated_body,
                        payload=payload,
                        original_value=param_value,
                    ))

                families.append(RequestFamily(
                    family_id=family_id,
                    target_id=target_id,
                    param=param_name,
                    attack_id=rule["attack_id"],
                    vuln_type=rule["vuln_type"],
                    technique=rule["technique"],
                    baseline=baseline,
                    mutations=mutations,
                ))

    return families


if __name__ == "__main__":
    import sys
    import dataclasses

    t_path = sys.argv[1] if len(sys.argv) > 1 else "results/new/scan_targets.json"
    r_path = sys.argv[2] if len(sys.argv) > 2 else "attack_request_list.json"
    result = generate_families(t_path, r_path)
    print(json.dumps([dataclasses.asdict(f) for f in result], ensure_ascii=False, indent=2))
    print(f"\n총 {len(result)}개 family 생성", file=sys.stderr)
