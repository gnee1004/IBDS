"""
꼮 지워야 하는거.
scan_targets.json → HTTP task 목록 변환

XSS 탐지 흐름 (2단계):
  1단계 probe  : IBDS_REFLECT_{token} / IBDS_ESC_{token}<>"'& 주입 → 반사 위치/필터 파악
  2단계 attack : probe 결과를 바탕으로 컨텍스트 맞는 XSS 페이로드 주입

SQLi 탐지 흐름:
  attack_requests payload_templates의 {value} placeholder를 base_value로 치환 후 replace 주입
  (executor inject_mode=replace로 통일, append 없음)
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path
from typing import List

_ATTACK_LIST_PATH = Path("attack_request_list.json")


def _load_rules(vuln_type: str) -> list:
    with open(_ATTACK_LIST_PATH, encoding="utf-8") as f:
        data = json.load(f)
    return [r for r in data["rules"] if r["vuln_type"] == vuln_type]

_CSRF_KEYWORDS = {"token", "csrf", "nonce"}

_TECHNIQUE_TO_PTYPE = {
    "error":    "SQLI_ERROR_META",
    "boolean":  "SQLI_BOOLEAN",
    "time":     "SQLI_TIME_MYSQL",
    "order_by": "SQLI_ORDERBY",
}

_STRENGTH_TECHNIQUES = {
    "LOW":    {"error"},
    "MEDIUM": {"error", "boolean"},
    "HIGH":   {"error", "boolean", "time"},
    "INSANE": {"error", "boolean", "time", "order_by"},
}


def _normalize_target(target: dict) -> dict:
    if "parameters" in target:
        return target
    params = target.get("params") or {}
    scannable = set(target.get("scannable_params") or params.keys())
    param_location = target.get("param_location", "query")
    parameters = [
        {
            "name": name,
            "scan": name in scannable,
            "sample_values": [value] if value else [],
            "request_location": param_location,
        }
        for name, value in params.items()
    ]
    return {**target, "parameters": parameters, "can_scan": bool(scannable)}


def load_targets(session_dir: str | Path) -> List[dict]:
    path = Path(session_dir) / "scan_targets.json"
    with open(path, encoding="utf-8") as f:
        raw = json.load(f)
    return [_normalize_target(t) for t in raw]


def _base_params(parameters: List[dict]) -> dict:
    result: dict = {}
    for p in parameters:
        name = p.get("name", "")
        if not name:
            continue
        vals = p.get("sample_values") or []
        result[name] = str(vals[0]) if vals else ""
    return result


def _base_value(param: dict) -> str:
    vals = param.get("sample_values") or []
    return str(vals[0]) if vals else ""


def _needs_csrf(parameters: List[dict]) -> bool:
    return any(
        not p.get("scan", True)
        and any(kw in (p.get("name") or "").lower() for kw in _CSRF_KEYWORDS)
        for p in parameters
    )


def _expand_templates(
    payload_templates: dict,
    sequence: list,
    base_value: str,
) -> list[tuple[str, str]]:
    """attack step의 (완성 payload, step 이름) 목록. baseline은 제외."""
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


def _common_task_fields(
    target: dict,
    param: dict,
    base_params: dict,
    target_idx: int,
    param_idx: int,
) -> dict:
    return {
        "url":             target.get("base_url", ""),
        "method":          target.get("method", "GET").upper(),
        "enctype":         target.get("enctype", "application/x-www-form-urlencoded"),
        "inject_location": param.get("request_location", "query"),
        "inject_param":    param.get("name", ""),
        "base_params":     dict(base_params),
        "base_headers":    dict(target.get("headers") or {}),
        "base_cookies":    dict(target.get("cookies") or {}),
        "base_value":      _base_value(param),
        "needs_csrf_refresh": _needs_csrf(target.get("parameters") or []),
        "source_url":      target.get("base_url", ""),
    }


def build_sqli_tasks(
    targets: List[dict],
    strength: str = "MEDIUM",
) -> List[dict]:
    allowed = _STRENGTH_TECHNIQUES.get(strength.upper(), _STRENGTH_TECHNIQUES["MEDIUM"])
    sqli_rules = [r for r in _load_rules("sqli") if r["technique"] in allowed]

    all_tasks: List[dict] = []

    for target_idx, target in enumerate(targets):
        if not target.get("can_scan", True):
            continue

        parameters = target.get("parameters") or []
        base_params = _base_params(parameters)
        scan_params = [p for p in parameters if p.get("scan", True)]

        for param_idx, param in enumerate(scan_params):
            param_name = param.get("name", "")
            orig_value = _base_value(param)
            common = _common_task_fields(target, param, base_params, target_idx, param_idx)

            for rule in sqli_rules:
                technique = rule["technique"]
                ptype = _TECHNIQUE_TO_PTYPE.get(technique, "SQLI_ERROR_META")
                payloads = _expand_templates(rule["payload_templates"], rule["sequence"], orig_value)

                for p_idx, (payload, step) in enumerate(payloads):
                    all_tasks.append({
                        **common,
                        "id":             f"{target_idx}_{param_name}_sqli_{technique}_{p_idx}",
                        "point":          param_name,
                        "payload":        payload,
                        "payload_type":   ptype,
                        "payload_family": f"{technique}_{step}",
                        "inject_mode":    "replace",
                        "meta": {
                            "role":         target.get("role", "guest"),
                            "target_index": target_idx,
                            "param_index":  param_idx,
                            "vuln_scan":    "sqli",
                            "attack_id":    rule["attack_id"],
                            "step":         step,
                        },
                    })

    return all_tasks


def build_xss_probe_tasks(targets: List[dict]) -> List[dict]:
    """XSS 1단계: reflection + escape probe 태스크 생성."""
    xss_rules = {r["technique"]: r for r in _load_rules("xss")}

    reflect_rule = xss_rules.get("reflection")
    escape_rule  = xss_rules.get("escape")

    all_tasks: List[dict] = []

    for target_idx, target in enumerate(targets):
        if not target.get("can_scan", True):
            continue

        parameters = target.get("parameters") or []
        base_params = _base_params(parameters)
        scan_params = [p for p in parameters if p.get("scan", True)]

        for param_idx, param in enumerate(scan_params):
            param_name = param.get("name", "")
            orig_value = _base_value(param)
            common = _common_task_fields(target, param, base_params, target_idx, param_idx)

            # (url, param)별 고정 토큰 — 두 probe가 같은 token 공유해서 analyzer가 매핑 가능
            token = secrets.token_hex(6).upper()

            for probe_type, rule in [("reflection", reflect_rule), ("escape", escape_rule)]:
                if not rule:
                    continue
                # baseline 제외 첫 번째 step 페이로드만 사용
                for step in rule["sequence"]:
                    if step == "baseline":
                        continue
                    for t_idx, tmpl in enumerate(rule["payload_templates"].get(step, [])):
                        try:
                            payload = tmpl.format(token=token, value=orig_value)
                        except KeyError:
                            payload = tmpl

                        all_tasks.append({
                            **common,
                            "id":             f"{target_idx}_{param_name}_xss_probe_{probe_type}_{t_idx}",
                            "point":          param_name,
                            "payload":        payload,
                            "payload_type":   "XSS_PROBE",
                            "payload_family": f"probe_{probe_type}",
                            "inject_mode":    "replace",
                            "meta": {
                                "role":           target.get("role", "guest"),
                                "target_index":   target_idx,
                                "param_index":    param_idx,
                                "vuln_scan":      "xss",
                                "attack_id":      rule["attack_id"],
                                "step":           step,
                                "xss_probe_token": token,
                                "xss_probe_type":  probe_type,
                            },
                        })
                    break  # 첫 번째 non-baseline step만 사용

    return all_tasks


def build_xss_attack_tasks(
    targets: List[dict],
    reflected_params: dict,
) -> List[dict]:
    """XSS 2단계: probe에서 반사 확인된 파라미터에만 실제 공격 페이로드 주입.

    reflected_params: {(url, param_name): {"context": str, "escaped_chars": set}}
    """
    all_tasks: List[dict] = []

    for target_idx, target in enumerate(targets):
        if not target.get("can_scan", True):
            continue

        parameters = target.get("parameters") or []
        base_params = _base_params(parameters)
        scan_params = [p for p in parameters if p.get("scan", True)]

        for param_idx, param in enumerate(scan_params):
            param_name = param.get("name", "")
            common = _common_task_fields(target, param, base_params, target_idx, param_idx)

            probe_info = reflected_params.get((common["url"], param_name))
            if not probe_info:
                continue

            context = probe_info.get("context", "body")
            escaped_chars = probe_info.get("escaped_chars", set())

            for p_idx, (payload, family) in enumerate(_select_xss_payloads(context, escaped_chars)):
                all_tasks.append({
                    **common,
                    "id":             f"{target_idx}_{param_name}_xss_attack_{p_idx}",
                    "point":          param_name,
                    "payload":        payload,
                    "payload_type":   "REFLECTED_XSS",
                    "payload_family": family,
                    "inject_mode":    "replace",
                    "meta": {
                        "role":         target.get("role", "guest"),
                        "target_index": target_idx,
                        "param_index":  param_idx,
                        "vuln_scan":    "xss",
                        "xss_context":  context,
                    },
                })

    return all_tasks


def _select_xss_payloads(context: str, escaped_chars: set) -> list[tuple[str, str]]:
    """컨텍스트 + 필터 특성 → (payload, family) 목록."""
    if context == "script":
        if '"' not in escaped_chars:
            return [('";alert(1);//', "sc_dq_break"), ('";alert(document.domain);//', "sc_dq_domain")]
        if "'" not in escaped_chars:
            return [("';alert(1);//", "sc_sq_break"), ("';alert(document.domain);//", "sc_sq_domain")]
        return [("alert`1`", "sc_backtick")]

    if context == "attr_value":
        if '"' not in escaped_chars and "<" not in escaped_chars:
            return [('"><img src=x onerror=alert(1)>', "av_dq_img"), ('"><svg onload=alert(1)>', "av_dq_svg")]
        if "'" not in escaped_chars and "<" not in escaped_chars:
            return [("'><img src=x onerror=alert(1)>", "av_sq_img"), ("'><svg onload=alert(1)>", "av_sq_svg")]
        if '"' not in escaped_chars:
            return [('" onmouseover=alert(1) x="', "av_dq_event"), ('" autofocus onfocus=alert(1) x="', "av_dq_focus")]
        if "'" not in escaped_chars:
            return [("' onmouseover=alert(1) x='", "av_sq_event")]
        return [("`-alert(1)-`", "av_backtick")]

    # body (기본 + fallback)
    if "<" not in escaped_chars:
        return [
            ("<img src=x onerror=alert(1)>", "body_img_onerror"),
            ("<svg onload=alert(1)>", "body_svg_onload"),
            ("<scrIpt>alert(1);</scRipt>", "body_script_mixed"),
        ]
    return [
        ("<img/src=x/onerror=alert(1)>", "body_img_slash"),
        ("<svg/onload=alert(1)>", "body_svg_slash"),
    ]


def build_mutation_tasks(mutations: List[dict], targets: List[dict]) -> List[dict]:
    """mutations.json 항목 → 재전송용 HTTP task 목록 (WAF/PHPIDS 우회 검증용).

    mutation의 meta.target_index/param_index로 원본 target/param을 다시 찾아
    mutated_payload로 실제 요청을 재구성한다.
    """
    all_tasks: List[dict] = []

    for m_idx, m in enumerate(mutations):
        meta = m.get("meta") or {}
        target_idx = meta.get("target_index")
        param_idx = meta.get("param_index")
        if target_idx is None or param_idx is None:
            continue
        if not (0 <= target_idx < len(targets)):
            continue

        target = targets[target_idx]
        parameters = target.get("parameters") or []
        scan_params = [p for p in parameters if p.get("scan", True)]
        if not (0 <= param_idx < len(scan_params)):
            continue
        param = scan_params[param_idx]

        base_params = _base_params(parameters)
        common = _common_task_fields(target, param, base_params, target_idx, param_idx)

        all_tasks.append({
            **common,
            "id":             f"mutverify_{m_idx}_{target_idx}_{param.get('name', '')}",
            "point":          param.get("name", ""),
            "payload":        m.get("mutated_payload"),
            "payload_type":   m.get("payload_type"),
            "payload_family": f"{m.get('payload_family', '')}_mutverify",
            "inject_mode":    "replace",
            "meta": {
                **meta,
                "mutation_verify":  True,
                "original_payload": m.get("payload"),
                "mutation_desc":    m.get("mutation_desc"),
                "vuln_type":        m.get("vuln_type"),
            },
        })

    return all_tasks


def build_tasks(
    targets: List[dict],
    strength: str = "MEDIUM",
    scan_xss: bool = True,
    scan_sqli: bool = True,
) -> List[dict]:
    """하위 호환용 — SQLi + XSS probe를 한번에 반환."""
    all_tasks: List[dict] = []
    if scan_sqli:
        all_tasks.extend(build_sqli_tasks(targets, strength=strength))
    if scan_xss:
        all_tasks.extend(build_xss_probe_tasks(targets))
    return all_tasks
