from __future__ import annotations

import json
from pathlib import Path
from typing import Callable
from typing import Callable
from urllib.parse import urlparse

from scan.match.matcher import AttackRule, match_and_render
from scan.match.rules_builder import get_rules
from ..models import DiscoveryResult, RequestFamily, ScanPoint
from .discovery import _CANDIDATE_SPECIALS
from .scan_point import build_scan_points
from .variant import build_baseline_case, build_mutation_case, build_stored_verify_case

_DOM_TECHNIQUE = "dom"        # DOM 계열은 payload를 URL fragment로 주입 (파라미터 값 아님)
_STORED_TECHNIQUE = "stored"  # 저장형 XSS: 주입 POST 뒤에 GET 재조회 case를 붙여 저장분을 확인


# case_id용 step 축약 — 모든 mutation step에 공통으로 붙는 "attack" 단어 제거
# 예: "true_attack"->"true", "error_attack"->"error", "attack"->"a"
def _short_step(step: str) -> str:
    s = step.removesuffix("attack").rstrip("_")
    return s or "a"


# ScanPoint 하나 + 룰 목록 -> RequestFamily 목록. payload_filter가 있으면 조건을 만족하는 payload만 mutation으로 남김
def build_families_for_point(
    sp: ScanPoint,
    target: dict,
    rules: list[AttackRule],
    payload_filter: Callable[[str], bool] | None = None,
    dynamic_markers: list[tuple[str, str]] | None = None,
) -> list[RequestFamily]:
    families: list[RequestFamily] = []

    for matched in match_and_render(sp, rules):
        family_id = f"{sp.target_id}_{sp.name}_{matched.attack_id}"
        baseline = build_baseline_case(target, sp.location, f"{family_id}_baseline")
        is_dom = matched.technique == _DOM_TECHNIQUE

        mutations = []
        p_idx = 0
        seen_cases: set[tuple[str, str]] = set()  # (url, body) — family 내 동일 요청 중복 방지
        for step in matched.sequence:
            if step == "baseline":
                continue
            for payload in matched.rendered_payloads.get(step, []):
                if payload_filter is not None and not payload_filter(payload):
                    continue  # Discovery 결과 등으로 실행 불가능하다고 판단된 payload 제외
                case = build_mutation_case(
                    target, sp.location, sp.name, sp.original_value,
                    payload, step, f"{family_id}_{_short_step(step)}{p_idx}",
                    inject_fragment=is_dom,
                )
                key = (case.url, case.body)
                if key in seen_cases:
                    continue
                seen_cases.add(key)
                mutations.append(case)
                p_idx += 1

        if not mutations:
            continue  # 살아남은 payload가 없으면 family 자체 미생성

        families.append(RequestFamily(
            family_id=family_id,
            target_id=sp.target_id,
            param=sp.name,
            attack_id=matched.attack_id,
            vuln_type=matched.vuln_type,
            technique=matched.technique,
            baseline=baseline,
            mutations=mutations,
            dynamic_markers=dynamic_markers or [],
        ))

    return families


# 타겟 목록 -> 모든 ScanPoint에 룰을 매칭해 RequestFamily 목록 생성 (기존 배치 진입점, 동작 변화 없음)
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
        families.extend(build_families_for_point(sp, target_by_id[sp.target_id], rules))
    return families


# discovery.py의 _CANDIDATE_SPECIALS와 반드시 같은 집합을 유지해야 함 — 한 쪽만 수정 시 issubset 비교가 어긋남
_SPECIAL_CHARS_WATCHLIST = ["<", ">", '"', "'", "=", "(", ")", "/", "\\", "`"]


# payload 문자열에 실제로 등장하는 특수문자 집합 — 이 payload가 살아남으려면 필요한 최소 조건
def _required_specials(payload: str) -> set[str]:
    return {ch for ch in _SPECIAL_CHARS_WATCHLIST if ch in payload}


# reflected XSS 전용 family 생성 — Discovery 결과로 실행 불가능한 payload/family를 사전 제거
def generate_xss_families(sp: ScanPoint, target: dict, discovery: DiscoveryResult) -> list[RequestFamily]:
    if not discovery.reflected:
        return []  # 반사 자체가 안 되면 XSS family를 만들 이유가 없음

    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique != "stored"]
    return build_families_for_point(
        sp, target, rules,
        payload_filter=lambda payload: _required_specials(payload).issubset(discovery.valid_specials),
    )


# Stored XSS 전용 family 생성 — Discovery 없이, form(POST) 파라미터에만, PL-XSS-STORED 룰만 적용
def generate_stored_xss_families(sp: ScanPoint, target: dict) -> list[RequestFamily]:
    if sp.location != "form":
        return []
    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique == "stored"]
    return build_families_for_point(sp, target, rules)


# 타겟 목록 -> 모든 ScanPoint에 룰을 매칭해 RequestFamily 목록 생성 (기존 배치 진입점, 동작 변화 없음)
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
        families.extend(build_families_for_point(sp, target_by_id[sp.target_id], rules))
    return families


# payload 문자열에 실제로 등장하는 특수문자 집합 — 이 payload가 살아남으려면 필요한 최소 조건
def _required_specials(payload: str) -> set[str]:
    return {ch for ch in _CANDIDATE_SPECIALS if ch in payload}


# injection_context -> 유효한 technique 집합 매핑 (dom은 context 무관하게 항상 포함)
_CONTEXT_TECHNIQUES: dict[str, set[str]] = {
    "inHTML":    {"body", "html_comment", "filter_bypass", "template", "json", "css"},
    "inAttr":    {"attr_value", "attr_event"},
    "inAttrUrl": {"attr_href"},
    "inScript":  {"script", "script_raw", "attr_event"},
}


# reflected XSS — Discovery 결과로 실행 불가능한 payload/family를 사전 제거
def generate_xss_families(sp: ScanPoint, target: dict, discovery: DiscoveryResult) -> list[RequestFamily]:
    if not discovery.reflected:
        return []  # 반사 자체가 안 되면 XSS family를 만들 이유가 없음

    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique != "stored"]

    if discovery.injection_context is not None:
        valid = _CONTEXT_TECHNIQUES.get(discovery.injection_context, set())
        rules = [r for r in rules if r.technique == "dom" or r.technique in valid]

    return build_families_for_point(
        sp, target, rules,
        payload_filter=lambda payload: _required_specials(payload).issubset(discovery.valid_specials),
    )


# Phase 1 프로브가 마커 반사를 확인할 URL 결정
# 우선순위: 명시된 revisit_url → 동일 호스트 referer → base_url → url
def resolve_revisit_url(target: dict) -> str:
    if explicit := target.get("revisit_url"):
        return explicit
    target_host = urlparse(target.get("url", "")).netloc
    referer = target.get("headers", {}).get("referer", "")
    if referer and urlparse(referer).netloc == target_host:
        return referer
    return target.get("base_url") or target.get("url", "")


# Stored XSS — Discovery 없이, form(POST) 파라미터에만, PL-XSS-STORED 룰만 적용
def generate_stored_xss_families(sp: ScanPoint, target: dict) -> list[RequestFamily]:
    if sp.location != "form":
        return []
    rules = [r for r in get_rules() if r.vuln_type == "xss" and r.technique == "stored"]
    return build_families_for_point(sp, target, rules)


# SQLi
def generate_sqli_families(
    sp: ScanPoint, target: dict, dynamic_markers: list[tuple[str, str]] | None = None,
) -> list[RequestFamily]:
    rules = [r for r in get_rules() if r.vuln_type == "sqli"]
    return build_families_for_point(sp, target, rules, dynamic_markers=dynamic_markers)


if __name__ == "__main__":
    import sys
    from dataclasses import asdict

    t_path = sys.argv[1] if len(sys.argv) > 1 else "results/new/scan_targets.json"
    result = generate_families(t_path)
    print(json.dumps([asdict(f) for f in result], ensure_ascii=False, indent=2))
    print(f"\n총 {len(result)}개 family 생성", file=sys.stderr)
