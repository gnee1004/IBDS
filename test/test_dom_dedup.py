"""
DOM payload 중복 정리 회귀 테스트

- A(데이터 정리): 실제 룰로 생성한 DOM family의 mutation 요청이 서로 겹치지 않음
- B(생성 단계 가드): fragment 변환 후 동일해지는 payload 쌍은 케이스 1개로 합쳐짐

playwright에 의존하는 analyzer 계열을 import하지 않으므로 headless 없이 단독 실행 가능.
(test_variant.py는 현재 시그니처와 맞지 않는 낡은 통합 스크립트라 사용하지 않음)
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest

from scan.mutation import request_builder
from scan.match.matcher import AttackRule


def _write_targets(targets: list[dict]) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(targets, f)
    return path


_TARGET = {
    "url": "http://x/vuln?name=orig",
    "method": "GET",
    "param_location": "query",
    "params": {"name": "orig"},
    "scannable_params": ["name"],
}


class RealRuleDomDedupTests(unittest.TestCase):
    """A: 실제 PL-XSS-DOM 룰로 생성한 DOM mutation URL이 전부 유일한지."""

    def test_dom_family_mutation_urls_are_unique(self) -> None:
        path = _write_targets([_TARGET])
        try:
            families = request_builder.generate_families(path, vuln_types=["xss"])
        finally:
            os.unlink(path)

        dom_families = [f for f in families if f.technique == "dom"]
        self.assertTrue(dom_families, "DOM family가 하나 이상 생성되어야 함")

        for fam in dom_families:
            urls = [m.url for m in fam.mutations]
            self.assertEqual(
                len(urls), len(set(urls)),
                f"DOM family {fam.family_id}의 mutation URL이 중복됨: {urls}",
            )


class FragmentDedupGuardTests(unittest.TestCase):
    """B: fragment 변환으로 동일해지는 payload 쌍이 케이스 1개로 합쳐지는지."""

    def test_hash_prefixed_and_bare_payload_collapse_to_one_case(self) -> None:
        dom_rule = AttackRule(
            attack_id="PL-XSS-DOM-TEST",
            vuln_type="xss",
            technique="dom",
            sequence=["baseline", "attack"],
            payload_templates={"attack": [
                "#<img src=x onerror=alert(1)>",   # fragment 변환 후 아래와 동일
                "<img src=x onerror=alert(1)>",
                "#<svg onload=alert(1)>",           # 고유 payload
            ]},
            allowed_locations=["query", "form", "json"],
            allowed_value_types=["string"],
        )
        original = request_builder.get_rules
        request_builder.get_rules = lambda: [dom_rule]
        path = _write_targets([_TARGET])
        try:
            families = request_builder.generate_families(path, vuln_types=["xss"])
        finally:
            request_builder.get_rules = original
            os.unlink(path)

        dom_families = [f for f in families if f.technique == "dom"]
        self.assertEqual(len(dom_families), 1)
        urls = [m.url for m in dom_families[0].mutations]
        # img(#유무 2개 → 1개) + svg 1개 = 2개, 전부 유일
        self.assertEqual(len(urls), 2, f"중복이 합쳐져 2개여야 함: {urls}")
        self.assertEqual(len(urls), len(set(urls)))


if __name__ == "__main__":
    unittest.main()
