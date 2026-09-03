from __future__ import annotations

import re
import unittest

from scan.match.matcher import CANARY_PREFIX, _generate_canary, _render_templates


class GenerateCanaryTests(unittest.TestCase):
    def test_format_matches_prefix_and_hex_length(self):
        canary = _generate_canary()
        self.assertRegex(canary, rf"^{CANARY_PREFIX}[0-9a-f]{{8}}$")

    def test_two_calls_produce_different_values(self):
        # 충돌 시 서로 다른 요청의 canary를 혼동할 수 있으므로 매 호출마다 달라야 함
        self.assertNotEqual(_generate_canary(), _generate_canary())

    def test_matches_analyzer_side_regex(self):
        # matcher.py(생성)와 analyzer/scan.py(탐지)가 서로 다른 파일에 있어서 형식이 어긋나면
        # 에러 없이 조용히 canary 매칭이 실패하게 됨 -> 두 쪽이 항상 맞는지 직접 확인
        from analyzer.scan import _CANARY_RE

        canary = _generate_canary()
        self.assertRegex(canary, _CANARY_RE)


class RenderTemplatesTests(unittest.TestCase):
    def test_substitutes_value_and_canary(self):
        templates = {"attack": ["{value}' AND extractvalue(1,concat(0x7e,'{canary}')) -- "]}
        rendered = _render_templates(templates, "1")

        payload = rendered["attack"][0]
        self.assertTrue(payload.startswith("1' AND extractvalue"))
        self.assertRegex(payload, rf"'{CANARY_PREFIX}[0-9a-f]{{8}}'\)\) -- $")

    def test_no_canary_placeholder_is_left_untouched(self):
        templates = {"attack": ["{value}'"]}
        rendered = _render_templates(templates, "1")
        self.assertEqual(rendered["attack"], ["1'"])

    def test_canary_is_shared_across_templates_in_one_call(self):
        # 같은 family 안의 여러 canary payload가 같은 canary를 써야, 어느 것이 응답에 반사되든
        # analyzer가 "이 family에서 나온 canary"로 일관되게 추출/확인할 수 있음
        templates = {
            "attack": [
                "{value} AND extractvalue(1,concat(0x7e,'{canary}')) -- ",
                "{value} UNION ALL SELECT '{canary}' -- ",
            ],
        }
        rendered = _render_templates(templates, "1")
        canaries = set(re.findall(rf"{CANARY_PREFIX}[0-9a-f]{{8}}", " ".join(rendered["attack"])))
        self.assertEqual(len(canaries), 1)

    def test_separate_calls_use_different_canaries(self):
        templates = {"attack": ["{value} AND extractvalue(1,concat(0x7e,'{canary}')) -- "]}
        first = _render_templates(templates, "1")["attack"][0]
        second = _render_templates(templates, "1")["attack"][0]
        self.assertNotEqual(first, second)


if __name__ == "__main__":
    unittest.main()
