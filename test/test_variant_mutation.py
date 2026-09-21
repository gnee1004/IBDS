from __future__ import annotations

import unittest

from scan.mutation.variant import build_mutation_case


class BuildMutationCaseFormUrlTests(unittest.TestCase):
    def test_form_mutation_keeps_original_query(self) -> None:
        target = {
            "method": "POST",
            "url": "http://example.com/submit?mode=edit",
            "base_url": "http://example.com/submit",
            "request_body": "comment=hello",
        }
        case = build_mutation_case(
            target, location="form", param_name="comment",
            original_value="hello", payload="x",
            step="attack", case_id="t1",
        )
        self.assertEqual(case.url, "http://example.com/submit?mode=edit")


if __name__ == "__main__":
    unittest.main()
