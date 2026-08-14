from __future__ import annotations

import unittest

from analyzer.headless import HeadlessSession, HeadlessVerdict


class ConfirmViaNavigatePostUnsupportedTests(unittest.TestCase):
    # POST navigate 재현은 ver1 범위 밖 — 브라우저를 아예 띄우지 않고 즉시 리턴해야 함
    def test_post_method_is_not_supported_without_launching_browser(self) -> None:
        session = HeadlessSession()

        verdict = session.confirm_via_navigate(
            "http://example.com/comment", cookies={}, method="POST"
        )

        self.assertIsInstance(verdict, HeadlessVerdict)
        self.assertFalse(verdict.executed)
        self.assertEqual(verdict.method, "navigate")
        self.assertIsNone(session._browser)
        session.close()


if __name__ == "__main__":
    unittest.main()
