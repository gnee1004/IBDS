from __future__ import annotations

import unittest

from attack_requests import build_attack_request_list


class BuildAttackRequestListTests(unittest.TestCase):
    def test_returns_flat_attack_request_list(self) -> None:
        requests = build_attack_request_list(max_order_by=2)

        self.assertIsInstance(requests, list)
        self.assertTrue(requests)
        self.assertTrue(
            all(set(request) == {"set_id", "payload"} for request in requests)
        )

    def test_set_ids_are_unique(self) -> None:
        requests = build_attack_request_list()
        set_ids = [request["set_id"] for request in requests]

        self.assertEqual(len(set_ids), len(set(set_ids)))

    def test_time_requests_use_original_request_as_baseline(self) -> None:
        requests = build_attack_request_list(delay_seconds=7)
        time_requests = [
            request
            for request in requests
            if request["set_id"].startswith("SQLI_time_delay_")
        ]

        self.assertEqual(len(time_requests), 3)
        self.assertTrue(all("SLEEP(7)" in request["payload"] for request in time_requests))
        self.assertFalse(any("SLEEP(0)" in request["payload"] for request in requests))
        self.assertFalse(any("retry" in request["set_id"] for request in requests))

    def test_boolean_true_false_requests_share_suffix(self) -> None:
        requests = build_attack_request_list()
        set_ids = {request["set_id"] for request in requests}

        for suffix in ("001", "002", "003"):
            self.assertIn(f"SQLI_boolean_true_{suffix}", set_ids)
            self.assertIn(f"SQLI_boolean_false_{suffix}", set_ids)

    def test_order_by_requests_cover_one_to_max_for_three_input_styles(self) -> None:
        requests = build_attack_request_list(max_order_by=10)
        order_requests = [
            request
            for request in requests
            if request["set_id"].startswith("SQLI_order_by_")
        ]

        self.assertEqual(len(order_requests), 30)
        for index in range(1, 11):
            expected_payloads = {
                f"{{value}}' ORDER BY {index}-- ",
                f'{{value}}" ORDER BY {index}-- ',
                f"{{value}} ORDER BY {index}",
            }
            actual_payloads = {
                request["payload"]
                for request in order_requests
                if request["payload"] in expected_payloads
            }
            self.assertEqual(actual_payloads, expected_payloads)

    def test_xss_requests_cover_multiple_contexts(self) -> None:
        requests = build_attack_request_list(include_sqli=False)
        set_ids = [request["set_id"] for request in requests]

        self.assertEqual(len(requests), 36)
        self.assertTrue(any(set_id.startswith("XSS_script_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_event_handler_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_attribute_breakout_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_javascript_context_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_url_context_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_dom_context_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_stored_context_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_escape_probe_") for set_id in set_ids))
        self.assertTrue(all("{token}" in request["payload"] for request in requests))

    def test_xss_requests_contain_attack_syntax(self) -> None:
        requests = build_attack_request_list(include_sqli=False)
        executable_requests = [
            request
            for request in requests
            if not request["set_id"].startswith("XSS_escape_probe_")
        ]

        self.assertTrue(
            all(
                any(
                    marker in request["payload"].lower()
                    for marker in (
                        "<script",
                        "alert(",
                        "confirm(",
                        "onerror",
                        "onload",
                        "onmouseover",
                        "onfocus",
                        "ontoggle",
                        "onanimationstart",
                        "javascript:",
                        "data:text/html",
                        "setattribute",
                        "srcdoc",
                    )
                )
                for request in executable_requests
            )
        )

    def test_xss_requests_are_not_token_only(self) -> None:
        requests = build_attack_request_list(include_sqli=False)
        executable_requests = [
            request
            for request in requests
            if not request["set_id"].startswith("XSS_escape_probe_")
        ]

        self.assertFalse(any(request["payload"] == "{token}" for request in requests))
        self.assertTrue(all("{token}" in request["payload"] for request in executable_requests))
        self.assertTrue(any("<script" in request["payload"].lower() for request in executable_requests))

    def test_xss_non_reflected_categories_are_present(self) -> None:
        requests = build_attack_request_list(include_sqli=False)
        set_ids = {request["set_id"] for request in requests}

        self.assertTrue(any(set_id.startswith("XSS_dom_context_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_stored_context_") for set_id in set_ids))
        self.assertTrue(any(set_id.startswith("XSS_javascript_context_") for set_id in set_ids))

    def test_include_flags(self) -> None:
        self.assertTrue(
            all(
                request["set_id"].startswith("XSS_")
                for request in build_attack_request_list(include_sqli=False)
            )
        )
        self.assertTrue(
            all(
                request["set_id"].startswith("SQLI_")
                for request in build_attack_request_list(include_xss=False)
            )
        )
        self.assertEqual(
            build_attack_request_list(include_sqli=False, include_xss=False),
            [],
        )

    def test_validates_sqli_options_only_when_sqli_is_enabled(self) -> None:
        with self.assertRaises(ValueError):
            build_attack_request_list(max_order_by=0)
        with self.assertRaises(ValueError):
            build_attack_request_list(delay_seconds=0)

        self.assertTrue(
            build_attack_request_list(
                max_order_by=0,
                delay_seconds=0,
                include_sqli=False,
            )
        )


if __name__ == "__main__":
    unittest.main()