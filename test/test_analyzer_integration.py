import json
import os
import tempfile
import unittest

from analyzer.scan import analyze_family, analyze_results


def case(step, payload, body, elapsed=0.1):
    return {
        "case": {
            "step": step,
            "method": "GET",
            "url": "http://example.test/?q=1",
            "body_type": "query",
            "payload": payload,
        },
        "status": "ok",
        "response_status": 200,
        "response_body": body,
        "elapsed": elapsed,
    }


def family(vuln_type, technique, mutations):
    return {
        "family_id": f"f-{vuln_type}-{technique}",
        "target_id": "t0",
        "vuln_type": vuln_type,
        "technique": technique,
        "param": "q",
        "baseline": case("baseline", None, "normal page"),
        "mutations": mutations,
    }


class AnalyzerIntegrationTest(unittest.TestCase):
    def test_reflected_xss(self):
        payload = "<script>alert(1)</script>"
        findings = analyze_family(family("xss", "body", [case("attack", payload, payload)]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["vuln_type"], "xss")

    def test_error_sqli(self):
        body = "You have an error in your SQL syntax"
        findings = analyze_family(family("sqli", "error_meta", [case("attack", "1'", body)]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["technique"], "error_meta")

    def test_boolean_sqli(self):
        item = family(
            "sqli",
            "boolean_and",
            [
                case("true_attack", "1 AND 1=1", "normal page"),
                case("false_attack", "1 AND 1=2", "access denied with different content"),
            ],
        )
        self.assertEqual(len(analyze_family(item)), 1)

    def test_jsonl_to_findings(self):
        payload = "<img src=x onerror=alert(1)>"
        item = family("xss", "body", [case("attack", payload, payload)])
        with tempfile.TemporaryDirectory() as directory:
            results_path = os.path.join(directory, "request_results.jsonl")
            with open(results_path, "w", encoding="utf-8") as file:
                file.write(json.dumps(item) + "\n")
            output_path = analyze_results(results_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, encoding="utf-8") as file:
                self.assertEqual(len(json.load(file)), 1)


if __name__ == "__main__":
    unittest.main()
