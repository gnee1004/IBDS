"""
judge_error_based_sqli 단위테스트 — 마커 인식 3분기 계약 검증.

  extraction + 마커(~~값~~) 공격응답에만 노출 → vulnerable (정보추출)
  마커 없이 baseline엔 없던 DB 에러만 노출     → error_exposed (실제 신호 O, 정보추출 X, low)
  DB 에러가 baseline에도 있음 / 아무 신호 없음  → safe
  judgment 미지정 시 기본 structural(마커 확인 안 함)
"""
from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from analyzer.sqli.judge import EXTRACT_MARKER, judge_error_based_sqli

_DB_ERROR = "You have an error in your SQL syntax; check the manual"


class ExtractionTests(unittest.TestCase):
    """extraction 룰 — 마커로 감싼 값이 공격 응답에만 노출되면 정보추출(vulnerable)."""

    def test_marked_value_only_in_attack_is_vulnerable(self) -> None:
        attack = f"<b>Error near ~~8.0.35~~ at line 1</b>"
        verdict = judge_error_based_sqli("정상 페이지", attack, judgment="extraction")

        self.assertTrue(verdict.vulnerable)
        self.assertEqual(verdict.final_status, "vulnerable")
        self.assertIn("8.0.35", verdict.evidence)

    def test_marked_value_also_in_baseline_is_not_extraction(self) -> None:
        # 마커+값이 baseline에도 있으면 공격으로 추출된 게 아님 → 정보추출 불인정 (DB 에러도 없어 safe)
        body = "버전 표시: ~~8.0.35~~"
        verdict = judge_error_based_sqli(body, body, judgment="extraction")

        self.assertFalse(verdict.vulnerable)
        self.assertEqual(verdict.final_status, "safe")

    def test_truncated_marker_is_not_matched(self) -> None:
        # 닫는 마커가 잘림(extractvalue 32자 truncate 재현) → 매치 실패 → 정보추출 불인정
        attack = "Error: XPATH syntax error: '~~8.0.35-0ubuntu0.20.04"  # 뒤 ~~ 없음
        verdict = judge_error_based_sqli("정상", attack, judgment="extraction")

        self.assertNotEqual(verdict.final_status, "vulnerable")

    def test_custom_marker_is_honored(self) -> None:
        attack = "결과: ##root@localhost##"
        verdict = judge_error_based_sqli("정상", attack, extract_marker="##", judgment="extraction")

        self.assertTrue(verdict.vulnerable)
        self.assertIn("root@localhost", verdict.evidence)


class ErrorExposedTests(unittest.TestCase):
    """마커 없이 baseline엔 없던 DB 에러만 → error_exposed(low). vulnerable도 safe도 아님."""

    def test_db_error_without_marker_is_error_exposed(self) -> None:
        verdict = judge_error_based_sqli("정상 응답", _DB_ERROR, judgment="extraction")

        self.assertFalse(verdict.vulnerable)
        self.assertEqual(verdict.final_status, "error_exposed")
        self.assertEqual(verdict.confidence, "low")

    def test_structural_default_does_not_promote_to_extraction(self) -> None:
        # judgment 미지정(기본 structural) — 마커가 있어도 정보추출로 승격 안 함. DB 에러만 있으면 error_exposed
        attack = f"~~secret~~ {_DB_ERROR}"
        verdict = judge_error_based_sqli("정상", attack)  # judgment 생략 → structural

        self.assertNotEqual(verdict.final_status, "vulnerable")
        self.assertEqual(verdict.final_status, "error_exposed")


class SafeTests(unittest.TestCase):
    def test_db_error_in_baseline_too_is_safe(self) -> None:
        # DB 에러가 baseline에도 있으면 이 페이지의 정상 동작 → safe
        verdict = judge_error_based_sqli(_DB_ERROR, _DB_ERROR, judgment="extraction")

        self.assertEqual(verdict.final_status, "safe")

    def test_no_error_no_marker_is_safe(self) -> None:
        verdict = judge_error_based_sqli("정상 페이지", "정상 페이지", judgment="extraction")

        self.assertFalse(verdict.vulnerable)
        self.assertEqual(verdict.final_status, "safe")


if __name__ == "__main__":
    unittest.main()
