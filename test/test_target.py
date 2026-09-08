from __future__ import annotations

import unittest

from scan.normalize.target import has_destructive_action


class HasDestructiveActionTests(unittest.TestCase):
    # 방명록 Clear 버튼 값이 실린 params → 파괴적 타겟으로 판정
    def test_clear_button_value_is_destructive(self):
        params = {"txtName": ["ZAP"], "mtxMessage": ["hi"], "btnClear": ["Clear Guestbook"]}
        self.assertTrue(has_destructive_action(params))

    # 브라우저가 "Clear+Guestbook" 로 인코딩해 보내도 토큰화로 검출
    def test_plus_encoded_clear_value_is_destructive(self):
        self.assertTrue(has_destructive_action({"btnClear": ["Clear+Guestbook"]}))

    # 같은 폼의 Sign 버튼(정상 쓰기) → 파괴적 아님
    def test_sign_button_form_is_not_destructive(self):
        params = {"txtName": ["ZAP"], "mtxMessage": ["hi"], "btnSign": ["Sign Guestbook"]}
        self.assertFalse(has_destructive_action(params))

    # D1 확정 파괴 단어 각각 검출 (clear/delete/reset/remove/logout)
    def test_each_destructive_word_is_detected(self):
        for word in ("clear", "delete", "reset", "remove", "logout"):
            with self.subTest(word=word):
                self.assertTrue(has_destructive_action({"btn": [f"{word} everything"]}))

    # D1 제외 목록(정상 쓰기·조회·이동) → 파괴적 아님
    def test_benign_action_words_are_not_destructive(self):
        for word in ("submit", "login", "search", "cancel", "change", "update",
                     "create", "register", "sign", "upload", "add"):
            with self.subTest(word=word):
                self.assertFalse(has_destructive_action({"btn": [f"{word} now"]}))

    # 대소문자 무관
    def test_detection_is_case_insensitive(self):
        self.assertTrue(has_destructive_action({"btn": ["DELETE"]}))

    # 파라미터 없음 → 파괴적 아님
    def test_empty_params_is_not_destructive(self):
        self.assertFalse(has_destructive_action({}))

    # 같은 이름 다중값 중 하나라도 파괴적이면 검출
    def test_any_value_in_multivalue_param_triggers(self):
        self.assertTrue(has_destructive_action({"action": ["view", "reset"]}))

    # scan_targets.json 은 params 값을 스칼라 문자열로 저장 (list 아님) — 그 형태도 지원
    def test_scalar_string_param_values_are_supported(self):
        params = {"txtName": "ZAP", "mtxMessage": "", "btnClear": "Clear Guestbook"}
        self.assertTrue(has_destructive_action(params))

    # 스칼라 형태 정상 폼(Sign) → 파괴적 아님
    def test_scalar_sign_form_is_not_destructive(self):
        params = {"txtName": "ZAP", "mtxMessage": "hi", "btnSign": "Sign Guestbook"}
        self.assertFalse(has_destructive_action(params))


if __name__ == "__main__":
    unittest.main()
