from .rules_sqli import SQLI_RULES
from .rules_xss import XSS_RULES
from .requests_list import build_attack_request_list

# 리치 구조 룰 (SQLi + XSS) — 매칭(scan.match)이 사용하는 단일 원본
RULES = SQLI_RULES + XSS_RULES

__all__ = ["RULES", "SQLI_RULES", "XSS_RULES", "build_attack_request_list"]
