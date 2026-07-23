from __future__ import annotations

import urllib.parse


def mutate_query(url: str, param_name: str, new_value: str) -> str:
    """URL 쿼리스트링에서 param_name 첫 번째 값만 new_value로 교체."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    replaced = False
    result = []
    for k, v in params:
        if k == param_name and not replaced:
            result.append((k, new_value))
            replaced = True
        else:
            result.append((k, v))
    return urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(result)))


def mutate_form(body: str, param_name: str, new_value: str) -> str:
    """form-urlencoded body에서 param_name 첫 번째 값만 new_value로 교체."""
    params = urllib.parse.parse_qsl(body or "", keep_blank_values=True)
    replaced = False
    result = []
    for k, v in params:
        if k == param_name and not replaced:
            result.append((k, new_value))
            replaced = True
        else:
            result.append((k, v))
    return urllib.parse.urlencode(result)
