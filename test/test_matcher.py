from __future__ import annotations

from models import ScanPoint
from scan.match.matcher import AttackRule, load_rules, match_and_render


# ── fixture ────────────────────────────────────────────────────────────────────

def _sqli_error_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-SQLI-ERR-001",
        vuln_type="sqli",
        technique="error",
        sequence=["baseline", "error_attack"],
        payload_templates={"error_attack": ["{value}'", "{value}\""]},
        allowed_locations=["query", "body"],
        allowed_value_types=["string", "number"],
    )


def _xss_reflected_rule() -> AttackRule:
    return AttackRule(
        attack_id="AR-XSS-REF-001",
        vuln_type="xss",
        technique="reflected",
        sequence=["baseline", "reflect"],
        payload_templates={"reflect": ["<script>alert(1)</script>"]},
        allowed_locations=["query", "body"],
        allowed_value_types=["string"],   # 문자열 파라미터에만
    )


def _query_number_point() -> ScanPoint:
    return ScanPoint(target_id="t0", name="id", location="query",
                     original_value="1", value_type="number")


def _body_string_point() -> ScanPoint:
    return ScanPoint(target_id="t1", name="username", location="body",
                     original_value="admin", value_type="string")


# ── 매칭 테스트 ────────────────────────────────────────────────────────────────

def test_value_type_filter_excludes_xss_on_number():
    """number 파라미터에는 string 전용 XSS 룰이 매칭되지 않아야 한다."""
    rules = [_sqli_error_rule(), _xss_reflected_rule()]
    matched = match_and_render(_query_number_point(), rules)
    ids = {m.attack_id for m in matched}
    assert ids == {"AR-SQLI-ERR-001"}, ids


def test_string_point_matches_both():
    """string 파라미터에는 SQLi + XSS 둘 다 매칭된다."""
    rules = [_sqli_error_rule(), _xss_reflected_rule()]
    matched = match_and_render(_body_string_point(), rules)
    ids = {m.attack_id for m in matched}
    assert ids == {"AR-SQLI-ERR-001", "AR-XSS-REF-001"}, ids


def test_location_filter():
    """allowed_locations 에 없는 위치는 제외된다."""
    query_only = _sqli_error_rule()
    query_only.allowed_locations = ["query"]
    matched = match_and_render(_body_string_point(), [query_only])
    assert matched == []


def test_empty_allowed_means_no_restriction():
    """allowed_* 가 비어 있으면 제한 없이 전부 허용."""
    unrestricted = _sqli_error_rule()
    unrestricted.allowed_locations = []
    unrestricted.allowed_value_types = []
    matched = match_and_render(_query_number_point(), [unrestricted])
    assert len(matched) == 1


# ── 렌더 테스트 ────────────────────────────────────────────────────────────────

def test_value_substitution():
    """{value} 가 원본값으로 치환된다."""
    matched = match_and_render(_query_number_point(), [_sqli_error_rule()])
    payloads = matched[0].rendered_payloads["error_attack"]
    assert payloads == ["1'", "1\""], payloads


def test_xss_payload_without_value_passthrough():
    """{value} 없는 고정 payload 는 그대로 통과한다."""
    matched = match_and_render(_body_string_point(), [_xss_reflected_rule()])
    assert matched[0].rendered_payloads["reflect"] == ["<script>alert(1)</script>"]


def test_sequence_preserved():
    """sequence(baseline 포함)가 그대로 보존된다."""
    matched = match_and_render(_query_number_point(), [_sqli_error_rule()])
    assert matched[0].sequence == ["baseline", "error_attack"]


# ── 룰 파일 로드 테스트 ──────────────────────────────────────────────────────
# 실제 룰 내용은 룰 작성자 소유다. 여기선 스키마 형태만 맞춘 임시 파일로 로더를 검증한다.

def test_load_rules_from_json(tmp_path=None):
    """스키마 형태의 JSON 을 읽어 AttackRule 로 변환되는지 확인."""
    import json
    import tempfile

    doc = {
        "version": 1,
        "rules": [{
            "attack_id": "TMP-001",
            "vuln_type": "sqli",
            "technique": "error",
            "sequence": ["baseline", "error_attack"],
            "payload_templates": {"error_attack": ["{value}'"]},
            "allowed_locations": ["query", "body"],
            "allowed_value_types": ["string", "number"],
        }],
    }
    with tempfile.NamedTemporaryFile(
        "w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(doc, f)
        path = f.name

    rules = load_rules(path)
    assert len(rules) == 1
    assert isinstance(rules[0], AttackRule)
    matched = match_and_render(_query_number_point(), rules)
    assert matched[0].rendered_payloads["error_attack"] == ["1'"]


if __name__ == "__main__":
    # pytest 없이도 실행 가능
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    passed = 0
    for fn in fns:
        try:
            fn()
            print(f"  PASS  {fn.__name__}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {fn.__name__}: {e}")
        except Exception as e:
            print(f"  ERROR {fn.__name__}: {type(e).__name__}: {e}")
    print(f"\n{passed}/{len(fns)} passed")
