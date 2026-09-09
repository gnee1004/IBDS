"""
Phase 1 probe_sink 단독 검증 스크립트.
ZAP + DVWA 켜진 상태에서 실행. PHPSESSID가 만료됐으면 아래 cookies 갱신 필요.
실행: set PYTHONPATH=src && python src/test_probe_manual.py
"""
from scan.models import ScanPoint, MutationCase
from scan.requester import requester
from analyzer.revisit import probe_sink, new_run_marker_factory, _get_headers_for_revisit

TARGET = {
    "method": "POST",
    "url": "http://192.168.45.4:8080/vulnerabilities/xss_s/",
    "base_url": "http://192.168.45.4:8080/vulnerabilities/xss_s/",
    "param_location": "body",
    "params": {"txtName": "ZAP", "mtxMessage": "", "btnSign": "Sign Guestbook"},
    "request_body": "txtName=ZAP&mtxMessage=&btnSign=Sign+Guestbook",
    "headers": {
        "host": "192.168.45.4:8080",
        "content-type": "application/x-www-form-urlencoded",
        "referer": "http://192.168.45.4:8080/vulnerabilities/xss_s/",
    },
    "cookies": {"PHPSESSID": "5q55c8pufvgf18bifk85p43ib0", "security": "low"},
}

SCAN_POINTS = [
    ScanPoint(target_id="t0", name="txtName",    location="form", original_value="ZAP", value_type="string", value_index=0),
    ScanPoint(target_id="t0", name="mtxMessage", location="form", original_value="",    value_type="string", value_index=0),
]

def _debug_get(zap, url: str, marker: str):
    """GET 응답 디버그 — 마커 포함 여부 + 앞 500자 출력"""
    get_case = MutationCase(
        case_id="debug_get",
        step="debug",
        method="GET",
        url=url,
        headers=_get_headers_for_revisit(TARGET),
        cookies=dict(TARGET.get("cookies") or {}),
        body_type="query",
        body="",
    )
    resp = requester.send(get_case, zap)
    body = resp.get("response_body") or ""
    status = resp.get("response_status")
    print(f"  [DEBUG GET] status={status}  marker_in_body={marker in body}")
    print(f"  [DEBUG GET] body(500자): {body[:500]}")


def main():
    zap = requester.get_zap_client()
    factory = new_run_marker_factory()

    for sp in SCAN_POINTS:
        marker = factory(sp.name)
        print(f"\n[PROBE] param={sp.name}  marker={marker}")
        try:
            _debug_get(zap, TARGET["base_url"], marker)  # POST 전 GET — 기준점
            result = probe_sink(sp, TARGET, marker, requester, zap)
            print(f"  sink_confirmed : {result.sink_confirmed}")
            print(f"  inconclusive   : {result.inconclusive}")
            print(f"  probe_marker   : {result.probe_marker}")
            print(f"  revisit_url    : {result.revisit_url}")
        except Exception as e:
            print(f"  ERROR: {e}")

if __name__ == "__main__":
    main()
