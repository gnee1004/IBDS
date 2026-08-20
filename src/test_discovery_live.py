"""
Discovery 실제 동작 확인 스크립트
DVWA Security Level을 바꿔가며 valid_specials 변화 확인용
"""
import json
import sys
import os

_SRC = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_SRC)
sys.path.insert(0, _SRC)

from scan.models import ScanPoint
from scan.mutation.discovery import run_discovery
from scan.requester import requester

TARGETS_PATH = os.path.join(_PROJECT_ROOT, "results", "collection_20260820_233945", "scan_targets.json")

targets = json.load(open(TARGETS_PATH, encoding="utf-8"))
t19 = next(t for t in targets if t["target_id"] == "t21")

sp = ScanPoint(
    target_id="t21",
    name="name",
    location="query",
    original_value="ZAP",
    value_type="string",
)

zap = requester.get_zap_client()
requester.clear_cookie_store()

print("=" * 60)
print(f"[Discovery] {t19['url']}")
print("=" * 60)

result = run_discovery(sp, t19, zap)  # t21 = xss_r

print(f"reflected     : {result.reflected}")
print(f"valid_specials: {result.valid_specials}")
print(f"valid_specials 수: {len(result.valid_specials)}")
print(f"injection_context: {result.injection_context}")
print()

if not result.reflected:
    print("-> reflected=False: XSS family 생성 없음")
elif "<" not in result.valid_specials or ">" not in result.valid_specials:
    print("-> <> 인코딩됨: 태그 기반 XSS 불가")
    print("-> 현재 구조에서는 <> 불필요 페이로드(template 등)만 family 생성됨")
else:
    print("-> <> 살아남음: 태그 기반 XSS 가능")
