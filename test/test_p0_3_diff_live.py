"""
P0-3 diff 단위 실측 (라인 diff + 추가 줄만 방식 검증) - live 테스트

DVWA 방명록(XSS Stored)에서 아래 3개를 실측한다.
  ① 방명록 페이지가 줄바꿈 되어 있나 (minified 아닌지)
  ② 안 심고 두 번 재조회 시 "추가된 줄" 노이즈가 몇 개 뜨나
  ③ 마커 줄이 항상 "추가된 줄"로 잡히나
셋 다 OK면 -> 라인 diff 확정.

실행:  python3 test/test_p0_3_diff_live.py
사전 준비는 아래 CONFIG 주석 참고.
"""

import difflib
import re
import requests

# ── CONFIG ─────────────────────────────────────────────
BASE    = "http://localhost:8080"                    # 도커로 띄운 DVWA 주소
GUEST   = f"{BASE}/vulnerabilities/xss_s/"           # 방명록 = 재조회(revisit) URL
COOKIES = {"PHPSESSID": "k75nee0i2g37f46rhnaa6u9ge5", "security": "low"}   # 브라우저 개발자도구에서 복사
MARKER  = "ibds1a2b_test_marker"                     # 회차 마커 흉내 (겹치지 않는 문자열)
# ───────────────────────────────────────────────────────

S = requests.Session()
S.cookies.update(COOKIES)


def fetch() -> str:
    """revisit URL GET -> 본문 텍스트"""
    r = S.get(GUEST, timeout=10)
    r.raise_for_status()
    return r.text


def get_csrf(html: str):
    """DVWA 폼의 user_token(CSRF) 추출, 없으면 None"""
    m = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([0-9a-f]+)['\"]", html)
    return m.group(1) if m else None


def post_payload(name: str, message: str):
    """방명록에 글 등록 (CSRF 토큰 있으면 자동 첨부)"""
    token = get_csrf(fetch())
    data = {"txtName": name, "mtxMessage": message, "btnSign": "Sign Guestbook"}
    if token:
        data["user_token"] = token
    S.post(GUEST, data=data, timeout=10).raise_for_status()


def added_lines(before: str, after: str):
    """before -> after 에서 '새로 추가된 줄'만 추출 (핵심 로직 = diff_new_region 원형)"""
    out = []
    for line in difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm=""):
        if line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return out


def main():
    # ① 줄바꿈 여부
    page = fetch()
    n = len(page.splitlines())
    print(f"[①] 페이지 총 줄 수 = {n}  -> {'OK 줄바꿈 정상' if n > 20 else '경고! minified 의심'}\n")

    # ② 노이즈 측정 (안 심고 두 번)
    before = fetch()
    after_noise = fetch()
    noise = added_lines(before, after_noise)
    print(f"[②] 노이즈(추가된 줄) = {len(noise)}개  -> {'OK 노이즈 적음' if len(noise) <= 3 else '검토 필요'}")
    for ln in noise[:5]:
        print(f"      노이즈: {ln.strip()[:80]}")
    print()

    # ③ 마커 심고 재조회 -> 추가 줄에 마커 잡히나
    before2 = fetch()
    post_payload(MARKER, f"<script>alert('{MARKER}')</script>")
    after2 = fetch()
    add = added_lines(before2, after2)
    hit = any(MARKER in ln for ln in add)
    print(f"[③] 마커 후 추가된 줄 = {len(add)}개, 마커 포함 = {hit}  -> {'OK 안 놓침' if hit else '실패! 마커 못 찾음'}")
    for ln in add:
        if MARKER in ln:
            print(f"      마커 줄: {ln.strip()[:100]}")
    print()

    ok = n > 20 and len(noise) <= 3 and hit
    print("=" * 50)
    print(f"판정: {'라인 diff 확정 가능 ✅' if ok else '재검토 필요 ⚠️'}")


if __name__ == "__main__":
    main()
