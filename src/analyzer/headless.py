"""
Playwright 기반 headless 확인
raw HTTP 판정으로는 안 보이는 실제 실행 여부를 확인. 브라우저는 최초 confirm 호출 시에만 뜬다.
"""

from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import urlparse

from playwright.sync_api import sync_playwright, Browser, Playwright


@dataclass
class HeadlessVerdict:  # headless 확인 1건의 결과
    executed: bool    # alert 등 dialog가 실제로 발생했는지
    method: str       # "render"(재렌더링) 또는 "navigate"(실제 재요청)
    evidence: str     # 짧은 근거 텍스트


class HeadlessSession:

    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    # 최초 호출 시에만 브라우저 프로세스를 띄움
    def _ensure_browser(self) -> Browser:
        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.chromium.launch(headless=True)
        return self._browser

    # 브라우저/Playwright 프로세스 정리
    def close(self) -> None:
        if self._browser is not None:
            self._browser.close()
        if self._playwright is not None:
            self._playwright.stop()
        self._browser = None
        self._playwright = None

    # 이미 받은 response_body를 그대로 렌더링만 함, 재요청 없음
    def confirm_via_render(self, response_body: str) -> HeadlessVerdict:
        browser = self._ensure_browser()
        page = browser.new_page()
        dialog_messages: list[str] = []
        page.on("dialog", lambda dialog: (dialog_messages.append(dialog.message), dialog.dismiss()))
        try:
            page.set_content(response_body or "", timeout=5000)
            page.wait_for_timeout(500)  # 지연 실행 payload 대비 짧은 대기
        except Exception as e:
            return HeadlessVerdict(executed=False, method="render", evidence=f"렌더링 실패: {e}")
        finally:
            page.close()
        if dialog_messages:
            return HeadlessVerdict(executed=True, method="render", evidence=f"dialog fired: {dialog_messages[0]}")
        return HeadlessVerdict(executed=False, method="render", evidence="dialog 없음")

    # 실제 URL로 navigate, 쿠키 주입 후 alert 발생 여부 확인 (DOM 기법 전용)
    def confirm_via_navigate(self, url: str, cookies: dict[str, str], method: str) -> HeadlessVerdict:
        if method != "GET":  # POST 폼 재현은 ver1 범위 밖 (design doc 참고)
            return HeadlessVerdict(executed=False, method="navigate", evidence="POST navigate 미지원 (ver1 범위 밖)")

        browser = self._ensure_browser()  # 브라우저 실행 실패는 loudly 전파 — try 밖에 유지
        context = None
        try:
            context = browser.new_context()  # context/쿠키/page 준비도 실패 가능하므로 try 안에서 처리, finally에서 반드시 정리
            if cookies:
                hostname = urlparse(url).hostname
                context.add_cookies([
                    {"name": name, "value": value, "domain": hostname, "path": "/"}
                    for name, value in cookies.items()
                ])
            page = context.new_page()
            dialog_messages: list[str] = []
            page.on("dialog", lambda dialog: (dialog_messages.append(dialog.message), dialog.dismiss()))
            page.goto(url, timeout=10000)
            page.wait_for_timeout(500)
        except Exception as e:
            return HeadlessVerdict(executed=False, method="navigate", evidence=f"navigate 실패: {e}")
        finally:
            if context is not None:
                context.close()
        if dialog_messages:
            return HeadlessVerdict(executed=True, method="navigate", evidence=f"dialog fired: {dialog_messages[0]}")
        return HeadlessVerdict(executed=False, method="navigate", evidence="dialog 없음")
