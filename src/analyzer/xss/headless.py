"""
Playwright 기반 headless 확인부
raw HTTP 판정으로는 안 보이는 실제 실행 여부를 확인함
"""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, Browser, Playwright

_DROP_ON_FULFILL = {"content-encoding", "content-length", "transfer-encoding"}  # fulfill 시 제외할 응답 헤더

@dataclass
class HeadlessVerdict:  # headless 확인 1건의 결과
    executed: bool         # alert 등 dialog가 실제로 발생했는지 (payload 실행 여부)
    method: str            # "render"(재렌더링) 또는 "navigate"(실제 재요청)
    evidence: str          # 짧은 근거 텍스트
    verified: bool = True  # headless 검증 자체가 유효했는지 (렌더/navigate 정상 완료). False면 "실행 안 됨"이 아니라 "확인 불가"


class HeadlessSession:
    def __init__(self) -> None:
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None

    # 최초 호출 시에만 브라우저 프로세스를 띄움
    def _ensure_browser(self) -> Browser:
        if self._browser is None:
            self._playwright = sync_playwright().start()
            self._browser = self._playwright.firefox.launch(headless=True)    # 파이어 폭스 브라우저 띄움
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
    # url+headers가 있으면 그 URL의 응답인 것처럼 fulfill → 실제 origin·CSP 헤더/Content-Type 적용
    def confirm_via_render(self, response_body: str, url: str | None = None,
                           headers: dict[str, str] | None = None) -> HeadlessVerdict:
        browser = self._ensure_browser()
        page = browser.new_page()
        dialog_messages: list[str] = []

        def _on_dialog(dialog):  # dialog 발생 시 메시지 기록 후 닫기 (None 반환 — page.on 시그니처)
            dialog_messages.append(dialog.message)
            dialog.dismiss()

        page.on("dialog", _on_dialog)
        try:
            if url and headers is not None:
                # 저장된 본문은 이미 디코딩된 문자열 → 인코딩/길이 헤더는 빼야 브라우저가 다시 디코딩하다 깨지지 않음
                fulfill_headers = {k: v for k, v in headers.items() if k.lower() not in _DROP_ON_FULFILL}
                served = False

                # 첫 메인 문서 요청만 저장된 응답으로 대체, 나머지(하위 리소스·재이동)는 전부 차단
                # 재요청 없음 유지 + 느린 리소스 타임아웃·사이트 자체 alert 오탐 방지
                def _serve_once(route):
                    nonlocal served
                    if not served and route.request.is_navigation_request():
                        served = True
                        route.fulfill(status=200, headers=fulfill_headers, body=response_body or "")
                    else:
                        route.abort()

                page.route("**/*", _serve_once)
                page.goto(url, timeout=5000)
            else:
                page.set_content(response_body or "", timeout=5000)
            page.wait_for_timeout(500)  # 지연 실행 payload 대비 짧은 대기
        except Exception as e:
            if not dialog_messages:  # 이미 발화한 뒤의 타임아웃(느린 하위 리소스 등)은 발화로 인정
                # 렌더링 자체가 안 됨 → 실행 안 됨이 아니라 확인 불가 (렌더링 제약 기록)
                return HeadlessVerdict(executed=False, method="render", evidence=f"렌더링 실패: {e}", verified=False)
        finally:
            page.close()
        if dialog_messages:
            return HeadlessVerdict(executed=True, method="render", evidence=f"dialog fired: {dialog_messages[0]}")
        return HeadlessVerdict(executed=False, method="render", evidence="dialog 없음")

    # 실제 URL로 navigate, 쿠키 주입 후 alert 발생 여부 확인 (DOM 기법·stored 재조회 공용, GET만)
    def confirm_via_navigate(self, url: str, cookies: dict[str, str], method: str) -> HeadlessVerdict:
        if method != "GET":  # POST 폼 재현은 ver1 범위 밖 (design doc 참고)
            # 미지원 → 실행 안 됨이 아니라 확인 불가
            return HeadlessVerdict(executed=False, method="navigate", evidence="POST navigate 미지원 (ver1 범위 밖)", verified=False)

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

            def _on_dialog(dialog):  # dialog 발생 시 메시지 기록 후 닫기 (None 반환 — page.on 시그니처)
                dialog_messages.append(dialog.message)
                dialog.dismiss()

            page.on("dialog", _on_dialog)
            page.goto(url, timeout=10000)
            page.wait_for_timeout(500)
        except Exception as e:
            # navigate 자체가 실패(타임아웃 등) → 실행 안 됨이 아니라 확인 불가
            return HeadlessVerdict(executed=False, method="navigate", evidence=f"navigate 실패: {e}", verified=False)
        finally:
            if context is not None:
                context.close()
        if dialog_messages:
            return HeadlessVerdict(executed=True, method="navigate", evidence=f"dialog fired: {dialog_messages[0]}")
        return HeadlessVerdict(executed=False, method="navigate", evidence="dialog 없음")