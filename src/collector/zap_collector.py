import re
import time
from urllib.parse import urlsplit

from zapv2 import ZAPv2  # type: ignore

from utilities.file_utils import load_json

SESSION_NAME = "IBDSSession"
CONTEXT_NAME = "IBDSContext"
_AJAX_BROWSERS = 5  # Ajax Spider 헤드리스 브라우저 병렬 수


# ZAP 수집 인프라 래퍼
class ZapCollector:
    def __init__(self, host="127.0.0.1", port=8081, api_key="changeme"):
        proxies = {"http": f"http://{host}:{port}", "https": f"http://{host}:{port}"}
        self.zap = ZAPv2(proxies=proxies, apikey=api_key)

    @classmethod
    def from_config(cls, config_path):
        cfg = load_json(config_path, default={})
        return cls(
            host=cfg.get("host", "127.0.0.1"),
            port=cfg.get("port", 8081),
            api_key=cfg.get("api_key", "changeme"),
        )


    # target origin(scheme+host+port) 밖 트래픽을 프록시 단에서 전역 제외
    # 매번 실행시 초기화됨.
    def restrict_to_target_domain(self, target_url: str):
        parts = urlsplit(target_url)
        origin = f"{parts.scheme}://{parts.netloc}" # target_url에 path가 있어도 origin 기준
        regex = f"^(?:(?!{re.escape(origin)}).)*$"

        self.zap.core.clear_excluded_from_proxy() # refresh
        print(f"[ZAP] 전역 제외 초기화 완료")

        self.zap.core.exclude_from_proxy(regex=regex)
        print(f"[ZAP] 전역 제외(target 외부 origin): {regex}")


    # Context 생성 + target include 등록
    def setup_context(self, target_url: str, name=CONTEXT_NAME) -> str:
        context_id = self.zap.context.new_context(contextname=name)
        include_regex = f"{target_url}.*"
        self.zap.context.include_in_context(contextname=name, regex=include_regex)
        print(f"[ZAP] Context 생성: {name} (id={context_id}), include: {include_regex}")
        return context_id


    # logout/reset/delete 등 위험 URL을 Context에서 제외, Spider 실행 전 필수 호출
    def exclude_danger_urls(self, patterns: list[str], name=CONTEXT_NAME):
        for pattern in patterns:
            self.zap.spider.exclude_from_scan(pattern)
            """
            # TODO: ajax Spider는 URL 정규식이 아니라 클릭할 엘리먼트(a 태그 href) 단위로 제외 등록해야함. 나중에 쓸때 추가
            self.zap.ajaxSpider.add_excluded_element()"""
        print(f"[ZAP] Context 위험 URL 제외 {len(patterns)}건 등록")


    # ZAP 메시지 히스토리에서 인증 성공 요청에 실린 쿠키(name=value) 수집.
    def _auth_cookies(self, target_url: str) -> dict:
        cookies = {}
        try:
            msgs = self.zap.core.messages(baseurl=target_url, count=500)
            
        except Exception as e:
            print(f"[SESSION] 메시지 조회 실패, 쿠키 자동 수집 건너뜀: {e}")
            return cookies
        
        for m in msgs:
            status = m.get("responseHeader", "").split("\r\n", 1)[0] # 헤더 첫줄 확인
            if " 2" not in status:  # 2xx 응답만 확인
                continue

            for line in m.get("requestHeader", "").split("\r\n"): 
                if not line.lower().startswith("cookie:"):
                    continue

                for part in line.split(":", 1)[1].split(";"):
                    if "=" not in part:
                        continue

                    k, v = part.split("=", 1) 
                    k, v = k.strip(), v.strip() 
                    if v and v.lower() != "deleted":
                        cookies[k] = v
        return cookies


    # 프록시가 캡처한 기존 세션 활성화, 없으면 anonymous로 진행
    def capture_session(self, target_url: str):
        site = urlsplit(target_url).netloc

        auth_cookies = self._auth_cookies(target_url)  # 마지막 2xx 요청이 쓰던 쿠키
        print(f"[SESSION] 인증 쿠키 감지: {auth_cookies}")

        cap_sess = self.zap.httpsessions.sessions(site)

        if not cap_sess:
            print("[SESSION] 세션 없음, anonymous 진행")
            return
        for i, entry in enumerate(cap_sess): # 캡쳐된 세션 확인 
            cks = ", ".join(f"{k}={v['value']}" for k, v in entry['session'][1].items())
            print(f"\n[SESSION]  [{i}] {entry['session'][0]} | msgs={entry['session'][2]} | {cks}\n")  # DEBUG: 캡처된 세션 전체 확인

        name = cap_sess[0]['session'][0]  # 최근 세션이라고 가정 (값은 어차피 아래에서 덮음)
        try:
            self.zap.httpsessions.set_active_session(site, name)
            for ck, val in auth_cookies.items():  # set_session_token_value가 토큰 등록 + 값 설정 동시 처리
                self.zap.httpsessions.set_session_token_value(site, name, ck, val) 
            print(f"[SESSION] active={name}, 주입={auth_cookies}")

        except Exception as e:
            print(f"[SESSION] 세션 설정 실패, anonymous 진행: {e}")
            return

        # DEBUG: 리다이렉트 끝까지 따라가서 최종 지점 확인
        try:
            chain = self.zap.core.access_url(url=target_url, followredirects=True)
            last = chain[-1] if isinstance(chain, list) and chain else {}
            req = (last.get("requestHeader") or "?").splitlines()[0]
            resp = (last.get("responseHeader") or "?").splitlines()[0]
            print(f"[SESSION] 테스트 요청 -> 최종 {req} : {resp}")

        except Exception as e:
            print(f"[SESSION] 테스트 요청 실패: {e}")


    # ZAP 사이트 트리에 target 직접 접근 등록 (Spider 시작 전 준비)
    def access_target(self, target_url: str):
        self.zap.core.access_url(url=target_url, followredirects=True)
        time.sleep(2)  # 사이트 트리 반영 대기


    # Spider 실행, 완료(100%)까지 폴링
    def run_spider(self, target_url: str, context_name=CONTEXT_NAME):
        try:  # Spider 시작 시점의 세션 상태 — capture_session 이후 유지 여부 확인용
            print(f"\n\n[SPIDER] 시작 시 세션 상태: {self.zap.httpsessions.sessions(urlsplit(target_url).netloc)}\n")

        except Exception as e:
            print(f"[SPIDER] 세션 상태 조회 실패: {e}")

        scan_id = self.zap.spider.scan(url=target_url, recurse=True, contextname=context_name)
        time.sleep(2)

        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"\r[SPIDER] {self.zap.spider.status(scan_id)}%", end="", flush=True)
            time.sleep(2)

        print("\r[SPIDER] 100% 완료")


    # Ajax Spider 실행 (SPA/JS 기반 요청 발견용, 선택 실행), timeout_seconds 초과 시 stop 후 결과 반환
    def run_ajax_spider(self, target_url: str, timeout_seconds: int) -> dict:
        self.zap.ajaxSpider.set_option_number_of_browsers(_AJAX_BROWSERS)  # 병렬 브라우저 수 제한
        self.zap.ajaxSpider.scan(url=target_url, inscope=True)

        time.sleep(2)
        start = time.time()
        completed = True

        while self.zap.ajaxSpider.status != "stopped":
            elapsed = time.time() - start

            if elapsed >= timeout_seconds:  # 시간 초과, 실패 아닌 정상 중단
                completed = False
                self.zap.ajaxSpider.stop()
                print(f"\n[AJAX SPIDER] {timeout_seconds}초 초과, 중단 요청")

                while self.zap.ajaxSpider.status != "stopped":
                    time.sleep(1)
                break

            print(f"\r[AJAX SPIDER] {self.zap.ajaxSpider.status} ({int(elapsed)}s/{timeout_seconds}s)", end="", flush=True)
            time.sleep(2)

        elapsed_seconds = round(time.time() - start, 1)
        print(f"\r[AJAX SPIDER] {'완료' if completed else '타임아웃 중단'} (경과 {elapsed_seconds}s)")
        return {
            "status": self.zap.ajaxSpider.status,
            "completed": completed,
            "timeout": timeout_seconds,
            "elapsed_seconds": elapsed_seconds,
        }

    # raw 메시지 일부만 조회 (필드 구조 확인용)
    def get_messages_sample(self, base_url: str, count=3):
        return self.zap.core.messages(baseurl=base_url, start=0, count=count)

    # 전체 메시지 조회 (페이지네이션)
    def get_all_messages(self, base_url: str, page_size=200):
        all_msgs, start = [], 0
        
        while True:
            batch = self.zap.core.messages(baseurl=base_url, start=start, count=page_size)
            all_msgs.extend(batch)
            if len(batch) < page_size:
                break
            start += page_size

        return all_msgs