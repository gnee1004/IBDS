import re
import time
from urllib.parse import urlsplit

from zapv2 import ZAPv2  # type: ignore

from utilities.file_utils import load_json

SESSION_NAME = "IBDSSession"
CONTEXT_NAME = "IBDSContext"


# ZAP 수집 인프라 래퍼 (세션/Context/Spider만 담당, Active Scan 없음)
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

    # target origin(scheme+host+port) 밖 트래픽을 프록시 단에서 전역 제외 (범위 축소용, 위험 URL 필터링과는 별개)
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

    # 프록시가 캡처한 기존 세션 활성화, 없으면 anonymous로 진행
    def capture_session(self, target_url: str):
        parts = urlsplit(target_url)
        site = parts.netloc
        cap_sess = self.zap.httpsessions.sessions(site) 
        if len(cap_sess) != 0 :
            fst_sess_name = cap_sess[0]['session'][0] # 가장 최근 세션
            print(f"fst_sess_name: {fst_sess_name}")  # 세션 이름 확인
            cookie_name, cookie_info = next(iter(cap_sess[0]['session'][1].items())) # 쿠키 이름 하드코딩 없이 첫 항목 확인
            print(f"fst_sess_value: {cookie_name}={cookie_info['value']}")
            try :
                sess = {}
                sess = self.zap.httpsessions.set_active_session(site, fst_sess_name)
                print(f"[ZAP] 현재 세션 잡기 성공 : {sess}")
            except Exception as e:
                print(f"[ZAP] 세션 이름이 틀렸거나 site가 잡혀있지 않습니다. :{e}")
        else : 
            print("[ZAP] 설정된 세션이 없습니다. anonymous로 진행합니다.")

    # ZAP 사이트 트리에 target 직접 접근 등록 (Spider 시작 전 준비)
    def access_target(self, target_url: str):
        self.zap.core.access_url(url=target_url, followredirects=True)
        time.sleep(2)  # 사이트 트리 반영 대기

    # Spider 실행, 완료(100%)까지 폴링
    def run_spider(self, target_url: str, context_name=CONTEXT_NAME):
        scan_id = self.zap.spider.scan(url=target_url, recurse=True, contextname=context_name)
        time.sleep(2)
        while int(self.zap.spider.status(scan_id)) < 100:
            print(f"\r[SPIDER] {self.zap.spider.status(scan_id)}%", end="", flush=True)
            time.sleep(2)
        print("\r[SPIDER] 100% 완료")

    # Ajax Spider 실행 (SPA/JS 기반 요청 발견용, 선택 실행), timeout_seconds 초과 시 stop 후 결과 반환
    def run_ajax_spider(self, target_url: str, timeout_seconds: int) -> dict:
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