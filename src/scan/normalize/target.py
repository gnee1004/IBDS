from dataclasses import dataclass

from .param_filter import NOSCAN_KEYWORDS, is_control_param, is_security_token


@dataclass
class RequestTarget:
    method: str                      # HTTP 메서드
    url: str                         # 쿼리 포함 전체 URL
    base_url: str                    # 쿼리 없는 base URL
    params: dict[str, list[str]]     # 주입 대상 파라미터 (키 → 값 목록, 같은 이름이 여러 번 나오면 등장 순서대로), GET은 쿼리스트링/POST는 폼바디에서 추출
    param_location: str              # 파라미터 위치: "query" 또는 "body"
    headers: dict[str, str]          # 요청 헤더 (cookie 키 제외)
    cookies: dict[str, str]          # 쿠키
    request_body: str                # 요청 바디 원문 (GET은 보통 빈 문자열)
    response_status: int             # 응답 상태 코드
    response_headers: dict[str, str] # 응답 헤더
    response_body: str               # 응답 바디
    zap_message_id: str              # ZAP 메시지 ID (추적용)

    # CSRF/token 계열, 액션 버튼, 보안 토큰 값 제외한 스캔 대상 파라미터 목록
    def scannable_params(self) -> list[str]:
        return [
            k for k, values in self.params.items()
            if not any(kw in k.lower() for kw in NOSCAN_KEYWORDS)
            and not any(is_control_param(v) for v in values)
            and not any(is_security_token(v) for v in values)
        ]

    def to_dict(self) -> dict:
        return {
            "zap_message_id": self.zap_message_id,
            "method": self.method,
            "url": self.url,
            "base_url": self.base_url,
            "param_location": self.param_location,
            "params": self.params,
            "scannable_params": self.scannable_params(),
            "headers": self.headers,
            "cookies": self.cookies,
            "request_body": self.request_body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
        }