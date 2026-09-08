import re
from dataclasses import dataclass

# CSRF/토큰 계열 파라미터 이름 키워드 (scan 대상에서 제외)
_NOSCAN_KEYWORDS = frozenset({
    "token", "csrf", "_wpnonce", "nonce",
    "viewstate", "__requestverificationtoken",
})

# 토큰처럼 생긴거 거르기
_HEX_TOKEN_RE = re.compile(r'^[0-9a-fA-F]{16,}$')

# 폼 제출/액션 값 (control 파라미터)
_CONTROL_ACTION_WORDS = frozenset({
    "submit", "login", "search", "change", "update", "delete",
    "create", "register", "logout", "reset", "cancel", "sign",
    "upload", "clear", "add", "remove",
})

# 기존 상태 피괴 액션 값
_DESTRUCTIVE_ACTION_WORDS = frozenset({
    "clear", "delete", "reset", "remove", "logout", "remove"
})


# 파라미터 값을 소문자 토큰 집합으로 분해 (단어매칭용 헬퍼)
def _value_words(value: str) -> set[str]:
    return set((value or "").strip().lower().replace("+", " ").split()) # "+" 는 공백 취급


# 값에 control 액션 단어가 포함되어 있으면 control 파라미터로 판정
def _is_control_param(value: str) -> bool:
    return bool(_value_words(value) & _CONTROL_ACTION_WORDS)


# 파라미터 값에서 파괴적 단어 검사
def has_destructive_action(params: dict) -> bool:
    for value in params.values():
        candidates = value if isinstance(value, (list, tuple)) else [value] # 스칼라 문자열, 문자열 리스트 양쪽 다 허용
        if any(_value_words(v) & _DESTRUCTIVE_ACTION_WORDS for v in candidates): # 파괴적 액션 단어가 하나라도 있으면 True
            return True
    return False


# 16자 이상 hex 문자열이면 보안 토큰(세션 ID 등)으로 판정
def _is_security_token(value: str) -> bool:
    return bool(_HEX_TOKEN_RE.match((value or "").strip()))


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
            if not any(kw in k.lower() for kw in _NOSCAN_KEYWORDS)
            and not any(_is_control_param(v) for v in values)
            and not any(_is_security_token(v) for v in values)
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