from __future__ import annotations
from dataclasses import dataclass


@dataclass
class ScanPoint:  # RequestTarget에서 공격 대상 파라미터를 하나씩 분리한 것.
    target_id: str       # 어느 RequestTarget에서 나왔는지 연결하는 키
    name: str            # 파라미터 이름 (예: "id", "username")
    location: str        # 파라미터 위치 ("query", "form", "json")
    original_value: str  # 파라미터 원본값 — payload 템플릿의 {value} 자리에 들어감
    value_type: str      # 값 타입 ("string" or "number") — 2번이 룰 매칭 시 사용


@dataclass
class MatchedRule: # 룰 선택 + {value} 치환까지 끝낸 결과물.
    attack_id: str       # 룰 식별자 (예: "AR-SQLI-ERR-001")
    vuln_type: str       # 취약점 타입 ("sqli" or "xss")
    technique: str       # 공격 기법 (예: "error", "boolean", "time")
    sequence: list[str]  # step 순서 — "baseline" 포함, 3번이 baseline은 스킵
    rendered_payloads: dict[str, list[str]]  # step별 치환 완료된 payload (예: {"error_attack": ["1'", ...]})


@dataclass
class MutationCase: # HTTP 요청 하나를 완전히 표현하는 단위. baseline과 mutation 모두 이 타입
    case_id: str         # 케이스 식별자 (예: "t0_id_AR-SQLI-ERR-001_baseline")
    step: str            # 이 케이스의 step (예: "baseline", "error_attack")
    method: str          # HTTP 메서드
    url: str             # 요청 URL — query mutation이면 payload가 URL에 포함
    headers: dict[str, str]  # 요청 헤더
    cookies: dict[str, str]  # 쿠키
    body_type: str       # 바디 타입 ("query" or "form") — "body" → "form" 변환된 값
    body: str            # 요청 바디 — form mutation이면 payload가 body에 포함
    payload: str | None = None         # 삽입된 payload — baseline은 None
    original_value: str | None = None  # 원본 파라미터 값 — baseline은 None


@dataclass
class RequestFamily: # 1파라미터 x 1룰 = 1Family. 분석기가 baseline 대비 응답 차이를 비교하는 단위
    family_id: str                # family 식별자 (예: "t0_id_AR-SQLI-ERR-001")
    target_id: str                # 어느 타겟에서 나온 family인지
    param: str                    # 공격 대상 파라미터 이름
    attack_id: str                # 적용된 룰 식별자
    vuln_type: str                # 취약점 타입 ("sqli" or "xss")
    technique: str                # 공격 기법
    baseline: MutationCase        # 원본 요청 — 응답 비교 기준점
    mutations: list[MutationCase] # payload 교체된 요청 목록


@dataclass
class CaseResult:  # MutationCase 하나를 전송한 결과
    case: MutationCase                                   # 어떤 요청을 보냈는지 (원본 그대로 참조)
    status: str                                          # "ok" 또는 "error"
    response_status: int | None = None
    response_headers: dict[str, str] | None = None
    response_body: str | None = None
    elapsed: float | None = None
    error: str | None = None                             # status="error"일 때 예외 메시지
    effective_cookies: dict[str, str] | None = None       # 요청 전송 시점에 실제로 실린 누적 쿠키


@dataclass
class FamilyResult:  # RequestFamily 하나를 전송한 결과 — baseline/mutations를 family 단위로 묶음
    family_id: str                # family 식별자
    vuln_type: str                # 취약점 타입 ("sqli" or "xss")
    technique: str                # 공격 기법
    target_id: str                # 어느 타겟에서 나온 family인지
    param: str                    # 공격 대상 파라미터 이름
    attack_id: str                # 적용된 룰 식별자
    baseline: CaseResult          # baseline 전송 결과
    mutations: list[CaseResult]   # mutation 전송 결과 목록


@dataclass
class DiscoveryResult:  # XSS family 생성 전 Discovery 단계의 결과
    reflected: bool                        # marker 문자열이 응답에 그대로 반사되는지
    valid_specials: set[str]               # 반사 지점에서 이스케이프 없이 살아남은 특수문자 집합
    injection_context: str | None = None   # inHTML/inAttr/inScript 판정 — 이번 범위에서는 항상 None (TODO)