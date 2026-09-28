from __future__ import annotations

# final status 확정본 값 집합 (XSS·SQLi 공용). 화면 표시는 web 쪽에서 별도 매핑.
POTENTIAL_HIGH = "potential_high"      # 명확하고 반복 가능한 공격 성공 근거
POTENTIAL_MEDIUM = "potential_medium"  # 취약 신호 존재, 실행 또는 재현성 부족
POTENTIAL_LOW = "potential_low"        # 검사 완료, 공격 근거 미확인
INCONCLUSIVE = "inconclusive"          # 검사 미완료, 비교 데이터 부족
