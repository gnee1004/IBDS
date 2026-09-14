"""로컬 웹 리포트 화면용 — findings.jsonl/request_results.jsonl을 읽어 URL·파라미터 단위로 묶음.
CLAUDE.md #3: src/analyzer 무수정, 이미 저장된 결과만 후처리해서 읽음.
"""
from __future__ import annotations
import json
import os
from datetime import datetime


# jsonl 파일 한 줄씩 dict로 읽기, 깨진 줄은 건너뜀
def _read_jsonl(path: str):
    if not path or not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


# out_dir(수집 결과 폴더) 안의 request_results.jsonl/findings.jsonl을 읽어
# (target_id, param) 단위로 묶은 그룹 목록을 반환
def build_report(out_dir: str) -> list[dict]:
    results_path = os.path.join(out_dir, "request_results.jsonl")
    findings_path = os.path.join(out_dir, "findings.jsonl")

    # family_id -> family 요청 URL/메서드 (findings.jsonl에 url이 없는 XSS 판정 결과용 보조 조인)
    family_info: dict[str, dict] = {}
    for family in _read_jsonl(results_path):
        family_id = family.get("family_id")
        if not family_id:
            continue
        baseline_case = ((family.get("baseline") or {}).get("case")) or {}
        family_info[family_id] = {
            "url": baseline_case.get("url"),
            "method": baseline_case.get("method"),
        }

    groups: dict[tuple, dict] = {}
    for finding in _read_jsonl(findings_path):
        if finding.get("status") == "error":  # 라우팅/전송 자체가 실패한 레코드는 판정 결과가 아님
            continue

        target_id = finding.get("target_id")
        param = finding.get("param")
        if target_id is None or param is None:
            continue

        family_id = finding.get("family_id")
        info = family_info.get(family_id, {})
        url = finding.get("url") or info.get("url")  # sqli 판정은 자체 url 필드를 가짐

        if finding.get("final_status"):          # xss 판정 결과 (family_pipeline.judge_case)
            final_status = finding["final_status"]
        elif finding.get("stage") == "probe":    # Phase 1 sink 프로브 자체가 판정 불가 (공격 시도 전)
            final_status = "inconclusive"
        elif "confidence" in finding:            # sqli 판정(analyzer/scan.py)은 걸린 것만 기록 -> 기록 자체가 vulnerable
            final_status = "vulnerable"
        else:
            continue  # 판정 결과로 해석할 수 없는 레코드는 리포트에 안 올림

        vuln_type = finding.get("vuln_type") or ("sqli" if "confidence" in finding else "xss")
        payload = finding.get("payload") or finding.get("sink_note")  # probe 레코드는 payload 대신 판정 불가 사유를 보여줌

        key = (target_id, param)
        group = groups.setdefault(key, {"target_id": target_id, "param": param, "url": url, "items": []})
        if not group["url"] and url:
            group["url"] = url
        group["items"].append({
            "vuln_type": vuln_type,
            "technique": finding.get("technique"),
            "attack_id": finding.get("attack_id"),
            "payload": payload,
            "final_status": final_status,
        })

    return sorted(groups.values(), key=lambda g: (g["target_id"], g["param"]))


# results/ 아래에서 가장 최근에 만들어진 collection_* 폴더 경로 (없으면 None)
def latest_out_dir(project_root: str) -> str | None:
    dirs = _run_dirs(project_root)
    return os.path.join(project_root, "results", dirs[-1]) if dirs else None


def _run_dirs(project_root: str) -> list[str]:
    base = os.path.join(project_root, "results")
    if not os.path.isdir(base):
        return []
    return sorted(d for d in os.listdir(base) if d.startswith("collection_"))


# "collection_20260914_010113" -> "2026-09-14 01:01"
def _label(run_id: str) -> str:
    try:
        dt = datetime.strptime(run_id, "collection_%Y%m%d_%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return run_id


# jsonl 파일 줄 수 (전체 파싱 없이 개수만, 실행 기록 목록용)
def _count_lines(path: str) -> int:
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())


# 과거 실행 기록 목록 (최신순) - 리포트 화면의 실행 기록 선택용
def list_runs(project_root: str) -> list[dict]:
    base = os.path.join(project_root, "results")
    runs = []
    for run_id in reversed(_run_dirs(project_root)):
        findings_path = os.path.join(base, run_id, "findings.jsonl")
        runs.append({"id": run_id, "label": _label(run_id), "count": _count_lines(findings_path)})
    return runs


# run_id(폴더명)를 안전하게 results/ 경로로 변환 - 상위 경로 탈출 방지, 없으면 None
def resolve_run_dir(project_root: str, run_id: str) -> str | None:
    if not run_id or run_id not in _run_dirs(project_root):
        return None
    return os.path.join(project_root, "results", run_id)
