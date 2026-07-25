from __future__ import annotations

import dataclasses
import json
from pathlib import Path

from scan.mutation.models import RequestFamily


def write_families(families: list[RequestFamily], output_path: str | Path) -> Path:
    """RequestFamily 목록을 JSONL로 저장. 저장된 파일 경로 반환."""
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for family in families:
            f.write(json.dumps(dataclasses.asdict(family), ensure_ascii=False) + "\n")
    return output_path
