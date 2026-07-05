"""schedulerのログを走査して data.json を生成する

実行: python build_dashboard.py
入力: E:\\2026ALL\\scheduler\\logs\\<ジョブ名>\\YYYY-MM-DD_HHMMSS.log
出力: このフォルダの data.json（index.html が fetch する）

公開ページのため、ログの中身（本文）は一切載せない。載せるのは
ジョブ名・実行時刻・成否(exit)・所要分数のみ。
"""
import json
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).parent
LOGS = Path(r"E:\2026ALL\scheduler\logs")
KEEP_DAYS = 60

FOOTER_RE = re.compile(r"終了 .* \(exit=(-?\d+), ([\d.]+)分\)")


def parse_log(path: Path) -> dict | None:
    m = re.match(r"(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})(\d{2})", path.stem)
    if not m:
        return None
    start = f"{m.group(1)}T{m.group(2)}:{m.group(3)}:{m.group(4)}"
    exit_code = None
    minutes = None
    try:
        # 末尾数行から終了行を探す（utf-8-sig: BOM対応）
        tail = path.read_text(encoding="utf-8-sig", errors="replace").splitlines()[-5:]
        for line in tail:
            f = FOOTER_RE.search(line)
            if f:
                exit_code = int(f.group(1))
                minutes = float(f.group(2))
    except OSError:
        pass
    return {
        "start": start,
        "exit": exit_code,   # None = 実行中 or 異常終了でフッター無し
        "minutes": minutes,
    }


def main() -> int:
    schedule = json.loads((BASE / "schedule.json").read_text(encoding="utf-8-sig"))
    cutoff = datetime.now() - timedelta(days=KEEP_DAYS)

    runs = []
    if LOGS.exists():
        for job_dir in LOGS.iterdir():
            if not job_dir.is_dir():
                continue
            for log in job_dir.glob("*.log"):
                r = parse_log(log)
                if not r:
                    continue
                try:
                    if datetime.fromisoformat(r["start"]) < cutoff:
                        continue
                except ValueError:
                    continue
                r["job"] = job_dir.name
                runs.append(r)

    runs.sort(key=lambda r: r["start"])
    data = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "jobs": schedule["jobs"],
        "links": schedule["links"],
        "runs": runs,
    }
    (BASE / "data.json").write_text(
        json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    print(f"data.json 更新: {len(runs)} runs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
