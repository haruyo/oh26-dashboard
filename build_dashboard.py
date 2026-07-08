"""schedulerのログを走査して data.enc.json（暗号化済み）を生成する

実行: python build_dashboard.py
入力: E:\\2026ALL\\scheduler\\logs\\<ジョブ名>\\YYYY-MM-DD_HHMMSS.log
出力: data.enc.json（AES-GCM暗号化。index.html がパスワードで復号）
      data.json（平文・ローカル確認用。gitignore対象＝公開されない）

パスワードは .password ファイル（gitignore対象）。変更したら再ビルドで反映。
"""
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta
from pathlib import Path

BASE = Path(__file__).parent
LOGS = Path(r"E:\2026ALL\scheduler\logs")
KEEP_DAYS = 60
PBKDF2_ITER = 200_000

FOOTER_RE = re.compile(r"終了 .* \(exit=(-?\d+), ([\d.]+)分\)")

# scheduler/logs の外で動く（別スクリプト・別フォーマットの）ジョブ。
# job_id -> (ログフォルダ, ファイル名の日時正規表現)。時:分が取れなければ 00:00 扱い。
EXTRA_LOG_DIRS = {
    "handle-loop": (
        Path(r"C:\Users\be\Dropbox\works\H_Handle\260408monthly-report\weekly_loop\logs"),
        re.compile(r"run-(\d{4}-\d{2}-\d{2})_(\d{2})(\d{2})"),
    ),
    "handle-monitor": (
        Path(r"C:\Users\be\Desktop\handle-260502\logs"),
        re.compile(r"weekly_(\d{4}-\d{2}-\d{2})"),
    ),
}
# 明らかなクラッシュだけ失敗扱い（外部ログには exit フッターが無いため）
CRASH_RE = re.compile(r"Traceback \(most recent call last\)|FATAL|Unhandled exception")


def parse_external_log(path: Path, date_re: re.Pattern) -> dict | None:
    m = date_re.search(path.name)
    if not m:
        return None
    hh = m.group(2) if m.lastindex and m.lastindex >= 2 else "00"
    mm = m.group(3) if m.lastindex and m.lastindex >= 3 else "00"
    start = f"{m.group(1)}T{hh}:{mm}:00"
    exit_code = 0  # 外部ジョブは「ログが残った＝実行された」を成功とみなす
    try:
        body = path.read_text(encoding="utf-8-sig", errors="replace")
        if CRASH_RE.search(body):
            exit_code = 1
    except OSError:
        pass
    return {"start": start, "exit": exit_code, "minutes": None}


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

    def keep(r) -> bool:
        try:
            return datetime.fromisoformat(r["start"]) >= cutoff
        except ValueError:
            return False

    runs = []
    if LOGS.exists():
        for job_dir in LOGS.iterdir():
            if not job_dir.is_dir():
                continue
            for log in job_dir.glob("*.log"):
                r = parse_log(log)
                if not r or not keep(r):
                    continue
                r["job"] = job_dir.name
                runs.append(r)

    # scheduler の外で動くジョブ（Handle系）も拾う
    for job_id, (log_dir, date_re) in EXTRA_LOG_DIRS.items():
        if not log_dir.exists():
            continue
        for log in log_dir.glob("*.log"):
            r = parse_external_log(log, date_re)
            if not r or not keep(r):
                continue
            r["job"] = job_id
            runs.append(r)

    runs.sort(key=lambda r: r["start"])
    data = {
        "generated": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "jobs": schedule["jobs"],
        "resident": schedule.get("resident", []),
        "links": schedule["links"],
        "runs": runs,
    }
    plain = json.dumps(data, ensure_ascii=False, indent=1)
    (BASE / "data.json").write_text(plain, encoding="utf-8")  # ローカル確認用（非公開）

    # --- 暗号化して公開用 data.enc.json を生成 ---
    password = (BASE / ".password").read_text(encoding="utf-8-sig").strip()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITER, dklen=32)
    ciphertext = AESGCM(key).encrypt(iv, plain.encode("utf-8"), None)
    enc = {
        "v": 1,
        "kdf": "PBKDF2-SHA256",
        "iter": PBKDF2_ITER,
        "salt": base64.b64encode(salt).decode(),
        "iv": base64.b64encode(iv).decode(),
        "data": base64.b64encode(ciphertext).decode(),
    }
    (BASE / "data.enc.json").write_text(json.dumps(enc), encoding="utf-8")
    print(f"data.enc.json 更新: {len(runs)} runs（暗号化済み）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
