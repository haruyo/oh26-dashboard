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
