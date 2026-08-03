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
import subprocess
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

# --- Area51 Discord bot（別リポジトリ・別ログ形式） ---------------------------
# logs\YYYY-MM-DD_<kind>.log に1日分を追記していく形式。1行 = 1実行。
# approve は5分毎（1日約288回）なので1実行1レコードにすると60日で数万件になり
# data.enc.json が肥大する。日ごとに1レコードへ畳み、回数は n / 失敗は ng で持つ。
AREA51_LOGS = Path(r"C:\Users\be\Dropbox\works\M_MCT\260712MVP\area51-discord-bot\logs")
_TS = r"(?P<ts>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})"
# job_id -> (ログ種別, 実行1回を表す行の正規表現)
AREA51_JOBS = {
    "area51-approve":  ("approve",  re.compile(_TS + r" poll:(?P<body>.*)$")),
    "area51-feedback": ("feedback", re.compile(_TS + r" fetch status:(?P<body>.*)$")),
    "area51-flash":    ("flash",    re.compile(_TS + r" \[\w+\] flash status:(?P<body>.*)$")),
}
# run_*.ps1 は python の最終行をそのまま書く。python が落ちると本文が空になる。
POSTED_RE = re.compile(r"posted=(\S+)")
CLAUDE_EXIT_RE = re.compile(r"Claude 終了.*\(exit=(-?\d+)\)")


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


def parse_area51_day(path: Path, line_re: re.Pattern) -> dict | None:
    """1日分のログを畳んで {last, n, ng} を返す。実行行が1つも無ければ None。"""
    try:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
    except OSError:
        return None
    n = ng = 0
    last = None
    for line in text.splitlines():
        m = line_re.match(line.strip())
        if m:
            n += 1
            last = m.group("ts")
            body = m.group("body").strip()
            posted = POSTED_RE.search(body)
            # 本文が空 = python が落ちて最終行を出せなかった
            if not body or (posted and not posted.group(1).startswith("ok")):
                ng += 1
            continue
        c = CLAUDE_EXIT_RE.search(line)
        if c and c.group(1) != "0":
            ng += 1
    if not n:
        return None
    return {"last": last, "n": n, "ng": min(ng, n)}


def collect_area51(cutoff: datetime) -> tuple[list, dict]:
    """Area51 bot のログを走査する。

    戻り値: (runs, last_seen)
      runs      … 日ごとに畳んだレコード（cutoff より新しいものだけ）
      last_seen … job_id -> 最後に実行された datetime（cutoff より古くても入れる。
                  稼働判定に使うため）
    """
    runs: list = []
    last_seen: dict = {}
    if not AREA51_LOGS.exists():
        return runs, last_seen
    for job_id, (kind, line_re) in AREA51_JOBS.items():
        for log in sorted(AREA51_LOGS.glob(f"*_{kind}.log")):
            day = log.stem.split("_")[0]
            try:
                datetime.strptime(day, "%Y-%m-%d")
            except ValueError:
                continue
            d = parse_area51_day(log, line_re)
            if not d:
                continue
            start = d["last"].replace(" ", "T") if d["last"] else f"{day}T00:00:00"
            try:
                when = datetime.fromisoformat(start)
            except ValueError:
                continue
            if when > last_seen.get(job_id, datetime.min):
                last_seen[job_id] = when
            if when < cutoff:
                continue
            runs.append({
                "job": job_id,
                "start": start,
                "exit": 1 if d["ng"] else 0,
                "minutes": None,
                "n": d["n"],     # その日の実行回数
                "ng": d["ng"],   # うち失敗した回数
            })
    return runs, last_seen


def process_running(match: str, name: str | None = None) -> bool:
    """コマンドラインに match を含むプロセスがいるか。

    schtasks の出力は日本語ロケールだと「状態: 実行中」になり解析が壊れるので、
    ロケールに依存しない CIM を見る。自分自身（この判定用に起動した powershell の
    コマンドラインにも match が入る）は $PID で除外する。
    """
    if not match:
        return False
    flt = f"-Filter \"Name='{name}'\" " if name else ""
    ps = (
        f"Get-CimInstance Win32_Process {flt}| "
        f"Where-Object {{ $_.ProcessId -ne $PID -and $_.CommandLine -like '*{match}*' }} | "
        "Select-Object -First 1 -ExpandProperty ProcessId"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(out.stdout.strip())


def check_health(entry: dict, last_seen: dict, now: datetime) -> dict:
    """schedule.json の resident エントリ1件の稼働状況を判定する。

    判定はビルド時刻を基準にする。ページを開いた時刻と比べると、ダッシュボードの
    push が数時間おきなので常に「古い」と出てしまい、赤が意味を持たなくなるため。
    """
    chk = entry.get("check") or {}
    kind = chk.get("type")

    if kind == "process":
        ok = process_running(chk.get("match", ""), chk.get("name"))
        return {"status": "ok" if ok else "ng",
                "detail": "プロセス稼働中" if ok else "プロセスが見つかりません"}

    if kind == "log":
        parts = []
        ok = True
        for spec in chk.get("jobs", []):
            short = spec.get("short", spec.get("job", ""))
            when = last_seen.get(spec.get("job"))
            if when is None:
                ok = False
                parts.append(f"{short} 記録なし")
                continue
            age_min = (now - when).total_seconds() / 60
            limit = spec.get("stale_minutes", 30)
            if age_min > limit:
                ok = False
                parts.append(f"{short} {when:%m/%d %H:%M}（{int(age_min)}分前・停止の疑い）")
            else:
                parts.append(f"{short} {when:%H:%M}")
        if not parts:
            return {"status": "unknown", "detail": ""}
        return {"status": "ok" if ok else "ng", "detail": " ／ ".join(parts)}

    return {"status": "unknown", "detail": ""}


def main() -> int:
    schedule = json.loads((BASE / "schedule.json").read_text(encoding="utf-8-sig"))
    now = datetime.now()
    cutoff = now - timedelta(days=KEEP_DAYS)

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

    # Area51 Discord bot（日ごとに畳んだレコード）
    a51_runs, a51_last = collect_area51(cutoff)
    runs.extend(a51_runs)

    # 常駐・高頻度ボットの稼働状況（ビルド時点の判定）
    resident = []
    for entry in schedule.get("resident", []):
        e = {k: v for k, v in entry.items() if k != "check"}
        e.update(check_health(entry, a51_last, now))
        resident.append(e)

    runs.sort(key=lambda r: r["start"])
    data = {
        "generated": now.strftime("%Y-%m-%d %H:%M"),
        "jobs": schedule["jobs"],
        "resident": resident,
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
    ng = [r["label"] for r in resident if r.get("status") == "ng"]
    print(f"data.enc.json 更新: {len(runs)} runs（暗号化済み）"
          + (f" ／ 要確認: {', '.join(ng)}" if ng else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
