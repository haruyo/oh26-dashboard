# OH26 自動化ダッシュボード

https://haruyo.github.io/oh26-dashboard/

OH26の定期ジョブ（タスクスケジューラ OH26-*）の実行履歴を週表示で確認できる静的ページ。

- `data.json` は各ジョブ完了時に `E:\2026ALL\scheduler\run-job.ps1` が自動生成・pushする
- 生成元: `build_dashboard.py`（schedulerのログから成否・時刻・所要分のみ抽出）
- **公開ページのため、ログ本文・顧客名・金額などの機微情報は載せない**（schedule.json の注記参照）
