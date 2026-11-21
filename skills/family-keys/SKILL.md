---
name: family-keys
description: 家族LANのキーをENV名や用途で探し、取得・登録・変更・削除する。
---

値は会話・ツール引数・出力・ログに出さない。URLは登録済みMCPと同じ接続先だけ使う。以下のshは同梱の `scripts/` 内。

ログイン例（Discord）: `search_env` でメールとパスワードのENV名を探し、`prepare_env(vars)` に両方を渡す。`sh append-env.sh URL - bundle-json ローカル処理` の標準入力は `{"env":"DISCORD_PASSWORD=demo\n","totp":{"DISCORD_PASSWORD":"012345"}}`。認証画面が出たら `has_totp: true` の項目のENV名（複数あれば `totp_env`）で再取得し、`totp.DISCORD_PASSWORD` を入力する。

- .env追記: `search_env(queries)` → `prepare_env(vars)` → `sh append-env.sh URL .env`。ローカル処理の終了コードは 0 OK、10 NO_OTP、11 NO_FIELD、12 SUBMITTED。
- 登録: ENV名は必須・一意、1ENVにつき1件。`sh register-env.sh BASE 元の.env ENV 名前 用途 [ENV 名前 用途 …]`。BASEはMCPから /mcp を除いたURL。二段階も同時に登録するなら `sh register-env.sh --with-totp BASE 元の.env ENV 名前 用途 URIファイル`（URIを標準入力から渡すなら `-`）。
- ブラウザ登録: `begin_intake(items)` に `title, variable, purpose` の配列を渡してURLを開く。ローカル処理で元ファイルから直接フォームにセット（単独は `#paste-value`、一括は `data-variable`）。otpauth URIは「二段階認証を追加」。操作可能ならOKまで押し `wait_intake`。入力できない値だけ本人に頼む。
- 変更・削除: 依頼があれば `manage_env(name, action)`（`update` / `delete`）。`sh register-env.sh --change URL ENV 元の.env` または `sh register-env.sh --delete URL ENV`。名前・用途だけの変更は `title` / `purpose` を渡し、元の.envを省略。旧データの同名が複数なら項目IDも指定。
- 二段階設定: 元のENV名で `manage_env(name, action="totp")` → `sh register-env.sh --totp URL ENV URIファイル`。ファイルの代わりに `-` で標準入力。本人が貼り付ける場合はWebの「二段階認証追加」。
- Skills: 同じMCPの `family_skills`。引数なしで名前だけ、`query` で概要検索、`name` で選んだ本文URL。
