# Family Keys

LAN向けの共有保管庫。ブラウザで登録した環境変数と二段階認証を、MCP対応のエージェントから用途で探し、認証付きの暗号化ダウンロードで受け取れます。

## 起動

gd **0.9.0** の開発版（`Schema` と `Task` API対応）、POSIXシェル、curl、OpenSSLが必要です。gdはPATHに置くか、`KEYS_GD` で実行ファイルを指定します。[gdのソースと配布状況](https://github.com/prog-sha/gd)

```sh
./keys check
./keys init
./keys serve
```

初期化時に共有Webパスワードを設定します。初期状態では [http://localhost:49174](http://localhost:49174) で起動します。ポート、公開ホスト名、別名は `settings.example.json` を参考に、ローカルの `settings.local.json` に設定できます。LANで使う場合は、停止中にサーバーIPと許可範囲を指定します。

```sh
./keys lan 192.0.2.10 192.0.2.0/24
./keys serve
```

上のIPは説明用です。実際のIPと範囲に置き換えてください。許可元はログイン後の「接続する端末」でも変更できます。Webログインとブラウザでのキー入力にはLAN内のHTTPを使うため、信頼できるネットワーク内で運用してください。

## 家族の端末をつなぐ

管理画面の「家族に配る」で、スキルと招待が付いた案内をコピーできます。案内をセットアップ先のエージェントに渡してください。招待は24時間・一度限りで、共通キーは端末の `~/.config/family-keys/key.env` に保存されます。

手動でMCPを追加する場合、名前は `family-keys`、接続先はサーバーの `/mcp` です。例として、同じPCから接続するCodexの設定は次のとおりです。

```toml
[mcp_servers.family-keys]
url = "http://localhost:49174/mcp"
```

## 操作

- `search_env` で名前・用途・ENV名を検索します。二段階認証がある項目には `has_totp: true` が付きます。
- `prepare_env(vars)` で複数のENVを一括取得できます。スキルの `append-env.sh URL .env` は既存の.envに追記し、`append-env.sh URL - bundle-json 処理` は `env` と `totp` を持つJSONをローカル処理に渡します。
- `begin_intake(items)` で登録フォームを開きます。ENV名は必須かつ一意で、otpauth URIも初回に入力できます。元の.envからの登録にはスキルの `register-env.sh` を使います。
- `manage_env` でENV名を指定して変更・削除・二段階認証の設定ができます。
- `family_skills` で家族用スキルを一覧・検索・取得できます。

配布用の `SKILL.md` と案内は管理画面で編集できます。元の手順は [SKILL.md](skills/family-keys/SKILL.md) を参照してください。

## 保存とテスト

ストレージと鍵は `state/` に保存されます。バックアップする場合は、サーバーを停止してからディレクトリ全体を保護された場所へ保存してください。テストは作業ディレクトリ内の `tmp/` にダミーデータを作ります。

```sh
./keys check
python3 tests/integration.py
node tests/intake_test.js
```

QR読み取り実装の著作権表示は [licenses/quirc.txt](licenses/quirc.txt) を参照してください。
