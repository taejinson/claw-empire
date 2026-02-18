<p align="center">
  <img src="public/claw-empire.svg" width="80" alt="Claw-Empire" />
</p>

<h1 align="center">Claw-Empire</h1>

<p align="center">
  <strong>CEOデスクからAIエージェント帝国を指揮しよう</strong><br>
  <b>Claude Code</b>、<b>Codex CLI</b>、<b>Gemini CLI</b>、<b>OpenCode</b>、<b>GitHub Copilot</b>、<b>Antigravity</b>を自律エージェントの仮想企業に変えるローカルファーストAIエージェントオフィスシミュレーター
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="Version" />
  <img src="https://img.shields.io/badge/node-%3E%3D22-brightgreen" alt="Node.js 22+" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-orange" alt="License" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Platform" />
  <img src="https://img.shields.io/badge/AI-Claude%20%7C%20Codex%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Copilot%20%7C%20Antigravity-purple" alt="AI Agents" />
</p>

<p align="center">
  <a href="#クイックスタート">クイックスタート</a> &middot;
  <a href="#ai-installation-guide">AIインストール</a> &middot;
  <a href="#openclaw-integration">OpenClaw連携</a> &middot;
  <a href="#dollar-command-logic">$ コマンド</a> &middot;
  <a href="#機能一覧">機能一覧</a> &middot;
  <a href="#スクリーンショット">スクリーンショット</a> &middot;
  <a href="#技術スタック">技術スタック</a> &middot;
  <a href="#cliプロバイダーの設定">プロバイダー</a> &middot;
  <a href="#セキュリティ">セキュリティ</a>
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="README_ko.md">한국어</a> | <b>日本語</b> | <a href="README_zh.md">中文</a>
</p>

<p align="center">
  <img src="Sample_Img/Office.png" alt="Office View" width="100%" />
</p>

---

## Claw-Empireとは？

Claw-EmpireはCLIベースのAIコーディングアシスタント — **Claude Code**、**Codex CLI**、**Gemini CLI**、**OpenCode** など — を完全にシミュレートされた**仮想ソフトウェア会社**へと変革します。あなたがCEOです。AIエージェントたちが社員として働きます。部署をまたいで協力し、会議を開き、タスクを完遂し、レベルアップしていく様子を、魅力的なピクセルアートのオフィスインターフェースを通じてリアルタイムに観察できます。

### なぜClaw-Empireなのか？

- **一つのインターフェースで複数のAIエージェントを管理** — Claude Code、Codex、Gemini CLIなどを単一のダッシュボードから一元管理
- **ローカルファースト＆プライバシー保護** — すべてのデータはローカルに保存。SQLiteデータベースを使用し、クラウド依存ゼロ
- **直感的なビジュアル体験** — ピクセルアートのオフィスビューがAIオーケストレーションを楽しく、わかりやすく表現
- **真の自律コラボレーション** — エージェントは独立したgit worktreeで作業し、会議に参加して成果物を生み出す

---

## AIでインストール

> **以下をAIコーディングエージェント（Claude Code、Codex、Gemini CLI等）に貼り付けるだけです：**
>
> ```
> Install Claw-Empire following the guide at:
> https://github.com/GreenSheep01201/claw-empire
> ```
>
> AIがこのREADMEを読んで自動的にすべてを処理します。

---

## スクリーンショット

<table>
<tr>
<td width="50%">

**ダッシュボード** — リアルタイムKPIメトリクス、エージェントランキング、各部署のステータスを一目で把握

<img src="Sample_Img/Dashboard.png" alt="Dashboard" width="100%" />
</td>
<td width="50%">

**カンバンボード** — 部署・エージェントフィルター付きのドラッグ＆ドロップによるタスク管理

<img src="Sample_Img/Kanban.png" alt="Kanban Board" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**スキルライブラリ** — カテゴリ別に整理された600以上のエージェントスキルを閲覧・割り当て

<img src="Sample_Img/Skills.png" alt="Skills Library" width="100%" />
</td>
<td width="50%">

**マルチプロバイダーCLI** — Claude Code、Codex、Gemini CLI、OpenCodeをモデル選択付きで設定

<img src="Sample_Img/CLI.png" alt="CLI Tools Settings" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**OAuth連携** — 暗号化トークンストレージによる安全なGitHub・Google OAuth

<img src="Sample_Img/OAuth.png" alt="OAuth Settings" width="100%" />
</td>
<td width="50%">

**議事録** — AIが生成する会議サマリーと複数ラウンドのレビュー承認フロー

<img src="Sample_Img/Meeting_Minutes.png" alt="Meeting Minutes" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**メッセンジャー連携** — Telegram、Discord、Slackから `$` CEOディレクティブを送信し、リアルタイムのタスク更新を受信（OpenClaw経由）

<img src="Sample_Img/telegram.png" alt="Messenger Integration" width="100%" />
</td>
<td width="50%">

**設定** — 会社名、CEO名、デフォルトCLIプロバイダー、言語などの環境設定

<img src="Sample_Img/Setting.png" alt="Settings" width="100%" />
</td>
</tr>
</table>

---

## 機能一覧

| 機能 | 説明 |
|------|------|
| **ピクセルアートオフィス** | 6つの部署でエージェントが歩き回り、作業し、会議に参加するアニメーション付きオフィスビュー |
| **カンバンタスクボード** | 受信箱、計画中、協議中、進行中、レビュー中、完了 — ドラッグ＆ドロップ対応の完全なタスクライフサイクル管理 |
| **CEOチャット＆ディレクティブ** | チームリーダーへの直接コミュニケーション；`$` ディレクティブで会議選択と作業パス/コンテキスト（`project_path`、`project_context`）を指定可能 |
| **マルチプロバイダー対応** | Claude Code、Codex CLI、Gemini CLI、OpenCode、Antigravity — すべて一つのダッシュボードから管理 |
| **OAuth連携** | ローカルSQLiteへのAES暗号化トークンストレージによるGitHub・Google OAuth |
| **リアルタイムWebSocket** | ライブステータス更新、アクティビティフィード、エージェント状態のリアルタイム同期 |
| **エージェントランキング＆XP** | タスク完了でXPを獲得するエージェント；上位パフォーマーを追跡するランキングボード |
| **スキルライブラリ** | Frontend、Backend、Design、AI、DevOps、Securityなど600以上のカテゴリ別スキル |
| **ミーティングシステム** | 予定・臨時ミーティング対応；AIによる議事録自動生成と複数ラウンドレビュー機能 |
| **Git Worktree分離** | 各エージェントは独立したgitブランチで作業し、CEO承認後にのみマージ |
| **多言語UI** | 英語、韓国語、日本語、中国語 — 自動検出または手動設定 |
| **メッセンジャー連携** | Telegram、Discord、Slack等 — OpenClawゲートウェイ経由で `$` CEOディレクティブ送信＆タスク更新受信 |
| **PowerPointエクスポート** | 議事録やレポートからプレゼンテーションスライドを自動生成 |
| **部署管理** | 企画、開発、デザイン、QA/QC、DevSecOps、オペレーション |

---

## 技術スタック

| レイヤー | 技術 |
|---------|------|
| **フロントエンド** | React 19 + Vite 7 + Tailwind CSS 4 + TypeScript 5.9 |
| **ピクセルアートエンジン** | PixiJS 8 |
| **バックエンド** | Express 5 + SQLite（設定不要の組み込みDB） |
| **リアルタイム通信** | WebSocket (ws) |
| **バリデーション** | Zod 4 |
| **アイコン** | Lucide React |
| **ルーティング** | React Router 7 |
| **エクスポート** | PptxGenJS（PowerPoint生成） |

<a id="ai-installation-guide">
## AIインストールガイド

> このセクションはAIコーディングエージェント向けです。各ステップで検証コマンドを実行してから次に進んでください。

### ステップ0: 前提条件の確認

```bash
# Node.js 22+
node -v

# pnpm（未導入ならcorepackを有効化）
pnpm -v || corepack enable

# git
git --version
```

### ステップ1: クローンしてワンクリックセットアップ

```bash
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire
bash install.sh
```

Windows PowerShell:

```powershell
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

### ステップ2: セットアップ結果の検証

macOS/Linux:

```bash
# 必須ファイル確認
[ -f .env ] && [ -f scripts/setup.mjs ] && echo "setup files ok"

# AGENTSオーケストレーションルール確認
grep -R "BEGIN claw-empire orchestration rules" ~/.openclaw/workspace/AGENTS.md AGENTS.md 2>/dev/null || true
```

Windows PowerShell:

```powershell
if ((Test-Path .\.env) -and (Test-Path .\scripts\setup.mjs)) { "setup files ok" }
$agentCandidates = @("$env:USERPROFILE\.openclaw\workspace\AGENTS.md", ".\AGENTS.md")
$agentCandidates | ForEach-Object { if (Test-Path $_) { Select-String -Path $_ -Pattern "BEGIN claw-empire orchestration rules" } }
```

### ステップ3: 起動とヘルスチェック

```bash
pnpm dev:local
```

別ターミナルで:

```bash
curl -s http://127.0.0.1:8790/healthz
```

期待値: `{"ok":true,...}`

### ステップ4: OpenClawゲートウェイ（任意）検証

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

`OPENCLAW_CONFIG` が有効なら、利用可能なメッセンジャーセッションが返ります。

---

## クイックスタート

### 前提条件

| ツール | バージョン | インストール |
|--------|-----------|-------------|
| **Node.js** | >= 22 | [nodejs.org](https://nodejs.org/) |
| **pnpm** | 最新版 | `corepack enable`（Node.js組み込み） |
| **Git** | 任意 | [git-scm.com](https://git-scm.com/) |

### ワンクリックセットアップ（推奨）

| プラットフォーム | コマンド |
|------------------|----------|
| **macOS / Linux** | `git clone https://github.com/GreenSheep01201/claw-empire.git && cd claw-empire && bash install.sh` |
| **Windows (PowerShell)** | `git clone https://github.com/GreenSheep01201/claw-empire.git; cd claw-empire; powershell -ExecutionPolicy Bypass -File .\install.ps1` |

既にクローン済みの場合:

| プラットフォーム | コマンド |
|------------------|----------|
| **macOS / Linux** | `bash scripts/openclaw-setup.sh` |
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1` |

### 手動セットアップ（代替）

<details>
<summary><b>macOS / Linux</b></summary>

```bash
# 1. リポジトリをクローン
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. corepackでpnpmを有効化
corepack enable

# 3. 依存関係をインストール
pnpm install

# 4. ローカル環境ファイルを作成
cp .env.example .env

# 5. ランダムな暗号化シークレットを生成
node -e "
  const fs = require('fs');
  const crypto = require('crypto');
  const p = '.env';
  const content = fs.readFileSync(p, 'utf8');
  fs.writeFileSync(p, content.replace('__CHANGE_ME__', crypto.randomBytes(32).toString('hex')));
"

# 6. AGENTS.mdオーケストレーション規則をセットアップ（AIエージェントにClaw-Empireプロジェクトマネージャーの役割を付与）
pnpm setup -- --port 8790

# 7. 開発サーバーを起動
pnpm dev:local
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# 1. リポジトリをクローン
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. corepackでpnpmを有効化
corepack enable

# 3. 依存関係をインストール
pnpm install

# 4. ローカル環境ファイルを作成
Copy-Item .env.example .env

# 5. ランダムな暗号化シークレットを生成
node -e "const fs=require('fs');const crypto=require('crypto');const p='.env';const c=fs.readFileSync(p,'utf8');fs.writeFileSync(p,c.replace('__CHANGE_ME__',crypto.randomBytes(32).toString('hex')))"

# 6. AGENTS.mdオーケストレーション規則をセットアップ（AIエージェントにClaw-Empireプロジェクトマネージャーの役割を付与）
pnpm setup -- --port 8790

# 7. 開発サーバーを起動
pnpm dev:local
```

</details>

### AGENTS.md セットアップ

`pnpm setup` コマンドはAIエージェントの `AGENTS.md` ファイルに**CEOディレクティブオーケストレーション規則**を注入します。これによりAIコーディングエージェント（Claude Code、Codex等）が以下を実行できるようになります：

- `$` プレフィックス **CEOディレクティブ** の解釈と優先タスクの委任
- Claw-Empire REST APIを呼び出してタスク作成、エージェント割り当て、ステータス報告
- 安全な並行開発のための独立したgit worktree環境での作業

```bash
# デフォルト：AGENTS.mdの場所を自動検出
pnpm setup

# カスタムパス
pnpm setup -- --agents-path /path/to/your/AGENTS.md

# カスタムポート
pnpm setup -- --port 8790
```

<a id="openclaw-integration"></a>
### OpenClaw連携セットアップ（Telegram/Discord/Slack）

`install.sh` / `install.ps1`（または `scripts/openclaw-setup.*`）は、可能な場合に `OPENCLAW_CONFIG` を自動検出して `.env` に設定します。

デフォルトパス:

| OS | パス |
|----|------|
| **macOS / Linux** | `~/.openclaw/openclaw.json` |
| **Windows** | `%USERPROFILE%\.openclaw\openclaw.json` |

手動実行:

```bash
# macOS / Linux
bash scripts/openclaw-setup.sh --openclaw-config ~/.openclaw/openclaw.json
```

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1 -OpenClawConfig "$env:USERPROFILE\.openclaw\openclaw.json"
```

セッション確認:

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

<a id="dollar-command-logic"></a>
### `$` コマンドによるOpenClawチャット依頼ロジック

チャットメッセージが `$` で始まる場合、Claw-EmpireはCEOディレクティブとして扱います。

1. オーケストレーターがチームリーダー会議を開くか確認します。
2. オーケストレーターが作業対象のプロジェクト（`project_path` または `project_context`）を確認します。
3. `$` プレフィックス付きのメッセージを `POST /api/inbox` に送信します。
4. 会議を省略する場合は `"skipPlannedMeeting": true` を付けます。
5. サーバーは `directive` として保存し、全社共有後に企画チーム（およびメンション部門）へ委任します。

会議あり:

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -d '{"source":"telegram","author":"ceo","text":"$金曜までにQA承認付きでv0.2をリリース","project_path":"/Users/me/Projects/climpire"}'
```

会議なし:

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -d '{"source":"telegram","author":"ceo","text":"$本番ログイン不具合を今すぐホットフィックス","skipPlannedMeeting":true,"project_context":"既存の climpire プロジェクト"}'
```

ブラウザで開く：

| URL | 説明 |
|-----|------|
| `http://127.0.0.1:8800` | フロントエンド（Vite開発サーバー） |
| `http://127.0.0.1:8790/healthz` | APIヘルスチェック |

---

## 環境変数

`.env.example` を `.env` にコピーしてください。すべてのシークレットはローカルに保管されます — `.env` はコミットしないでください。

| 変数 | 必須 | 説明 |
|------|------|------|
| `OAUTH_ENCRYPTION_SECRET` | **必須** | SQLite内のOAuthトークンを暗号化 |
| `PORT` | 任意 | サーバーポート（デフォルト: `8790`） |
| `HOST` | 任意 | バインドアドレス（デフォルト: `127.0.0.1`） |
| `DB_PATH` | 任意 | SQLiteデータベースパス（デフォルト: `./claw-empire.sqlite`） |
| `LOGS_DIR` | 任意 | ログディレクトリ（デフォルト: `./logs`） |
| `OAUTH_GITHUB_CLIENT_ID` | 任意 | GitHub OAuth Appクライアント ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | 任意 | GitHub OAuth Appクライアントシークレット |
| `OAUTH_GOOGLE_CLIENT_ID` | 任意 | Google OAuthクライアントID |
| `OAUTH_GOOGLE_CLIENT_SECRET` | 任意 | Google OAuthクライアントシークレット |
| `OPENAI_API_KEY` | 任意 | OpenAI APIキー（Codex用） |

---

## 実行モード

```bash
# 開発モード（ローカルのみ、推奨）
pnpm dev:local          # 127.0.0.1にバインド

# 開発モード（ネットワークアクセス可）
pnpm dev                # 0.0.0.0にバインド

# プロダクションビルド
pnpm build              # TypeScriptチェック + Viteビルド
pnpm start              # ビルド済みサーバーを起動

# ヘルスチェック
curl -fsS http://127.0.0.1:8790/healthz
```

---

## CLIプロバイダーの設定

Claw-Empireは複数のCLIベースAIコーディングアシスタントに対応しています。少なくとも一つをインストールしてください：

| プロバイダー | インストール | 認証 |
|-------------|------------|------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm i -g @anthropic-ai/claude-code` | `claude`（プロンプトに従う） |
| [Codex CLI](https://github.com/openai/codex) | `npm i -g @openai/codex` | `.env`に`OPENAI_API_KEY`を設定 |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `npm i -g @google/gemini-cli` | 設定パネルからOAuth認証 |
| [OpenCode](https://github.com/opencode-ai/opencode) | `npm i -g opencode` | プロバイダー固有の設定 |

アプリ内の **Settings > CLI Tools** パネルでプロバイダーとモデルを設定してください。

---

## プロジェクト構成

```
claw-empire/
├── server/
│   └── index.ts              # Express 5 + SQLite + WebSocketバックエンド
├── src/
│   ├── App.tsx                # ルーティング付きメインReactアプリ
│   ├── api.ts                 # フロントエンドAPIクライアント
│   ├── i18n.ts                # 多言語サポート（en/ko/ja/zh）
│   ├── components/
│   │   ├── OfficeView.tsx     # PixiJSエージェント付きピクセルアートオフィス
│   │   ├── Dashboard.tsx      # KPIメトリクスとチャート
│   │   ├── TaskBoard.tsx      # カンバン形式のタスク管理
│   │   ├── ChatPanel.tsx      # CEO-エージェント間コミュニケーション
│   │   ├── SettingsPanel.tsx  # 会社・プロバイダー設定
│   │   ├── SkillsLibrary.tsx  # エージェントスキル管理
│   │   └── TerminalPanel.tsx  # リアルタイムCLI出力ビューアー
│   ├── hooks/                 # usePolling, useWebSocket
│   └── types/                 # TypeScript型定義
├── public/sprites/            # 12種類のピクセルアートエージェントスプライト
├── scripts/
│   ├── openclaw-setup.sh      # ワンクリックセットアップ（macOS/Linux）
│   ├── openclaw-setup.ps1     # ワンクリックセットアップ（Windows PowerShell）
│   ├── preflight-public.sh    # リリース前セキュリティチェック
│   └── generate-architecture-report.mjs
├── install.sh                 # scripts/openclaw-setup.sh のラッパー
├── install.ps1                # scripts/openclaw-setup.ps1 のラッパー
├── docs/                      # 設計・アーキテクチャドキュメント
├── .env.example               # 環境変数テンプレート
└── package.json
```

---

## セキュリティ

Claw-Empireはセキュリティを重視した設計になっています：

- **ローカルファーストアーキテクチャ** — すべてのデータをSQLiteにローカル保存；外部クラウドサービス不要
- **OAuthトークンの暗号化** — ユーザーのOAuthトークンは**サーバー側のSQLiteにのみ保存**され、`OAUTH_ENCRYPTION_SECRET`を使用してAES-256-GCMで暗号化されます。ブラウザにリフレッシュトークンが渡ることはありません
- **ビルトインOAuth Client ID** — ソースコードに埋め込まれたGitHub・Google OAuth client ID/secretは**公開OAuthアプリ認証情報**であり、ユーザーシークレットではありません。[Googleのドキュメント](https://developers.google.com/identity/protocols/oauth2/native-app)によると、インストール型/デスクトップアプリのclient secretは「シークレットとして扱われない」とされています。これはオープンソースアプリ（VS Code、Thunderbird、GitHub CLI等）の標準的な慣行です。これらの認証情報はアプリ自体を識別するだけであり、個人トークンは常に別途暗号化されます
- **ソースコードに個人認証情報なし** — すべてのユーザー固有トークン（GitHub、Google OAuth）はローカルSQLiteに暗号化して保存され、ソースコードには含まれません
- **リポジトリにシークレットを含まない** — 包括的な `.gitignore` が `.env`、`*.pem`、`*.key`、`credentials.json` などをブロック
- **プリフライトセキュリティチェック** — 公開リリース前に `pnpm run preflight:public` を実行し、ワーキングツリーとgit履歴の両方で漏洩したシークレットをスキャン
- **デフォルトでローカルホスト** — 開発サーバーは `127.0.0.1` にバインドされ、ネットワークに公開されない

---

## コントリビューション

コントリビューションを歓迎します！以下の手順でお願いします：

1. リポジトリをフォーク
2. フィーチャーブランチを作成（`git checkout -b feature/amazing-feature`）
3. 変更をコミット（`git commit -m 'Add amazing feature'`）
4. ブランチにプッシュ（`git push origin feature/amazing-feature`）
5. Pull Requestを作成

---

## ライセンス

[Apache 2.0](LICENSE) — 個人・商用利用ともに無料。

---

<div align="center">

**ピクセルと情熱で作られています。**

*Claw-Empire — AIエージェントたちが働く場所。*

</div>
