<p align="center">
  <img src="public/claw-empire.svg" width="80" alt="Claw-Empire" />
</p>

<h1 align="center">Claw-Empire</h1>

<p align="center">
  <strong>从CEO办公桌指挥您的AI代理帝国</strong><br>
  将 <b>Claude Code</b>、<b>Codex CLI</b>、<b>Gemini CLI</b>、<b>OpenCode</b>、<b>GitHub Copilot</b>、<b>Antigravity</b> 转化为自主代理虚拟公司的本地优先AI代理办公室模拟器
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="Version" />
  <img src="https://img.shields.io/badge/node-%3E%3D22-brightgreen" alt="Node.js 22+" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-orange" alt="License" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Platform" />
  <img src="https://img.shields.io/badge/AI-Claude%20%7C%20Codex%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Copilot%20%7C%20Antigravity-purple" alt="AI Agents" />
</p>

<p align="center">
  <a href="#快速开始">快速开始</a> &middot;
  <a href="#ai-installation-guide">AI 安装指南</a> &middot;
  <a href="#openclaw-integration">OpenClaw 集成</a> &middot;
  <a href="#dollar-command-logic">$ 命令逻辑</a> &middot;
  <a href="#功能特性">功能特性</a> &middot;
  <a href="#截图">截图</a> &middot;
  <a href="#技术栈">技术栈</a> &middot;
  <a href="#cli-提供商配置">提供商</a> &middot;
  <a href="#安全性">安全性</a>
</p>

<p align="center">
  <a href="README.md">English</a> | <a href="README_ko.md">한국어</a> | <a href="README_jp.md">日本語</a> | <b>中文</b>
</p>

<p align="center">
  <img src="Sample_Img/Office.png" alt="Office View" width="100%" />
</p>

---

## 什么是 Claw-Empire？

Claw-Empire 将您的 CLI AI 编程助手 —— **Claude Code**、**Codex CLI**、**Gemini CLI**、**OpenCode** 等 —— 转化为一个完整模拟的**虚拟软件公司**。您是 CEO，AI 代理是员工。看着它们跨部门协作、召开会议、完成任务、不断成长 —— 一切都通过迷人的像素风格办公室界面直观呈现。

### 为什么选择 Claw-Empire？

- **统一界面，多款 AI 代理** — 从单一仪表板管理 Claude Code、Codex、Gemini CLI 等
- **本地优先，隐私保障** — 所有数据存储在您的机器上，SQLite 数据库，无需云端依赖
- **可视化且直观** — 像素艺术风格的办公室视图，让 AI 编排变得有趣而透明
- **真正的自主协作** — 代理在独立的 git worktree 中工作、参加会议并产出成果

---

## 用 AI 安装

> **只需将以下内容粘贴到您的 AI 编程代理（Claude Code、Codex、Gemini CLI 等）：**
>
> ```
> Install Claw-Empire following the guide at:
> https://github.com/GreenSheep01201/claw-empire
> ```
>
> AI 将阅读此 README 并自动处理一切。

---

## 截图

<table>
<tr>
<td width="50%">

**仪表板** — 实时 KPI 指标、代理排名和部门状态一览无余

<img src="Sample_Img/Dashboard.png" alt="Dashboard" width="100%" />
</td>
<td width="50%">

**看板** — 支持拖拽的任务管理，可按部门和代理筛选

<img src="Sample_Img/Kanban.png" alt="Kanban Board" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**技能库** — 浏览并分配 600+ 项跨类别的代理技能

<img src="Sample_Img/Skills.png" alt="Skills Library" width="100%" />
</td>
<td width="50%">

**多提供商 CLI** — 配置 Claude Code、Codex、Gemini CLI、OpenCode 并选择模型

<img src="Sample_Img/CLI.png" alt="CLI Tools Settings" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**OAuth 集成** — 安全的 GitHub 与 Google OAuth，加密令牌存储

<img src="Sample_Img/OAuth.png" alt="OAuth Settings" width="100%" />
</td>
<td width="50%">

**会议纪要** — AI 生成的会议摘要，支持多轮审阅与批准

<img src="Sample_Img/Meeting_Minutes.png" alt="Meeting Minutes" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**即时通讯集成** — 通过 Telegram、Discord、Slack 发送 `$` CEO 指令并接收实时任务更新（OpenClaw 集成）

<img src="Sample_Img/telegram.png" alt="Messenger Integration" width="100%" />
</td>
<td width="50%">

**设置** — 配置公司名称、CEO 名称、默认 CLI 提供商和语言偏好

<img src="Sample_Img/Setting.png" alt="Settings" width="100%" />
</td>
</tr>
</table>

---

## 功能特性

| 功能 | 描述 |
|------|------|
| **像素风格办公室** | 动态办公室视图，代理可在 6 个部门之间行走、工作和参加会议 |
| **看板任务面板** | 完整任务生命周期 — 收件箱、已计划、协作中、进行中、审阅中、已完成 — 支持拖拽操作 |
| **CEO 聊天与指令** | 与团队负责人直接沟通；`$` 指令支持会议选择与项目路径/上下文路由（`project_path`、`project_context`） |
| **多提供商支持** | Claude Code、Codex CLI、Gemini CLI、OpenCode、Antigravity — 统一仪表板管理 |
| **OAuth 集成** | GitHub 与 Google OAuth，AES 加密令牌本地存储于 SQLite |
| **实时 WebSocket** | 实时状态更新、活动动态及代理状态同步 |
| **代理排名与经验值** | 代理完成任务可获得经验值，排行榜追踪顶尖表现者 |
| **技能库** | 600+ 分类技能（前端、后端、设计、AI、DevOps、安全等） |
| **会议系统** | 支持计划内及临时会议，AI 生成纪要并支持多轮审阅 |
| **Git Worktree 隔离** | 每个代理在独立的 git 分支中工作，仅在 CEO 批准后合并 |
| **多语言界面** | 英语、韩语、日语、中文 — 自动检测或手动设置 |
| **即时通讯集成** | Telegram、Discord、Slack 等 — 通过 OpenClaw gateway 发送 `$` CEO 指令并接收任务更新 |
| **PowerPoint 导出** | 从会议纪要和报告生成演示文稿幻灯片 |
| **部门管理** | 规划、开发、设计、QA/QC、DevSecOps、运营 |

---

## 技术栈

| 层级 | 技术 |
|------|------|
| **前端** | React 19 + Vite 7 + Tailwind CSS 4 + TypeScript 5.9 |
| **像素艺术引擎** | PixiJS 8 |
| **后端** | Express 5 + SQLite（零配置嵌入式数据库） |
| **实时通信** | WebSocket (ws) |
| **数据校验** | Zod 4 |
| **图标** | Lucide React |
| **路由** | React Router 7 |
| **导出** | PptxGenJS（PowerPoint 生成） |

<a id="ai-installation-guide">
## AI 安装指南

> 本节面向 AI 编程代理。请逐步执行，并在每一步运行验证命令后再继续。

### 第 0 步：检查前置条件

```bash
# Node.js 22+
node -v

# pnpm（如缺失则启用 corepack）
pnpm -v || corepack enable

# git
git --version
```

### 第 1 步：克隆并执行一键安装

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

### 第 2 步：验证安装结果

macOS/Linux:

```bash
# 关键文件检查
[ -f .env ] && [ -f scripts/setup.mjs ] && echo "setup files ok"

# 检查 AGENTS 编排规则
grep -R "BEGIN claw-empire orchestration rules" ~/.openclaw/workspace/AGENTS.md AGENTS.md 2>/dev/null || true
```

Windows PowerShell:

```powershell
if ((Test-Path .\.env) -and (Test-Path .\scripts\setup.mjs)) { "setup files ok" }
$agentCandidates = @("$env:USERPROFILE\.openclaw\workspace\AGENTS.md", ".\AGENTS.md")
$agentCandidates | ForEach-Object { if (Test-Path $_) { Select-String -Path $_ -Pattern "BEGIN claw-empire orchestration rules" } }
```

### 第 3 步：启动并健康检查

```bash
pnpm dev:local
```

在另一个终端执行：

```bash
curl -s http://127.0.0.1:8790/healthz
```

期望结果：`{"ok":true,...}`

### 第 4 步：可选 OpenClaw 网关验证

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

当 `OPENCLAW_CONFIG` 有效时，将返回可用的消息会话列表。

---

## 快速开始

### 环境要求

| 工具 | 版本 | 安装方式 |
|------|------|---------|
| **Node.js** | >= 22 | [nodejs.org](https://nodejs.org/) |
| **pnpm** | 最新版 | `corepack enable`（Node.js 内置） |
| **Git** | 任意版本 | [git-scm.com](https://git-scm.com/) |

### 一键安装（推荐）

| 平台 | 命令 |
|------|------|
| **macOS / Linux** | `git clone https://github.com/GreenSheep01201/claw-empire.git && cd claw-empire && bash install.sh` |
| **Windows (PowerShell)** | `git clone https://github.com/GreenSheep01201/claw-empire.git; cd claw-empire; powershell -ExecutionPolicy Bypass -File .\install.ps1` |

如果仓库已克隆：

| 平台 | 命令 |
|------|------|
| **macOS / Linux** | `bash scripts/openclaw-setup.sh` |
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1` |

### 手动安装（备用）

<details>
<summary><b>macOS / Linux</b></summary>

```bash
# 1. 克隆仓库
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. 通过 corepack 启用 pnpm
corepack enable

# 3. 安装依赖
pnpm install

# 4. 创建本地环境文件
cp .env.example .env

# 5. 生成随机加密密钥
node -e "
  const fs = require('fs');
  const crypto = require('crypto');
  const p = '.env';
  const content = fs.readFileSync(p, 'utf8');
  fs.writeFileSync(p, content.replace('__CHANGE_ME__', crypto.randomBytes(32).toString('hex')));
"

# 6. 设置 AGENTS.md 编排规则（教 AI 代理成为 Claw-Empire 项目经理）
pnpm setup -- --port 8790

# 7. 启动开发服务器
pnpm dev:local
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# 1. 克隆仓库
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. 通过 corepack 启用 pnpm
corepack enable

# 3. 安装依赖
pnpm install

# 4. 创建本地环境文件
Copy-Item .env.example .env

# 5. 生成随机加密密钥
node -e "const fs=require('fs');const crypto=require('crypto');const p='.env';const c=fs.readFileSync(p,'utf8');fs.writeFileSync(p,c.replace('__CHANGE_ME__',crypto.randomBytes(32).toString('hex')))"

# 6. 设置 AGENTS.md 编排规则（教 AI 代理成为 Claw-Empire 项目经理）
pnpm setup -- --port 8790

# 7. 启动开发服务器
pnpm dev:local
```

</details>

### AGENTS.md 设置

`pnpm setup` 命令将 **CEO 指令编排规则** 注入到 AI 代理的 `AGENTS.md` 文件中。这使 AI 编程代理（Claude Code、Codex 等）能够：

- 解析 `$` 前缀 **CEO 指令**，进行优先任务委派
- 调用 Claw-Empire REST API 创建任务、分配代理、报告状态
- 在独立的 git worktree 环境中进行安全的并行开发

```bash
# 默认：自动检测 AGENTS.md 位置
pnpm setup

# 自定义路径
pnpm setup -- --agents-path /path/to/your/AGENTS.md

# 自定义端口
pnpm setup -- --port 8790
```

<a id="openclaw-integration"></a>
### OpenClaw 集成设置（Telegram/Discord/Slack）

`install.sh` / `install.ps1`（或 `scripts/openclaw-setup.*`）会在可用时自动检测并写入 `OPENCLAW_CONFIG` 到 `.env`。

默认路径：

| OS | 路径 |
|----|------|
| **macOS / Linux** | `~/.openclaw/openclaw.json` |
| **Windows** | `%USERPROFILE%\.openclaw\openclaw.json` |

手动命令：

```bash
# macOS / Linux
bash scripts/openclaw-setup.sh --openclaw-config ~/.openclaw/openclaw.json
```

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1 -OpenClawConfig "$env:USERPROFILE\.openclaw\openclaw.json"
```

会话验证：

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

<a id="dollar-command-logic"></a>
### `$` 命令的 OpenClaw 聊天委托逻辑

当聊天消息以 `$` 开头时，Claw-Empire 会将其作为 CEO 指令处理：

1. 编排器先询问是否召开组长会议。
2. 编排器会再确认项目路径/上下文（`project_path` 或 `project_context`）。
3. 将带 `$` 前缀的消息发送到 `POST /api/inbox`。
4. 若跳过会议，则附带 `"skipPlannedMeeting": true`。
5. 服务器按 `directive` 存储并全员广播，然后委派给企划组（以及被提及的部门）。

召开会议：

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -d '{"source":"telegram","author":"ceo","text":"$请在周五前完成带 QA 签核的 v0.2 发布","project_path":"/Users/me/Projects/climpire"}'
```

跳过会议：

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -d '{"source":"telegram","author":"ceo","text":"$立即修复生产环境登录故障","skipPlannedMeeting":true,"project_context":"之前在做的 climpire 项目"}'
```

在浏览器中打开：

| URL | 描述 |
|-----|------|
| `http://127.0.0.1:8800` | 前端（Vite 开发服务器） |
| `http://127.0.0.1:8790/healthz` | API 健康检查 |

---

## 环境变量

将 `.env.example` 复制为 `.env`。所有密钥均保存在本地，切勿提交 `.env` 文件。

| 变量 | 是否必填 | 描述 |
|------|---------|------|
| `OAUTH_ENCRYPTION_SECRET` | **必填** | 用于加密 SQLite 中的 OAuth 令牌 |
| `PORT` | 否 | 服务器端口（默认：`8790`） |
| `HOST` | 否 | 绑定地址（默认：`127.0.0.1`） |
| `DB_PATH` | 否 | SQLite 数据库路径（默认：`./claw-empire.sqlite`） |
| `LOGS_DIR` | 否 | 日志目录（默认：`./logs`） |
| `OAUTH_GITHUB_CLIENT_ID` | 否 | GitHub OAuth 应用客户端 ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | 否 | GitHub OAuth 应用客户端密钥 |
| `OAUTH_GOOGLE_CLIENT_ID` | 否 | Google OAuth 客户端 ID |
| `OAUTH_GOOGLE_CLIENT_SECRET` | 否 | Google OAuth 客户端密钥 |
| `OPENAI_API_KEY` | 否 | OpenAI API 密钥（用于 Codex） |

---

## 运行模式

```bash
# 开发模式（仅本地，推荐）
pnpm dev:local          # 绑定到 127.0.0.1

# 开发模式（网络可访问）
pnpm dev                # 绑定到 0.0.0.0

# 生产构建
pnpm build              # TypeScript 检查 + Vite 构建
pnpm start              # 运行构建后的服务器

# 健康检查
curl -fsS http://127.0.0.1:8790/healthz
```

---

## CLI 提供商配置

Claw-Empire 支持多款 CLI AI 编程助手，请至少安装其中一款：

| 提供商 | 安装方式 | 认证 |
|--------|---------|------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm i -g @anthropic-ai/claude-code` | `claude`（按提示操作） |
| [Codex CLI](https://github.com/openai/codex) | `npm i -g @openai/codex` | 在 `.env` 中设置 `OPENAI_API_KEY` |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `npm i -g @google/gemini-cli` | 通过设置面板进行 OAuth 认证 |
| [OpenCode](https://github.com/opencode-ai/opencode) | `npm i -g opencode` | 按提供商要求配置 |

在应用内的 **设置 > CLI 工具** 面板中配置提供商和模型。

---

## 项目结构

```
claw-empire/
├── server/
│   └── index.ts              # Express 5 + SQLite + WebSocket 后端
├── src/
│   ├── App.tsx                # 主 React 应用及路由
│   ├── api.ts                 # 前端 API 客户端
│   ├── i18n.ts                # 多语言支持（en/ko/ja/zh）
│   ├── components/
│   │   ├── OfficeView.tsx     # 基于 PixiJS 的像素风格办公室
│   │   ├── Dashboard.tsx      # KPI 指标和图表
│   │   ├── TaskBoard.tsx      # 看板式任务管理
│   │   ├── ChatPanel.tsx      # CEO 与代理通信
│   │   ├── SettingsPanel.tsx  # 公司和提供商设置
│   │   ├── SkillsLibrary.tsx  # 代理技能管理
│   │   └── TerminalPanel.tsx  # 实时 CLI 输出查看器
│   ├── hooks/                 # usePolling, useWebSocket
│   └── types/                 # TypeScript 类型定义
├── public/sprites/            # 12 款像素风格代理角色
├── scripts/
│   ├── openclaw-setup.sh      # 一键安装（macOS/Linux）
│   ├── openclaw-setup.ps1     # 一键安装（Windows PowerShell）
│   ├── preflight-public.sh    # 发布前安全检查
│   └── generate-architecture-report.mjs
├── install.sh                 # scripts/openclaw-setup.sh 包装脚本
├── install.ps1                # scripts/openclaw-setup.ps1 包装脚本
├── docs/                      # 设计与架构文档
├── .env.example               # 环境变量模板
└── package.json
```

---

## 安全性

Claw-Empire 在设计上充分考虑了安全性：

- **本地优先架构** — 所有数据本地存储于 SQLite，无需外部云服务
- **加密 OAuth 令牌** — 用户 OAuth 令牌**仅存储在服务器端 SQLite** 中，使用 `OAUTH_ENCRYPTION_SECRET` 通过 AES-256-GCM 加密。浏览器永远不会接收刷新令牌
- **内置 OAuth Client ID** — 源代码中嵌入的 GitHub 和 Google OAuth client ID/secret 是**公开的 OAuth 应用凭据**，而非用户密钥。根据 [Google 文档](https://developers.google.com/identity/protocols/oauth2/native-app)，安装型/桌面应用的 client secret "不被视为密钥"。这是开源应用（VS Code、Thunderbird、GitHub CLI 等）的标准做法。这些凭据仅用于标识应用本身，您的个人令牌始终单独加密
- **源代码中无个人凭据** — 所有用户特定令牌（GitHub、Google OAuth）均加密存储在本地 SQLite 数据库中，不会出现在源代码中
- **仓库中无密钥** — 全面的 `.gitignore` 配置屏蔽 `.env`、`*.pem`、`*.key`、`credentials.json` 等敏感文件
- **发布前安全检查** — 在任何公开发布前运行 `pnpm run preflight:public`，扫描工作区和 git 历史中泄露的密钥
- **默认绑定本地** — 开发服务器绑定到 `127.0.0.1`，不对外网暴露

---

## 参与贡献

欢迎贡献！请遵循以下步骤：

1. Fork 本仓库
2. 创建功能分支（`git checkout -b feature/amazing-feature`）
3. 提交您的更改（`git commit -m 'Add amazing feature'`）
4. 推送到分支（`git push origin feature/amazing-feature`）
5. 发起 Pull Request

---

## 许可证

[Apache 2.0](LICENSE) — 个人和商业用途均可免费使用。

---

<div align="center">

**以像素为笔，以热情为墨。**

*Claw-Empire — AI 代理的工作天地。*

</div>
