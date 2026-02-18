<p align="center">
  <img src="public/claw-empire.svg" width="80" alt="Claw-Empire" />
</p>

<h1 align="center">Claw-Empire</h1>

<p align="center">
  <strong>Command Your AI Agent Empire from the CEO Desk</strong><br>
  A local-first AI agent office simulator that turns <b>Claude Code</b>, <b>Codex CLI</b>, <b>Gemini CLI</b>, <b>OpenCode</b>, <b>GitHub Copilot</b>, and <b>Antigravity</b> into a virtual company of autonomous agents.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0.0-blue" alt="Version" />
  <img src="https://img.shields.io/badge/node-%3E%3D22-brightgreen" alt="Node.js 22+" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-orange" alt="License" />
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey" alt="Platform" />
  <img src="https://img.shields.io/badge/AI-Claude%20%7C%20Codex%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Copilot%20%7C%20Antigravity-purple" alt="AI Agents" />
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#ai-installation-guide">AI Install Guide</a> &middot;
  <a href="#openclaw-integration">OpenClaw</a> &middot;
  <a href="#dollar-command-logic">$ Command</a> &middot;
  <a href="#features">Features</a> &middot;
  <a href="#screenshots">Screenshots</a> &middot;
  <a href="#tech-stack">Tech Stack</a> &middot;
  <a href="#cli-provider-setup">Providers</a> &middot;
  <a href="#security">Security</a>
</p>

<p align="center">
  <b>English</b> | <a href="README_ko.md">한국어</a> | <a href="README_jp.md">日本語</a> | <a href="README_zh.md">中文</a>
</p>

<p align="center">
  <img src="Sample_Img/Office.png" alt="Office View" width="100%" />
</p>

---

## What is Claw-Empire?

Claw-Empire transforms your CLI-based AI coding assistants — **Claude Code**, **Codex CLI**, **Gemini CLI**, **OpenCode**, and more — into a fully simulated **virtual software company**. You are the CEO. Your AI agents are the employees. Watch them collaborate across departments, hold meetings, deliver tasks, and level up — all visualized through a charming pixel-art office interface.

### Why Claw-Empire?

- **One interface, many AI agents** — Manage Claude Code, Codex, Gemini CLI, and others from a single dashboard
- **Local-first & private** — All data stays on your machine. SQLite database, no cloud dependency
- **Visual & intuitive** — Pixel-art office view makes AI orchestration fun and transparent
- **Real autonomous collaboration** — Agents work in isolated git worktrees, attend meetings, and produce deliverables

---

## Install with AI

> **Just paste this to your AI coding agent (Claude Code, Codex, Gemini CLI, etc.):**
>
> ```
> Install Claw-Empire following the guide at:
> https://github.com/GreenSheep01201/claw-empire
> ```
>
> The AI will read this README and handle everything automatically.

---

## Screenshots

<table>
<tr>
<td width="50%">

**Dashboard** — Real-time KPI metrics, agent rankings, and department status at a glance

<img src="Sample_Img/Dashboard.png" alt="Dashboard" width="100%" />
</td>
<td width="50%">

**Kanban Board** — Drag-and-drop task management with department and agent filters

<img src="Sample_Img/Kanban.png" alt="Kanban Board" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**Skills Library** — Browse and assign 600+ agent skills across categories

<img src="Sample_Img/Skills.png" alt="Skills Library" width="100%" />
</td>
<td width="50%">

**Multi-Provider CLI** — Configure Claude Code, Codex, Gemini CLI, OpenCode with model selection

<img src="Sample_Img/CLI.png" alt="CLI Tools Settings" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**OAuth Integration** — Secure GitHub & Google OAuth with encrypted token storage

<img src="Sample_Img/OAuth.png" alt="OAuth Settings" width="100%" />
</td>
<td width="50%">

**Meeting Minutes** — AI-generated meeting summaries with multi-round review approval

<img src="Sample_Img/Meeting_Minutes.png" alt="Meeting Minutes" width="100%" />
</td>
</tr>
<tr>
<td width="50%">

**Messenger Integration** — Send `$` CEO directives from Telegram, Discord, Slack and receive real-time task updates via OpenClaw

<img src="Sample_Img/telegram.png" alt="Telegram Integration" width="100%" />
</td>
<td width="50%">

**Settings** — Configure company name, CEO name, default CLI provider, and language preferences

<img src="Sample_Img/Setting.png" alt="Settings" width="100%" />
</td>
</tr>
</table>

---

## Features

| Feature | Description |
|---------|-------------|
| **Pixel-Art Office** | Animated office view with agents walking, working, and attending meetings across 6 departments |
| **Kanban Task Board** | Full task lifecycle — Inbox, Planned, Collaborating, In Progress, Review, Done — with drag-and-drop |
| **CEO Chat & Directives** | Direct communication with team leaders; `$` directives support meeting choice plus project path/context routing (`project_path`, `project_context`) |
| **Multi-Provider Support** | Claude Code, Codex CLI, Gemini CLI, OpenCode, Antigravity — all from one dashboard |
| **OAuth Integration** | GitHub & Google OAuth with AES-encrypted token storage in local SQLite |
| **Real-time WebSocket** | Live status updates, activity feed, and agent state synchronization |
| **Agent Ranking & XP** | Agents earn XP for completed tasks; ranking board tracks top performers |
| **Skills Library** | 600+ categorized skills (Frontend, Backend, Design, AI, DevOps, Security, etc.) |
| **Meeting System** | Planned and ad-hoc meetings with AI-generated minutes and multi-round review |
| **Git Worktree Isolation** | Each agent works in isolated git branches, merged only on CEO approval |
| **Multi-Language UI** | English, Korean, Japanese, Chinese — auto-detected or manually set |
| **Messenger Integration** | Telegram, Discord, Slack and more — send `$` CEO directives and receive task updates via OpenClaw gateway |
| **PowerPoint Export** | Generate presentation slides from meeting minutes and reports |
| **Department Management** | Planning, Development, Design, QA/QC, DevSecOps, Operations |

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| **Frontend** | React 19 + Vite 7 + Tailwind CSS 4 + TypeScript 5.9 |
| **Pixel Art Engine** | PixiJS 8 |
| **Backend** | Express 5 + SQLite (zero-config embedded DB) |
| **Real-time** | WebSocket (ws) |
| **Validation** | Zod 4 |
| **Icons** | Lucide React |
| **Routing** | React Router 7 |
| **Export** | PptxGenJS (PowerPoint generation) |

<a id="ai-installation-guide">
## AI Installation Guide

> This section is for AI coding agents. Execute each step and run verification commands before moving to the next step.

### Step 0: Verify prerequisites

```bash
# Node.js 22+
node -v

# pnpm (or enable corepack)
pnpm -v || corepack enable

# git
git --version
```

### Step 1: Clone and run one-click setup

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

### Step 2: Verify setup output

macOS/Linux:

```bash
# Required files after setup
[ -f .env ] && [ -f scripts/setup.mjs ] && echo "setup files ok"

# AGENTS orchestration rules installed
grep -R "BEGIN claw-empire orchestration rules" ~/.openclaw/workspace/AGENTS.md AGENTS.md 2>/dev/null || true
```

Windows PowerShell:

```powershell
if ((Test-Path .\.env) -and (Test-Path .\scripts\setup.mjs)) { "setup files ok" }
$agentCandidates = @("$env:USERPROFILE\.openclaw\workspace\AGENTS.md", ".\AGENTS.md")
$agentCandidates | ForEach-Object { if (Test-Path $_) { Select-String -Path $_ -Pattern "BEGIN claw-empire orchestration rules" } }
```

### Step 3: Start and health-check

```bash
pnpm dev:local
```

In another terminal:

```bash
curl -s http://127.0.0.1:8790/healthz
```

Expected: `{"ok":true,...}`

### Step 4: Optional OpenClaw gateway verification

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

If `OPENCLAW_CONFIG` is valid, this returns available messenger sessions.

---

## Quick Start

### Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| **Node.js** | >= 22 | [nodejs.org](https://nodejs.org/) |
| **pnpm** | latest | `corepack enable` (built into Node.js) |
| **Git** | any | [git-scm.com](https://git-scm.com/) |

### One-Click Setup (Recommended)

| Platform | Command |
|----------|---------|
| **macOS / Linux** | `git clone https://github.com/GreenSheep01201/claw-empire.git && cd claw-empire && bash install.sh` |
| **Windows (PowerShell)** | `git clone https://github.com/GreenSheep01201/claw-empire.git; cd claw-empire; powershell -ExecutionPolicy Bypass -File .\install.ps1` |

If the repo is already cloned:

| Platform | Command |
|----------|---------|
| **macOS / Linux** | `bash scripts/openclaw-setup.sh` |
| **Windows (PowerShell)** | `powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1` |

### Manual Setup (Fallback)

<details>
<summary><b>macOS / Linux</b></summary>

```bash
# 1. Clone the repository
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. Enable pnpm via corepack
corepack enable

# 3. Install dependencies
pnpm install

# 4. Create your local environment file
cp .env.example .env

# 5. Generate a random encryption secret
node -e "
  const fs = require('fs');
  const crypto = require('crypto');
  const p = '.env';
  const content = fs.readFileSync(p, 'utf8');
  fs.writeFileSync(p, content.replace('__CHANGE_ME__', crypto.randomBytes(32).toString('hex')));
"

# 6. Setup AGENTS.md orchestration rules (teaches your AI agent to be a Claw-Empire project manager)
pnpm setup -- --port 8790

# 7. Start the development server
pnpm dev:local
```

</details>

<details>
<summary><b>Windows (PowerShell)</b></summary>

```powershell
# 1. Clone the repository
git clone https://github.com/GreenSheep01201/claw-empire.git
cd claw-empire

# 2. Enable pnpm via corepack
corepack enable

# 3. Install dependencies
pnpm install

# 4. Create your local environment file
Copy-Item .env.example .env

# 5. Generate a random encryption secret
node -e "const fs=require('fs');const crypto=require('crypto');const p='.env';const c=fs.readFileSync(p,'utf8');fs.writeFileSync(p,c.replace('__CHANGE_ME__',crypto.randomBytes(32).toString('hex')))"

# 6. Setup AGENTS.md orchestration rules (teaches your AI agent to be a Claw-Empire project manager)
pnpm setup -- --port 8790

# 7. Start the development server
pnpm dev:local
```

</details>

Open your browser:

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:8800` | Frontend (Vite dev server) |
| `http://127.0.0.1:8790/healthz` | API health check |

### AGENTS.md Setup

The `pnpm setup` command injects **CEO directive orchestration rules** into your AI agent's `AGENTS.md` file. This teaches your AI coding agent (Claude Code, Codex, etc.) how to:

- Interpret `$` prefix **CEO directives** for priority task delegation
- Call the Claw-Empire REST API to create tasks, assign agents, and report status
- Work within isolated git worktrees for safe parallel development

```bash
# Default: auto-detects AGENTS.md location
pnpm setup

# Custom path
pnpm setup -- --agents-path /path/to/your/AGENTS.md

# Custom port
pnpm setup -- --port 8790
```

<a id="openclaw-integration"></a>
### OpenClaw Integration Setup (Telegram/Discord/Slack)

`install.sh` / `install.ps1` (or `scripts/openclaw-setup.*`) will auto-detect and write `OPENCLAW_CONFIG` when possible.

Default config paths:

| OS | Path |
|----|------|
| **macOS / Linux** | `~/.openclaw/openclaw.json` |
| **Windows** | `%USERPROFILE%\.openclaw\openclaw.json` |

Manual commands:

```bash
# macOS / Linux
bash scripts/openclaw-setup.sh --openclaw-config ~/.openclaw/openclaw.json
```

```powershell
# Windows PowerShell
powershell -ExecutionPolicy Bypass -File .\scripts\openclaw-setup.ps1 -OpenClawConfig "$env:USERPROFILE\.openclaw\openclaw.json"
```

Verify messenger sessions:

```bash
curl -s http://127.0.0.1:8790/api/gateway/targets
```

<a id="dollar-command-logic"></a>
### `$` Command -> OpenClaw Chat Delegation Logic

When a chat message starts with `$`, Claw-Empire handles it as a CEO directive:

1. Orchestrator asks whether to hold a team-leader meeting first.
2. Orchestrator asks for project path/context (`project_path` or `project_context`).
3. It sends the directive to `POST /api/inbox` with the `$` prefix.
4. If meeting is skipped, include `"skipPlannedMeeting": true`.
5. Server stores it as `directive`, broadcasts company-wide, then delegates to Planning (and mentioned departments when included).

With meeting:

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -d '{"source":"telegram","author":"ceo","text":"$Release v0.2 by Friday with QA sign-off","project_path":"/Users/me/Projects/climpire"}'
```

Without meeting:

```bash
curl -X POST http://127.0.0.1:8790/api/inbox \
  -H "content-type: application/json" \
  -d '{"source":"telegram","author":"ceo","text":"$Hotfix production login bug immediately","skipPlannedMeeting":true,"project_context":"existing climpire project"}'
```

---

## Environment Variables

Copy `.env.example` to `.env`. All secrets stay local — never commit `.env`.

| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_ENCRYPTION_SECRET` | **Yes** | Encrypts OAuth tokens in SQLite |
| `PORT` | No | Server port (default: `8790`) |
| `HOST` | No | Bind address (default: `127.0.0.1`) |
| `DB_PATH` | No | SQLite database path (default: `./claw-empire.sqlite`) |
| `LOGS_DIR` | No | Log directory (default: `./logs`) |
| `OAUTH_GITHUB_CLIENT_ID` | No | GitHub OAuth App client ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | No | GitHub OAuth App client secret |
| `OAUTH_GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `OAUTH_GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `OPENAI_API_KEY` | No | OpenAI API key (for Codex) |

---

## Run Modes

```bash
# Development (local-only, recommended)
pnpm dev:local          # binds to 127.0.0.1

# Development (network-accessible)
pnpm dev                # binds to 0.0.0.0

# Production build
pnpm build              # TypeScript check + Vite build
pnpm start              # run the built server

# Health check
curl -fsS http://127.0.0.1:8790/healthz
```

---

## CLI Provider Setup

Claw-Empire works with multiple CLI-based AI coding assistants. Install at least one:

| Provider | Install | Auth |
|----------|---------|------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm i -g @anthropic-ai/claude-code` | `claude` (follow prompts) |
| [Codex CLI](https://github.com/openai/codex) | `npm i -g @openai/codex` | Set `OPENAI_API_KEY` in `.env` |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `npm i -g @google/gemini-cli` | OAuth via Settings panel |
| [OpenCode](https://github.com/opencode-ai/opencode) | `npm i -g opencode` | Provider-specific |

Configure providers and models in the **Settings > CLI Tools** panel within the app.

---

## Project Structure

```
claw-empire/
├── server/
│   └── index.ts              # Express 5 + SQLite + WebSocket backend
├── src/
│   ├── App.tsx                # Main React app with routing
│   ├── api.ts                 # Frontend API client
│   ├── i18n.ts                # Multi-language support (en/ko/ja/zh)
│   ├── components/
│   │   ├── OfficeView.tsx     # Pixel-art office with PixiJS agents
│   │   ├── Dashboard.tsx      # KPI metrics and charts
│   │   ├── TaskBoard.tsx      # Kanban-style task management
│   │   ├── ChatPanel.tsx      # CEO-to-agent communication
│   │   ├── SettingsPanel.tsx  # Company and provider settings
│   │   ├── SkillsLibrary.tsx  # Agent skills management
│   │   └── TerminalPanel.tsx  # Real-time CLI output viewer
│   ├── hooks/                 # usePolling, useWebSocket
│   └── types/                 # TypeScript type definitions
├── public/sprites/            # 12 pixel-art agent sprites
├── scripts/
│   ├── openclaw-setup.sh      # One-click setup (macOS/Linux)
│   ├── openclaw-setup.ps1     # One-click setup (Windows PowerShell)
│   ├── preflight-public.sh    # Pre-release security checks
│   └── generate-architecture-report.mjs
├── install.sh                 # Wrapper for scripts/openclaw-setup.sh
├── install.ps1                # Wrapper for scripts/openclaw-setup.ps1
├── docs/                      # Design & architecture docs
├── .env.example               # Environment variable template
└── package.json
```

---

## Security

Claw-Empire is designed with security in mind:

- **Local-first architecture** — All data stored locally in SQLite; no external cloud services required
- **Encrypted OAuth tokens** — AES encryption with your `OAUTH_ENCRYPTION_SECRET`
- **No secrets in repo** — Comprehensive `.gitignore` blocks `.env`, `*.pem`, `*.key`, `credentials.json`, etc.
- **Preflight security checks** — Run `pnpm run preflight:public` before any public release to scan for leaked secrets in both working tree and git history
- **Localhost by default** — Development server binds to `127.0.0.1`, not exposed to network

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

[Apache 2.0](LICENSE) — Free for personal and commercial use.

---

<div align="center">

**Built with pixels and passion.**

*Claw-Empire — Where AI agents come to work.*

</div>
