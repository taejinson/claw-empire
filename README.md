# CLImpire

> Command your AI agent empire from the CEO desk.

CLImpire is a **local-first AI agent office simulator** that turns CLI-based AI coding assistants (Claude Code, Codex, Gemini CLI, etc.) into a virtual company of autonomous agents. Watch them collaborate, hold meetings, and deliver tasks -- all from a pixel-art office view.

**Stack:** React 19 + Vite 7 + Tailwind CSS 4 (frontend) / Express 5 + SQLite (backend) / WebSocket (real-time)

---

## Quick Start (One-Shot Install)

### Prerequisites

| Tool | Version | How to get it |
|------|---------|---------------|
| **Node.js** | >= 22 | [nodejs.org](https://nodejs.org/) |
| **pnpm** | latest | `corepack enable` (built into Node.js) |
| **Git** | any | [git-scm.com](https://git-scm.com/) |

### Install & Run

```bash
# 1. Clone the repository
git clone https://github.com/<org>/climpire.git
cd climpire

# 2. Enable pnpm via corepack
corepack enable

# 3. Install dependencies
pnpm install

# 4. Create your local environment file
cp .env.example .env

# 5. Generate a random encryption secret (replaces the first __CHANGE_ME__)
node -e "
  const fs = require('fs');
  const crypto = require('crypto');
  const p = '.env';
  const content = fs.readFileSync(p, 'utf8');
  fs.writeFileSync(p, content.replace('__CHANGE_ME__', crypto.randomBytes(32).toString('hex')));
"

# 6. Start the development server
pnpm dev:local
```

Open your browser:

| URL | Description |
|-----|-------------|
| `http://127.0.0.1:5173` | Frontend (Vite dev server) |
| `http://127.0.0.1:8787/healthz` | API health check |

---

## Environment Variables

Copy `.env.example` to `.env`. All secrets stay local -- never commit `.env`.

| Variable | Required | Description |
|----------|----------|-------------|
| `OAUTH_ENCRYPTION_SECRET` | **Yes** | Encrypts OAuth tokens stored in SQLite. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `PORT` | No | Server port (default: `8787`) |
| `HOST` | No | Bind address (default: `127.0.0.1`) |
| `DB_PATH` | No | SQLite database path (default: `./climpire.sqlite`) |
| `LOGS_DIR` | No | Log directory (default: `./logs`) |
| `OAUTH_BASE_URL` | No | Callback base URL override |
| `OAUTH_GITHUB_CLIENT_ID` | No | GitHub OAuth App client ID |
| `OAUTH_GITHUB_CLIENT_SECRET` | No | GitHub OAuth App client secret |
| `OAUTH_GOOGLE_CLIENT_ID` | No | Google OAuth client ID |
| `OAUTH_GOOGLE_CLIENT_SECRET` | No | Google OAuth client secret |
| `GEMINI_OAUTH_CLIENT_ID` | No | Gemini-specific OAuth client ID |
| `GEMINI_OAUTH_CLIENT_SECRET` | No | Gemini-specific OAuth client secret |
| `OPENAI_API_KEY` | No | OpenAI API key |
| `GOOGLE_CLOUD_PROJECT` | No | GCP project ID |

---

## Run Modes

### Development (local-only)

```bash
pnpm dev:local          # binds to 127.0.0.1
```

### Development (network-accessible)

```bash
pnpm dev                # binds to 0.0.0.0
```

### Production build

```bash
pnpm build              # TypeScript check + Vite build
pnpm start              # run the built server
```

### Health check

```bash
curl -fsS http://127.0.0.1:8787/healthz
```

---

## Project Structure

```
climpire/
├── server/
│   └── index.ts          # Express + SQLite + WebSocket backend (single file)
├── src/
│   ├── App.tsx            # Main React app with routing
│   ├── api.ts             # Frontend API client
│   ├── i18n.ts            # Multi-language support (en/ko/ja/zh)
│   ├── components/
│   │   ├── OfficeView.tsx    # Pixel-art office with PixiJS agents
│   │   ├── Dashboard.tsx     # KPI metrics and charts
│   │   ├── TaskBoard.tsx     # Kanban-style task management
│   │   ├── ChatPanel.tsx     # CEO-to-agent communication
│   │   ├── SettingsPanel.tsx  # Company and provider settings
│   │   ├── AgentDetail.tsx   # Individual agent profiles
│   │   ├── SkillsLibrary.tsx # Agent skills management
│   │   └── TerminalPanel.tsx # Real-time CLI output viewer
│   ├── hooks/               # usePolling, useWebSocket
│   └── types/               # TypeScript type definitions
├── public/sprites/          # 12 pixel-art agent sprites
├── scripts/
│   ├── preflight-public.sh  # Pre-release security checks
│   └── generate-architecture-report.mjs
├── docs/
│   ├── DESIGN.md            # UI/UX design guide
│   └── architecture/        # Auto-generated architecture docs
├── .env.example             # Environment variable template
└── package.json
```

---

## Features

- **Office View** -- Pixel-art simulation where agents walk, work, and attend meetings
- **Task Management** -- Kanban board with drag-and-drop, subtasks, and cross-department collaboration
- **CEO Chat** -- Direct communication with team leaders and agents
- **Multi-Provider Support** -- Claude Code, Codex, Gemini CLI, OpenCode, Antigravity
- **OAuth Integration** -- GitHub and Google OAuth with encrypted token storage
- **Real-time Updates** -- WebSocket-powered live status and activity feed
- **Multi-language** -- English, Korean, Japanese, Chinese
- **Git Worktree Isolation** -- Agents work in isolated branches, merged on approval
- **Meeting System** -- Planned and ad-hoc meetings with minute generation

---

## CLI Provider Setup

CLImpire works with various CLI-based AI coding assistants. Install at least one:

| Provider | Install | Auth |
|----------|---------|------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | `npm i -g @anthropic-ai/claude-code` | `claude` (follow prompts) |
| [Codex](https://github.com/openai/codex) | `npm i -g @openai/codex` | Set `OPENAI_API_KEY` in `.env` |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `npm i -g @anthropic-ai/gemini-cli` | OAuth via Settings panel |

Configure providers and models in the **Settings** panel within the app.

---

## Public Release Preflight

Before pushing to a public GitHub repository:

```bash
pnpm run preflight:public
```

This script verifies:

- `.gitignore` has all required public-release entries
- No `.env`, credential, or key files are tracked
- No high-confidence secret patterns in tracked files or git history
- `.env.example` covers all required variables with placeholder values
- Production build succeeds

---

## License

MIT
