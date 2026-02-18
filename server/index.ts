import express from "express";
import cors from "cors";
import path from "path";
import fs from "node:fs";
import os from "node:os";
import { randomUUID, createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { spawn, execFile, execFileSync, type ChildProcess } from "node:child_process";
import { DatabaseSync } from "node:sqlite";
import { WebSocketServer, WebSocket } from "ws";
import { fileURLToPath } from "node:url";
import type { IncomingMessage } from "node:http";

// ---------------------------------------------------------------------------
// .env loader (no dotenv dependency)
// ---------------------------------------------------------------------------
const __server_dirname = path.dirname(fileURLToPath(import.meta.url));
const envFilePath = path.resolve(__server_dirname, "..", ".env");
try {
  if (fs.existsSync(envFilePath)) {
    const envContent = fs.readFileSync(envFilePath, "utf8");
    for (const line of envContent.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const value = trimmed.slice(eqIdx + 1).trim();
      if (!(key in process.env)) {
        process.env[key] = value;
      }
    }
  }
} catch { /* ignore .env read errors */ }

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
const PKG_VERSION: string = (() => {
  try {
    return JSON.parse(
      fs.readFileSync(path.resolve(__server_dirname, "..", "package.json"), "utf8"),
    ).version ?? "1.0.0";
  } catch {
    return "1.0.0";
  }
})();

const PORT = Number(process.env.PORT ?? 8787);
const HOST = process.env.HOST ?? "127.0.0.1";

// ---------------------------------------------------------------------------
// Express setup
// ---------------------------------------------------------------------------
const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ---------------------------------------------------------------------------
// OAuth encryption helpers
// ---------------------------------------------------------------------------
const OAUTH_ENCRYPTION_SECRET =
  process.env.OAUTH_ENCRYPTION_SECRET || process.env.SESSION_SECRET || "";

function oauthEncryptionKey(): Buffer {
  if (!OAUTH_ENCRYPTION_SECRET) {
    throw new Error("Missing OAUTH_ENCRYPTION_SECRET");
  }
  return createHash("sha256").update(OAUTH_ENCRYPTION_SECRET, "utf8").digest();
}

function encryptSecret(plaintext: string): string {
  const key = oauthEncryptionKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", iv.toString("base64"), tag.toString("base64"), enc.toString("base64")].join(":");
}

function decryptSecret(payload: string): string {
  const [ver, ivB64, tagB64, ctB64] = payload.split(":");
  if (ver !== "v1" || !ivB64 || !tagB64 || !ctB64) throw new Error("invalid_encrypted_payload");
  const key = oauthEncryptionKey();
  const iv = Buffer.from(ivB64, "base64");
  const tag = Buffer.from(tagB64, "base64");
  const ct = Buffer.from(ctB64, "base64");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const dec = Buffer.concat([decipher.update(ct), decipher.final()]);
  return dec.toString("utf8");
}

// ---------------------------------------------------------------------------
// OAuth web-auth constants & PKCE helpers
// ---------------------------------------------------------------------------
const OAUTH_BASE_URL = process.env.OAUTH_BASE_URL || `http://${HOST}:${PORT}`;

// Built-in OAuth client credentials (same as OpenClaw/Claw-Kanban built-in values)
const BUILTIN_GITHUB_CLIENT_ID = "Iv1.b507a08c87ecfe98";
const BUILTIN_GOOGLE_CLIENT_ID = Buffer.from(
  "MTA3MTAwNjA2MDU5MS10bWhzc2luMmgyMWxjcmUyMzV2dG9sb2poNGc0MDNlcC5hcHBzLmdvb2dsZXVzZXJjb250ZW50LmNvbQ==",
  "base64",
).toString();
const BUILTIN_GOOGLE_CLIENT_SECRET = Buffer.from(
  "R09DU1BYLUs1OEZXUjQ4NkxkTEoxbUxCOHNYQzR6NnFEQWY=",
  "base64",
).toString();

const OAUTH_STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function pkceVerifier(): string {
  return b64url(randomBytes(32));
}

async function pkceChallengeS256(verifier: string): Promise<string> {
  return b64url(createHash("sha256").update(verifier, "ascii").digest());
}

// ---------------------------------------------------------------------------
// OAuth helper functions
// ---------------------------------------------------------------------------
function sanitizeOAuthRedirect(raw: string | undefined): string {
  if (!raw) return "/";
  try {
    const u = new URL(raw);
    if (u.hostname === "localhost" || u.hostname === "127.0.0.1") return raw;
  } catch { /* not absolute URL — treat as path */ }
  if (raw.startsWith("/")) return raw;
  return "/";
}

function appendOAuthQuery(url: string, key: string, val: string): string {
  const u = new URL(url);
  u.searchParams.set(key, val);
  return u.toString();
}

// ---------------------------------------------------------------------------
// Production static file serving
// ---------------------------------------------------------------------------
const distDir = path.resolve(__server_dirname, "..", "dist");
const isProduction = !process.env.VITE_DEV && fs.existsSync(path.join(distDir, "index.html"));

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const dbPath = process.env.DB_PATH ?? path.join(process.cwd(), "climpire.sqlite");
const db = new DatabaseSync(dbPath);
db.exec("PRAGMA journal_mode = WAL");
db.exec("PRAGMA busy_timeout = 3000");
db.exec("PRAGMA foreign_keys = ON");

const logsDir = process.env.LOGS_DIR ?? path.join(process.cwd(), "logs");
try {
  fs.mkdirSync(logsDir, { recursive: true });
} catch { /* ignore */ }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function nowMs(): number {
  return Date.now();
}

function firstQueryValue(value: unknown): string | undefined {
  if (typeof value === "string") return value;
  if (Array.isArray(value)) {
    const first = value.find((item) => typeof item === "string");
    return typeof first === "string" ? first : undefined;
  }
  return undefined;
}

// ---------------------------------------------------------------------------
// Schema creation
// ---------------------------------------------------------------------------
db.exec(`
CREATE TABLE IF NOT EXISTS departments (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_ko TEXT NOT NULL,
  icon TEXT NOT NULL,
  color TEXT NOT NULL,
  description TEXT,
  sort_order INTEGER NOT NULL DEFAULT 99,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  name_ko TEXT NOT NULL,
  department_id TEXT REFERENCES departments(id),
  role TEXT NOT NULL CHECK(role IN ('team_leader','senior','junior','intern')),
  cli_provider TEXT CHECK(cli_provider IN ('claude','codex','gemini','opencode','copilot','antigravity')),
  avatar_emoji TEXT NOT NULL DEFAULT '🤖',
  personality TEXT,
  status TEXT NOT NULL DEFAULT 'idle' CHECK(status IN ('idle','working','break','offline')),
  current_task_id TEXT,
  stats_tasks_done INTEGER DEFAULT 0,
  stats_xp INTEGER DEFAULT 0,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS tasks (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT,
  department_id TEXT REFERENCES departments(id),
  assigned_agent_id TEXT REFERENCES agents(id),
  status TEXT NOT NULL DEFAULT 'inbox' CHECK(status IN ('inbox','planned','in_progress','review','done','cancelled')),
  priority INTEGER DEFAULT 0,
  task_type TEXT DEFAULT 'general' CHECK(task_type IN ('general','development','design','analysis','presentation','documentation')),
  project_path TEXT,
  result TEXT,
  started_at INTEGER,
  completed_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()*1000),
  updated_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  sender_type TEXT NOT NULL CHECK(sender_type IN ('ceo','agent','system')),
  sender_id TEXT,
  receiver_type TEXT NOT NULL CHECK(receiver_type IN ('agent','department','all')),
  receiver_id TEXT,
  content TEXT NOT NULL,
  message_type TEXT DEFAULT 'chat' CHECK(message_type IN ('chat','task_assign','announcement','report','status_update')),
  task_id TEXT REFERENCES tasks(id),
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS task_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task_id TEXT REFERENCES tasks(id),
  kind TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS meeting_minutes (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  meeting_type TEXT NOT NULL CHECK(meeting_type IN ('planned','review')),
  round INTEGER NOT NULL,
  title TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'in_progress' CHECK(status IN ('in_progress','completed','revision_requested','failed')),
  started_at INTEGER NOT NULL,
  completed_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS meeting_minute_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  meeting_id TEXT NOT NULL REFERENCES meeting_minutes(id) ON DELETE CASCADE,
  seq INTEGER NOT NULL,
  speaker_agent_id TEXT REFERENCES agents(id),
  speaker_name TEXT NOT NULL,
  department_name TEXT,
  role_label TEXT,
  message_type TEXT NOT NULL DEFAULT 'chat',
  content TEXT NOT NULL,
  created_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_credentials (
  provider TEXT PRIMARY KEY,
  source TEXT,
  encrypted_data TEXT NOT NULL,
  email TEXT,
  scope TEXT,
  expires_at INTEGER,
  created_at INTEGER DEFAULT (unixepoch()*1000),
  updated_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS oauth_states (
  id TEXT PRIMARY KEY,
  provider TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  verifier_enc TEXT NOT NULL,
  redirect_to TEXT
);

CREATE TABLE IF NOT EXISTS cli_usage_cache (
  provider TEXT PRIMARY KEY,
  data_json TEXT NOT NULL,
  updated_at INTEGER DEFAULT (unixepoch()*1000)
);

CREATE TABLE IF NOT EXISTS subtasks (
  id TEXT PRIMARY KEY,
  task_id TEXT NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  description TEXT,
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK(status IN ('pending','in_progress','done','blocked')),
  assigned_agent_id TEXT REFERENCES agents(id),
  blocked_reason TEXT,
  cli_tool_use_id TEXT,
  created_at INTEGER DEFAULT (unixepoch()*1000),
  completed_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_subtasks_task ON subtasks(task_id);
CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(assigned_agent_id);
CREATE INDEX IF NOT EXISTS idx_tasks_dept ON tasks(department_id);
CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_type, receiver_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_meeting_minutes_task ON meeting_minutes(task_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_meeting_minute_entries_meeting ON meeting_minute_entries(meeting_id, seq ASC);
`);

// Add columns to oauth_credentials for web-oauth tokens (safe to run repeatedly)
try { db.exec("ALTER TABLE oauth_credentials ADD COLUMN access_token_enc TEXT"); } catch { /* already exists */ }
try { db.exec("ALTER TABLE oauth_credentials ADD COLUMN refresh_token_enc TEXT"); } catch { /* already exists */ }

// Subtask cross-department delegation columns
try { db.exec("ALTER TABLE subtasks ADD COLUMN target_department_id TEXT"); } catch { /* already exists */ }
try { db.exec("ALTER TABLE subtasks ADD COLUMN delegated_task_id TEXT"); } catch { /* already exists */ }

// ---------------------------------------------------------------------------
// Seed default data
// ---------------------------------------------------------------------------
const deptCount = (db.prepare("SELECT COUNT(*) as cnt FROM departments").get() as { cnt: number }).cnt;

if (deptCount === 0) {
  const insertDept = db.prepare(
    "INSERT INTO departments (id, name, name_ko, icon, color, sort_order) VALUES (?, ?, ?, ?, ?, ?)"
  );
  // Workflow order: 기획 → 개발 → 디자인 → QA → 인프라보안 → 운영
  insertDept.run("planning",  "Planning",    "기획팀",     "📊", "#f59e0b", 1);
  insertDept.run("dev",       "Development", "개발팀",     "💻", "#3b82f6", 2);
  insertDept.run("design",    "Design",      "디자인팀",   "🎨", "#8b5cf6", 3);
  insertDept.run("qa",        "QA/QC",       "품질관리팀", "🔍", "#ef4444", 4);
  insertDept.run("devsecops", "DevSecOps",   "인프라보안팀","🛡️", "#f97316", 5);
  insertDept.run("operations","Operations",  "운영팀",     "⚙️", "#10b981", 6);
  console.log("[CLImpire] Seeded default departments");
}

const agentCount = (db.prepare("SELECT COUNT(*) as cnt FROM agents").get() as { cnt: number }).cnt;

if (agentCount === 0) {
  const insertAgent = db.prepare(
    `INSERT INTO agents (id, name, name_ko, department_id, role, cli_provider, avatar_emoji, personality)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  // Development (3)
  insertAgent.run(randomUUID(), "Aria",  "아리아", "dev",        "team_leader", "claude",   "👩‍💻", "꼼꼼한 시니어 개발자");
  insertAgent.run(randomUUID(), "Bolt",  "볼트",   "dev",        "senior",      "codex",    "⚡",   "빠른 코딩 전문가");
  insertAgent.run(randomUUID(), "Nova",  "노바",   "dev",        "junior",      "copilot",  "🌟",   "창의적인 주니어");
  // Design (2)
  insertAgent.run(randomUUID(), "Pixel", "픽셀",   "design",     "team_leader", "claude",   "🎨",   "디자인 리더");
  insertAgent.run(randomUUID(), "Luna",  "루나",   "design",     "junior",      "gemini",   "🌙",   "감성적인 UI 디자이너");
  // Planning (2)
  insertAgent.run(randomUUID(), "Sage",  "세이지", "planning",   "team_leader", "codex",    "🧠",   "전략 분석가");
  insertAgent.run(randomUUID(), "Clio",  "클리오", "planning",   "senior",      "claude",   "📝",   "데이터 기반 기획자");
  // Operations (2)
  insertAgent.run(randomUUID(), "Atlas", "아틀라스","operations", "team_leader", "claude",   "🗺️",  "운영의 달인");
  insertAgent.run(randomUUID(), "Turbo", "터보",   "operations", "senior",      "codex",    "🚀",   "자동화 전문가");
  // QA/QC (2)
  insertAgent.run(randomUUID(), "Hawk",  "호크",   "qa",         "team_leader", "claude",   "🦅",   "날카로운 품질 감시자");
  insertAgent.run(randomUUID(), "Lint",  "린트",   "qa",         "senior",      "codex",    "🔬",   "꼼꼼한 테스트 전문가");
  // DevSecOps (2)
  insertAgent.run(randomUUID(), "Vault", "볼트S",  "devsecops",  "team_leader", "claude",   "🛡️",  "보안 아키텍트");
  insertAgent.run(randomUUID(), "Pipe",  "파이프", "devsecops",  "senior",      "codex",    "🔧",   "CI/CD 파이프라인 전문가");
  console.log("[CLImpire] Seeded default agents");
}

// Seed default settings if none exist
{
  const settingsCount = (db.prepare("SELECT COUNT(*) as c FROM settings").get() as { c: number }).c;
  if (settingsCount === 0) {
    const insertSetting = db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)");
    insertSetting.run("companyName", "CLImpire Corp.");
    insertSetting.run("ceoName", "CEO");
    insertSetting.run("autoAssign", "true");
    insertSetting.run("language", "en");
    console.log("[CLImpire] Seeded default settings");
  }

  const hasLanguageSetting = db
    .prepare("SELECT 1 FROM settings WHERE key = 'language' LIMIT 1")
    .get() as { 1: number } | undefined;
  if (!hasLanguageSetting) {
    db.prepare("INSERT INTO settings (key, value) VALUES (?, ?)")
      .run("language", "en");
  }
}

// Migrate: add sort_order column & set correct ordering for existing DBs
{
  try { db.exec("ALTER TABLE departments ADD COLUMN sort_order INTEGER NOT NULL DEFAULT 99"); } catch { /* already exists */ }

  const DEPT_ORDER: Record<string, number> = { planning: 1, dev: 2, design: 3, qa: 4, devsecops: 5, operations: 6 };
  const updateOrder = db.prepare("UPDATE departments SET sort_order = ? WHERE id = ?");
  for (const [id, order] of Object.entries(DEPT_ORDER)) {
    updateOrder.run(order, id);
  }

  const insertDeptIfMissing = db.prepare(
    "INSERT OR IGNORE INTO departments (id, name, name_ko, icon, color, sort_order) VALUES (?, ?, ?, ?, ?, ?)"
  );
  insertDeptIfMissing.run("qa", "QA/QC", "품질관리팀", "🔍", "#ef4444", 4);
  insertDeptIfMissing.run("devsecops", "DevSecOps", "인프라보안팀", "🛡️", "#f97316", 5);

  const insertAgentIfMissing = db.prepare(
    `INSERT OR IGNORE INTO agents (id, name, name_ko, department_id, role, cli_provider, avatar_emoji, personality)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );

  // Check which agents exist by name to avoid duplicates
  const existingNames = new Set(
    (db.prepare("SELECT name FROM agents").all() as { name: string }[]).map((r) => r.name)
  );

  const newAgents: [string, string, string, string, string, string, string][] = [
    // [name, name_ko, dept, role, provider, emoji, personality]
    ["Luna",  "루나",   "design",     "junior",      "gemini",   "🌙",  "감성적인 UI 디자이너"],
    ["Clio",  "클리오", "planning",   "senior",      "claude",   "📝",  "데이터 기반 기획자"],
    ["Turbo", "터보",   "operations", "senior",      "codex",    "🚀",  "자동화 전문가"],
    ["Hawk",  "호크",   "qa",         "team_leader", "claude",   "🦅",  "날카로운 품질 감시자"],
    ["Lint",  "린트",   "qa",         "senior",      "opencode", "🔬",  "꼼꼼한 테스트 전문가"],
    ["Vault", "볼트S",  "devsecops",  "team_leader", "claude",   "🛡️", "보안 아키텍트"],
    ["Pipe",  "파이프", "devsecops",  "senior",      "codex",    "🔧",  "CI/CD 파이프라인 전문가"],
  ];

  let added = 0;
  for (const [name, nameKo, dept, role, provider, emoji, personality] of newAgents) {
    if (!existingNames.has(name)) {
      insertAgentIfMissing.run(randomUUID(), name, nameKo, dept, role, provider, emoji, personality);
      added++;
    }
  }
  if (added > 0) console.log(`[CLImpire] Added ${added} new agents`);
}

// ---------------------------------------------------------------------------
// Track active child processes
// ---------------------------------------------------------------------------
const activeProcesses = new Map<string, ChildProcess>();
const stopRequestedTasks = new Set<string>();

// ---------------------------------------------------------------------------
// Git Worktree support — agent isolation per task
// ---------------------------------------------------------------------------
const taskWorktrees = new Map<string, {
  worktreePath: string;
  branchName: string;
  projectPath: string; // original project path
}>();

function isGitRepo(dir: string): boolean {
  try {
    execFileSync("git", ["rev-parse", "--is-inside-work-tree"], { cwd: dir, stdio: "pipe", timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

function createWorktree(projectPath: string, taskId: string, agentName: string): string | null {
  if (!isGitRepo(projectPath)) return null;

  const shortId = taskId.slice(0, 8);
  const branchName = `climpire/${shortId}`;
  const worktreeBase = path.join(projectPath, ".climpire-worktrees");
  const worktreePath = path.join(worktreeBase, shortId);

  try {
    fs.mkdirSync(worktreeBase, { recursive: true });

    // Get current branch/HEAD as base
    const base = execFileSync("git", ["rev-parse", "HEAD"], { cwd: projectPath, stdio: "pipe", timeout: 5000 }).toString().trim();

    // Create worktree with new branch
    execFileSync("git", ["worktree", "add", worktreePath, "-b", branchName, base], {
      cwd: projectPath,
      stdio: "pipe",
      timeout: 15000,
    });

    taskWorktrees.set(taskId, { worktreePath, branchName, projectPath });
    console.log(`[CLImpire] Created worktree for task ${shortId}: ${worktreePath} (branch: ${branchName}, agent: ${agentName})`);
    return worktreePath;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[CLImpire] Failed to create worktree for task ${shortId}: ${msg}`);
    return null;
  }
}

function mergeWorktree(projectPath: string, taskId: string): { success: boolean; message: string; conflicts?: string[] } {
  const info = taskWorktrees.get(taskId);
  if (!info) return { success: false, message: "No worktree found for this task" };

  try {
    // Get current branch name in the original repo
    const currentBranch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: projectPath, stdio: "pipe", timeout: 5000,
    }).toString().trim();

    // Check if there are actual changes to merge
    try {
      const diffCheck = execFileSync("git", ["diff", `${currentBranch}...${info.branchName}`, "--stat"], {
        cwd: projectPath, stdio: "pipe", timeout: 10000,
      }).toString().trim();
      if (!diffCheck) {
        return { success: true, message: "변경사항 없음 — 병합 불필요" };
      }
    } catch { /* proceed with merge attempt anyway */ }

    // Attempt merge with no-ff
    const mergeMsg = `Merge climpire task ${taskId.slice(0, 8)} (branch ${info.branchName})`;
    execFileSync("git", ["merge", info.branchName, "--no-ff", "-m", mergeMsg], {
      cwd: projectPath, stdio: "pipe", timeout: 30000,
    });

    return { success: true, message: `병합 완료: ${info.branchName} → ${currentBranch}` };
  } catch (err: unknown) {
    // Detect conflicts by checking git status instead of parsing error messages
    try {
      const unmerged = execFileSync("git", ["diff", "--name-only", "--diff-filter=U"], {
        cwd: projectPath, stdio: "pipe", timeout: 5000,
      }).toString().trim();
      const conflicts = unmerged ? unmerged.split("\n").filter(Boolean) : [];

      if (conflicts.length > 0) {
        // Abort the failed merge
        try { execFileSync("git", ["merge", "--abort"], { cwd: projectPath, stdio: "pipe", timeout: 5000 }); } catch { /* ignore */ }

        return {
          success: false,
          message: `병합 충돌 발생: ${conflicts.length}개 파일에서 충돌이 있습니다. 수동 해결이 필요합니다.`,
          conflicts,
        };
      }
    } catch { /* ignore conflict detection failure */ }

    // Abort any partial merge
    try { execFileSync("git", ["merge", "--abort"], { cwd: projectPath, stdio: "pipe", timeout: 5000 }); } catch { /* ignore */ }

    const msg = err instanceof Error ? err.message : String(err);
    return { success: false, message: `병합 실패: ${msg}` };
  }
}

function cleanupWorktree(projectPath: string, taskId: string): void {
  const info = taskWorktrees.get(taskId);
  if (!info) return;

  const shortId = taskId.slice(0, 8);

  try {
    // Remove worktree
    execFileSync("git", ["worktree", "remove", info.worktreePath, "--force"], {
      cwd: projectPath, stdio: "pipe", timeout: 10000,
    });
  } catch {
    // If worktree remove fails, try manual cleanup
    console.warn(`[CLImpire] git worktree remove failed for ${shortId}, falling back to manual cleanup`);
    try {
      if (fs.existsSync(info.worktreePath)) {
        fs.rmSync(info.worktreePath, { recursive: true, force: true });
      }
      execFileSync("git", ["worktree", "prune"], { cwd: projectPath, stdio: "pipe", timeout: 5000 });
    } catch { /* ignore */ }
  }

  try {
    // Delete branch
    execFileSync("git", ["branch", "-D", info.branchName], {
      cwd: projectPath, stdio: "pipe", timeout: 5000,
    });
  } catch {
    console.warn(`[CLImpire] Failed to delete branch ${info.branchName} — may need manual cleanup`);
  }

  taskWorktrees.delete(taskId);
  console.log(`[CLImpire] Cleaned up worktree for task ${shortId}`);
}

function rollbackTaskWorktree(taskId: string, reason: string): boolean {
  const info = taskWorktrees.get(taskId);
  if (!info) return false;

  const diffSummary = getWorktreeDiffSummary(info.projectPath, taskId);
  if (diffSummary && diffSummary !== "변경사항 없음" && diffSummary !== "diff 조회 실패") {
    appendTaskLog(taskId, "system", `Rollback(${reason}) diff summary:\n${diffSummary}`);
  }

  cleanupWorktree(info.projectPath, taskId);
  appendTaskLog(taskId, "system", `Worktree rollback completed (${reason})`);
  return true;
}

function getWorktreeDiffSummary(projectPath: string, taskId: string): string {
  const info = taskWorktrees.get(taskId);
  if (!info) return "";

  try {
    // Get current branch in original repo
    const currentBranch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: projectPath, stdio: "pipe", timeout: 5000,
    }).toString().trim();

    const stat = execFileSync("git", ["diff", `${currentBranch}...${info.branchName}`, "--stat"], {
      cwd: projectPath, stdio: "pipe", timeout: 10000,
    }).toString().trim();

    return stat || "변경사항 없음";
  } catch {
    return "diff 조회 실패";
  }
}

// ---------------------------------------------------------------------------
// WebSocket setup
// ---------------------------------------------------------------------------
const wsClients = new Set<WebSocket>();

function broadcast(type: string, payload: unknown): void {
  const message = JSON.stringify({ type, payload, ts: nowMs() });
  for (const ws of wsClients) {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  }
}

// ---------------------------------------------------------------------------
// CLI spawn helpers (ported from claw-kanban)
// ---------------------------------------------------------------------------
function buildAgentArgs(provider: string, model?: string, reasoningLevel?: string): string[] {
  switch (provider) {
    case "codex": {
      const args = ["codex", "--enable", "multi_agent"];
      if (model) args.push("-m", model);
      if (reasoningLevel) args.push("-c", `model_reasoning_effort="${reasoningLevel}"`);
      args.push("--yolo", "exec", "--json");
      return args;
    }
    case "claude": {
      const args = [
        "claude",
        "--dangerously-skip-permissions",
        "--print",
        "--verbose",
        "--output-format=stream-json",
        "--include-partial-messages",
      ];
      if (model) args.push("--model", model);
      return args;
    }
    case "gemini": {
      const args = ["gemini"];
      if (model) args.push("-m", model);
      args.push("--yolo", "--output-format=stream-json");
      return args;
    }
    case "opencode": {
      const args = ["opencode", "run"];
      if (model) args.push("-m", model);
      args.push("--format", "json");
      return args;
    }
    case "copilot":
    case "antigravity":
      throw new Error(`${provider} uses HTTP agent (not CLI spawn)`);
    default:
      throw new Error(`unsupported CLI provider: ${provider}`);
  }
}

/** Fetch recent conversation context for an agent to include in spawn prompt */
function getRecentConversationContext(agentId: string, limit = 10): string {
  const msgs = db.prepare(`
    SELECT sender_type, sender_id, content, message_type, created_at
    FROM messages
    WHERE (
      (sender_type = 'ceo' AND receiver_type = 'agent' AND receiver_id = ?)
      OR (sender_type = 'agent' AND sender_id = ?)
      OR (receiver_type = 'all')
    )
    ORDER BY created_at DESC
    LIMIT ?
  `).all(agentId, agentId, limit) as Array<{
    sender_type: string;
    sender_id: string | null;
    content: string;
    message_type: string;
    created_at: number;
  }>;

  if (msgs.length === 0) return "";

  const lines = msgs.reverse().map((m) => {
    const role = m.sender_type === "ceo" ? "CEO" : "Agent";
    const type = m.message_type !== "chat" ? ` [${m.message_type}]` : "";
    return `${role}${type}: ${m.content}`;
  });

  return `\n\n--- Recent conversation context ---\n${lines.join("\n")}\n--- End context ---`;
}

interface MeetingTranscriptEntry {
  speaker: string;
  department: string;
  role: string;
  content: string;
}

interface OneShotRunOptions {
  projectPath?: string;
  timeoutMs?: number;
  streamTaskId?: string | null;
}

interface OneShotRunResult {
  text: string;
  error?: string;
}

interface MeetingPromptOptions {
  meetingType: "planned" | "review";
  round: number;
  taskTitle: string;
  taskDescription: string | null;
  transcript: MeetingTranscriptEntry[];
  turnObjective: string;
  stanceHint?: string;
  lang: string;
}

function sleepMs(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function randomDelay(minMs: number, maxMs: number): number {
  return Math.floor(minMs + Math.random() * Math.max(0, maxMs - minMs));
}

function getAgentDisplayName(agent: AgentRow, lang: string): string {
  return lang === "ko" ? (agent.name_ko || agent.name) : agent.name;
}

function localeInstruction(lang: string): string {
  switch (lang) {
    case "ja":
      return "Respond in Japanese.";
    case "zh":
      return "Respond in Chinese.";
    case "en":
      return "Respond in English.";
    case "ko":
    default:
      return "Respond in Korean.";
  }
}

function normalizeConversationReply(raw: string, maxChars = 420): string {
  if (!raw.trim()) return "";
  const parsed = prettyStreamJson(raw);
  let text = parsed.trim() ? parsed : raw;
  text = text
    .replace(/^\[(init|usage|mcp|thread)\][^\n]*$/gim, "")
    .replace(/^\[reasoning\]\s*/gim, "")
    .replace(/\[(tool|result|output|spawn_agent|agent_done|one-shot-error)[^\]]*\]/gi, " ")
    .replace(/^\[(copilot|antigravity)\][^\n]*$/gim, "")
    .replace(/\b(Crafting|Formulating|Composing|Thinking|Analyzing)\b[^.!?。！？]{0,80}\b(message|reply)\s*/gi, "")
    .replace(/\b(I need to|Let me|I'll|I will|First, I'?ll)\b[^.!?。！？]{0,140}\b(analy[sz]e|examin|inspect|check|review|look at)\b[^.!?。！？]*[.!?。！？]?/gi, " ")
    .replace(/\b(current codebase|relevant files|quickly examine|let me quickly|analyze the current project)\b[^.!?。！？]*[.!?。！？]?/gi, " ")
    .replace(/```[\s\S]*?```/g, " ")
    .replace(/`[^`]*`/g, " ")
    .replace(/(?:^|\s)(find|ls|rg|grep|cat|head|tail|sed|awk|npm|pnpm|yarn|node|git|cd|pwd)\s+[^\n]+/gi, " ")
    .replace(/---+/g, " ")
    .replace(/[\r\n]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return "";

  const sentenceParts = text
    .split(/(?<=[.!?。！？])\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
  const uniqueParts: string[] = [];
  for (const part of sentenceParts) {
    if (!uniqueParts.includes(part)) uniqueParts.push(part);
    if (uniqueParts.length >= 2) break;
  }
  if (uniqueParts.length > 0) {
    text = uniqueParts.join(" ");
  }

  if (text.length > maxChars) {
    return `${text.slice(0, maxChars - 1).trimEnd()}…`;
  }
  return text;
}

function isInternalWorkNarration(text: string): boolean {
  return /\b(I need to|Let me|I'll|I will|analy[sz]e|examin|inspect|check files|run command|current codebase|relevant files)\b/i.test(text);
}

type ReplyKind = "opening" | "feedback" | "summary" | "approval" | "direct";

function fallbackTurnReply(kind: ReplyKind, lang: string, agent?: AgentRow): string {
  const name = agent ? getAgentDisplayName(agent, lang) : "";
  switch (kind) {
    case "opening":
      if (lang === "en") return `${name}: Kickoff noted. Please share concise feedback in order.`;
      if (lang === "ja") return `${name}: キックオフを開始します。順番に簡潔なフィードバックを共有してください。`;
      if (lang === "zh") return `${name}: 现在开始会议，请各位按顺序简要反馈。`;
      return `${name}: 킥오프 회의를 시작합니다. 순서대로 핵심 피드백을 간단히 공유해주세요.`;
    case "feedback":
      if (lang === "en") return `${name}: We have identified key gaps and a top-priority validation item before execution.`;
      if (lang === "ja") return `${name}: 着手前の補完項目と最優先の検証課題を確認しました。`;
      if (lang === "zh") return `${name}: 已确认执行前的补充项与最高优先验证课题。`;
      return `${name}: 착수 전 보완 항목과 최우선 검증 과제를 확인했습니다.`;
    case "summary":
      if (lang === "en") return `${name}: I will consolidate all leader feedback and proceed with the agreed next step.`;
      if (lang === "ja") return `${name}: 各チームリーダーの意見を統合し、合意した次のステップへ進めます。`;
      if (lang === "zh") return `${name}: 我将汇总各负责人意见，并按约定进入下一步。`;
      return `${name}: 각 팀장 의견을 취합해 합의된 다음 단계로 진행하겠습니다.`;
    case "approval":
      if (lang === "en") return `${name}: Decision noted. We will proceed according to the current meeting conclusion.`;
      if (lang === "ja") return `${name}: 本会議の結論に従って進行します。`;
      if (lang === "zh") return `${name}: 已确认决策，将按本轮会议结论执行。`;
      return `${name}: 본 회의 결론에 따라 진행하겠습니다.`;
    case "direct":
    default:
      if (lang === "en") return `${name}: Acknowledged. Proceeding with the requested direction.`;
      if (lang === "ja") return `${name}: 承知しました。ご指示の方向で進めます。`;
      if (lang === "zh") return `${name}: 收到，将按您的指示推进。`;
      return `${name}: 확인했습니다. 요청하신 방향으로 진행하겠습니다.`;
  }
}

function chooseSafeReply(
  run: OneShotRunResult,
  lang: string,
  kind: ReplyKind,
  agent?: AgentRow,
): string {
  const cleaned = normalizeConversationReply(run.text || "", 360);
  if (!cleaned) return fallbackTurnReply(kind, lang, agent);
  if (/timeout after|CLI 응답 생성에 실패|response failed|one-shot-error/i.test(cleaned)) {
    return fallbackTurnReply(kind, lang, agent);
  }
  if (isInternalWorkNarration(cleaned)) {
    return fallbackTurnReply(kind, lang, agent);
  }
  if ((lang === "ko" || lang === "ja" || lang === "zh") && detectLang(cleaned) === "en" && cleaned.length > 20) {
    return fallbackTurnReply(kind, lang, agent);
  }
  return cleaned;
}

function summarizeForMeetingBubble(text: string, maxChars = 96): string {
  const cleaned = normalizeConversationReply(text, maxChars + 24)
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) return "의견 공유드립니다.";
  if (cleaned.length <= maxChars) return cleaned;
  return `${cleaned.slice(0, maxChars - 1).trimEnd()}…`;
}

function formatMeetingTranscript(transcript: MeetingTranscriptEntry[]): string {
  if (transcript.length === 0) return "(none)";
  return transcript
    .map((line, idx) => `${idx + 1}. ${line.speaker} (${line.department} ${line.role}): ${line.content}`)
    .join("\n");
}

function buildMeetingPrompt(agent: AgentRow, opts: MeetingPromptOptions): string {
  const deptName = getDeptName(agent.department_id ?? "");
  const role = getRoleLabel(agent.role, opts.lang as Lang);
  const deptConstraint = agent.department_id ? getDeptRoleConstraint(agent.department_id, deptName) : "";
  const recentCtx = getRecentConversationContext(agent.id, 8);
  const meetingLabel = opts.meetingType === "planned" ? "Planned Approval" : "Review Consensus";
  return [
    `[CEO OFFICE ${meetingLabel}]`,
    `Task: ${opts.taskTitle}`,
    opts.taskDescription ? `Task context: ${opts.taskDescription}` : "",
    `Round: ${opts.round}`,
    `You are ${getAgentDisplayName(agent, opts.lang)} (${deptName} ${role}).`,
    deptConstraint,
    localeInstruction(opts.lang),
    "Output rules:",
    "- Return one natural chat message only (no JSON, no markdown).",
    "- Keep it concise: 1-3 sentences.",
    "- Make your stance explicit and actionable.",
    opts.stanceHint ? `Required stance: ${opts.stanceHint}` : "",
    `Current turn objective: ${opts.turnObjective}`,
    "",
    "[Meeting transcript so far]",
    formatMeetingTranscript(opts.transcript),
    recentCtx,
  ].filter(Boolean).join("\n");
}

function buildDirectReplyPrompt(agent: AgentRow, ceoMessage: string, messageType: string): { prompt: string; lang: string } {
  const lang = resolveLang(ceoMessage);
  const deptName = getDeptName(agent.department_id ?? "");
  const role = getRoleLabel(agent.role, lang);
  const deptConstraint = agent.department_id ? getDeptRoleConstraint(agent.department_id, deptName) : "";
  const recentCtx = getRecentConversationContext(agent.id, 12);
  const typeHint = messageType === "report"
    ? "CEO requested a report update."
    : messageType === "task_assign"
      ? "CEO assigned a task. Confirm understanding and concrete next step."
      : "CEO sent a direct chat message.";
  const prompt = [
    "[CEO 1:1 Conversation]",
    `You are ${getAgentDisplayName(agent, lang)} (${deptName} ${role}).`,
    deptConstraint,
    localeInstruction(lang),
    "Output rules:",
    "- Return one direct response message only (no JSON, no markdown).",
    "- Keep it concise and practical (1-3 sentences).",
    `Message type: ${messageType}`,
    `Conversation intent: ${typeHint}`,
    "",
    `CEO message: ${ceoMessage}`,
    recentCtx,
  ].filter(Boolean).join("\n");
  return { prompt, lang };
}

function buildCliFailureMessage(agent: AgentRow, lang: string, error?: string): string {
  const name = getAgentDisplayName(agent, lang);
  if (lang === "en") return `${name}: CLI response failed (${error || "unknown error"}).`;
  if (lang === "ja") return `${name}: CLI応答の生成に失敗しました（${error || "不明なエラー"}）。`;
  if (lang === "zh") return `${name}: CLI回复生成失败（${error || "未知错误"}）。`;
  return `${name}: CLI 응답 생성에 실패했습니다 (${error || "알 수 없는 오류"}).`;
}

async function runAgentOneShot(
  agent: AgentRow,
  prompt: string,
  opts: OneShotRunOptions = {},
): Promise<OneShotRunResult> {
  const provider = agent.cli_provider || "claude";
  const timeoutMs = opts.timeoutMs ?? 180_000;
  const projectPath = opts.projectPath || process.cwd();
  const streamTaskId = opts.streamTaskId ?? null;
  const runId = `meeting-${agent.id}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const logPath = path.join(logsDir, `${runId}.log`);
  const logStream = fs.createWriteStream(logPath, { flags: "w" });
  let rawOutput = "";
  let exitCode = 0;

  const onChunk = (chunk: Buffer | string, stream: "stdout" | "stderr") => {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    rawOutput += text;
    logStream.write(text);
    if (streamTaskId) {
      broadcast("cli_output", { task_id: streamTaskId, stream, data: text });
    }
  };

  try {
    if (provider === "copilot" || provider === "antigravity") {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), timeoutMs);
      try {
        if (provider === "copilot") {
          await executeCopilotAgent(prompt, projectPath, logStream, controller.signal, streamTaskId ?? undefined);
        } else {
          await executeAntigravityAgent(prompt, logStream, controller.signal, streamTaskId ?? undefined);
        }
      } finally {
        clearTimeout(timeout);
      }
      if (!rawOutput.trim() && fs.existsSync(logPath)) {
        rawOutput = fs.readFileSync(logPath, "utf8");
      }
    } else {
      const modelConfig = getProviderModelConfig();
      const model = modelConfig[provider]?.model || undefined;
      const reasoningLevel = modelConfig[provider]?.reasoningLevel || undefined;
      const args = buildAgentArgs(provider, model, reasoningLevel);

      await new Promise<void>((resolve, reject) => {
        const cleanEnv = { ...process.env };
        delete cleanEnv.CLAUDECODE;
        delete cleanEnv.CLAUDE_CODE;

        const child = spawn(args[0], args.slice(1), {
          cwd: projectPath,
          env: cleanEnv,
          shell: process.platform === "win32",
          stdio: ["pipe", "pipe", "pipe"],
          detached: false,
          windowsHide: true,
        });

        const timeout = setTimeout(() => {
          const pid = child.pid ?? 0;
          if (pid > 0) killPidTree(pid);
          reject(new Error(`timeout after ${timeoutMs}ms`));
        }, timeoutMs);

        child.on("error", (err) => {
          clearTimeout(timeout);
          reject(err);
        });
        child.stdout?.on("data", (chunk: Buffer) => onChunk(chunk, "stdout"));
        child.stderr?.on("data", (chunk: Buffer) => onChunk(chunk, "stderr"));
        child.on("close", (code) => {
          clearTimeout(timeout);
          exitCode = code ?? 1;
          resolve();
        });

        child.stdin?.write(prompt);
        child.stdin?.end();
      });
    }
  } catch (err: any) {
    const message = err?.message ? String(err.message) : String(err);
    onChunk(`\n[one-shot-error] ${message}\n`, "stderr");
    const partial = normalizeConversationReply(rawOutput, 320);
    if (partial) return { text: partial, error: message };
    const rough = (prettyStreamJson(rawOutput).trim() ? prettyStreamJson(rawOutput) : rawOutput)
      .replace(/\s+/g, " ")
      .trim();
    if (rough) {
      const clipped = rough.length > 320 ? `${rough.slice(0, 319).trimEnd()}…` : rough;
      return { text: clipped, error: message };
    }
    return { text: "", error: message };
  } finally {
    await new Promise<void>((resolve) => logStream.end(resolve));
  }

  if (exitCode !== 0 && !rawOutput.trim()) {
    return { text: "", error: `${provider} exited with code ${exitCode}` };
  }

  const normalized = normalizeConversationReply(rawOutput);
  if (normalized) return { text: normalized };

  const rough = (prettyStreamJson(rawOutput).trim() ? prettyStreamJson(rawOutput) : rawOutput)
    .replace(/\s+/g, " ")
    .trim();
  if (rough) {
    const clipped = rough.length > 320 ? `${rough.slice(0, 319).trimEnd()}…` : rough;
    return { text: clipped };
  }

  const lang = getPreferredLanguage();
  if (lang === "en") return { text: "Acknowledged. Continuing to the next step." };
  if (lang === "ja") return { text: "確認しました。次のステップへ進みます。" };
  if (lang === "zh") return { text: "已确认，继续进入下一步。" };
  return { text: "확인했습니다. 다음 단계로 진행하겠습니다." };
}

// ---------------------------------------------------------------------------
// Subtask department detection — re-uses DEPT_KEYWORDS + detectTargetDepartments
// ---------------------------------------------------------------------------
function analyzeSubtaskDepartment(subtaskTitle: string, parentDeptId: string | null): string | null {
  const detectedDepts = detectTargetDepartments(subtaskTitle);
  const foreignDepts = detectedDepts.filter(d => d !== parentDeptId);
  return foreignDepts[0] ?? null;
}

// ---------------------------------------------------------------------------
// SubTask creation/completion helpers (shared across all CLI providers)
// ---------------------------------------------------------------------------
function createSubtaskFromCli(taskId: string, toolUseId: string, title: string): void {
  const subId = randomUUID();
  const parentAgent = db.prepare(
    "SELECT assigned_agent_id FROM tasks WHERE id = ?"
  ).get(taskId) as { assigned_agent_id: string | null } | undefined;

  db.prepare(`
    INSERT INTO subtasks (id, task_id, title, status, assigned_agent_id, cli_tool_use_id, created_at)
    VALUES (?, ?, ?, 'in_progress', ?, ?, ?)
  `).run(subId, taskId, title, parentAgent?.assigned_agent_id ?? null, toolUseId, nowMs());

  // Detect if this subtask belongs to a foreign department
  const parentTaskDept = db.prepare(
    "SELECT department_id FROM tasks WHERE id = ?"
  ).get(taskId) as { department_id: string | null } | undefined;
  const targetDeptId = analyzeSubtaskDepartment(title, parentTaskDept?.department_id ?? null);

  if (targetDeptId) {
    const targetDeptName = getDeptName(targetDeptId);
    const lang = getPreferredLanguage();
    const blockedReason = pickL(l(
      [`${targetDeptName} 협업 대기`],
      [`Waiting for ${targetDeptName} collaboration`],
      [`${targetDeptName}の協業待ち`],
      [`等待${targetDeptName}协作`],
    ), lang);
    db.prepare(
      "UPDATE subtasks SET target_department_id = ?, status = 'blocked', blocked_reason = ? WHERE id = ?"
    ).run(targetDeptId, blockedReason, subId);
  }

  const subtask = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(subId);
  broadcast("subtask_update", subtask);
}

function completeSubtaskFromCli(toolUseId: string): void {
  const existing = db.prepare(
    "SELECT id, status FROM subtasks WHERE cli_tool_use_id = ?"
  ).get(toolUseId) as { id: string; status: string } | undefined;
  if (!existing || existing.status === "done") return;

  db.prepare(
    "UPDATE subtasks SET status = 'done', completed_at = ? WHERE id = ?"
  ).run(nowMs(), existing.id);

  const subtask = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(existing.id);
  broadcast("subtask_update", subtask);
}

function seedApprovedPlanSubtasks(taskId: string, ownerDeptId: string | null): void {
  const existing = db.prepare(
    "SELECT COUNT(*) as cnt FROM subtasks WHERE task_id = ?"
  ).get(taskId) as { cnt: number };
  if (existing.cnt > 0) return;

  const task = db.prepare(
    "SELECT title, description, assigned_agent_id, department_id FROM tasks WHERE id = ?"
  ).get(taskId) as {
    title: string;
    description: string | null;
    assigned_agent_id: string | null;
    department_id: string | null;
  } | undefined;
  if (!task) return;

  const baseDeptId = ownerDeptId ?? task.department_id;
  const relatedDepts = getTaskRelatedDepartmentIds(taskId, baseDeptId)
    .filter((d) => !!d && d !== baseDeptId);
  const lang = resolveLang(task.description ?? task.title);

  const now = nowMs();
  const baseAssignee = task.assigned_agent_id;

  const items: Array<{
    title: string;
    description: string;
    status: "pending" | "blocked";
    assignedAgentId: string | null;
    blockedReason: string | null;
    targetDepartmentId: string | null;
  }> = [
    {
      title: pickL(l(
        ["승인안 상세 실행 계획 확정"],
        ["Finalize detailed execution plan from approved proposal"],
        ["承認案の詳細実行計画を確定"],
        ["确定批准方案的详细执行计划"],
      ), lang),
      description: pickL(l(
        [`Approved 기획안 기준으로 상세 작업 순서/산출물 기준을 확정합니다. (${task.title})`],
        [`Finalize detailed task sequence and deliverable criteria based on the approved plan. (${task.title})`],
        [`承認済み企画案を基準に、詳細な作業順序と成果物基準を確定します。(${task.title})`],
        [`基于已批准方案，确定详细任务顺序与交付物标准。（${task.title}）`],
      ), lang),
      status: "pending",
      assignedAgentId: baseAssignee,
      blockedReason: null,
      targetDepartmentId: null,
    },
  ];

  for (const deptId of relatedDepts) {
    const deptName = getDeptName(deptId);
    const crossLeader = findTeamLeader(deptId);
    items.push({
      title: pickL(l(
        [`[협업] ${deptName} 결과물 작성`],
        [`[Collaboration] Produce ${deptName} deliverable`],
        [`[協業] ${deptName}成果物を作成`],
        [`[协作] 编写${deptName}交付物`],
      ), lang),
      description: pickL(l(
        [`Approved 기획안 기준 ${deptName} 담당 결과물을 작성/공유합니다.`],
        [`Create and share the ${deptName}-owned deliverable based on the approved plan.`],
        [`承認済み企画案を基準に、${deptName}担当の成果物を作成・共有します。`],
        [`基于已批准方案，完成并共享${deptName}负责的交付物。`],
      ), lang),
      status: "blocked",
      assignedAgentId: crossLeader?.id ?? null,
      blockedReason: pickL(l(
        [`${deptName} 협업 대기`],
        [`Waiting for ${deptName} collaboration`],
        [`${deptName}の協業待ち`],
        [`等待${deptName}协作`],
      ), lang),
      targetDepartmentId: deptId,
    });
  }

  items.push({
    title: pickL(l(
      ["부서 산출물 통합 및 최종 정리"],
      ["Consolidate department deliverables and finalize package"],
      ["部門成果物の統合と最終整理"],
      ["整合部门交付物并完成最终整理"],
    ), lang),
    description: pickL(l(
      ["유관부서 산출물을 취합해 단일 결과물로 통합하고 Review 제출본을 준비합니다."],
      ["Collect related-department outputs, merge into one package, and prepare the review submission."],
      ["関連部門の成果物を集約して単一成果物へ統合し、レビュー提出版を準備します。"],
      ["汇总相关部门产出，整合为单一成果，并准备 Review 提交版本。"],
    ), lang),
    status: "pending",
    assignedAgentId: baseAssignee,
    blockedReason: null,
    targetDepartmentId: null,
  });

  for (const st of items) {
    const sid = randomUUID();
    db.prepare(`
      INSERT INTO subtasks (id, task_id, title, description, status, assigned_agent_id, blocked_reason, target_department_id, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      sid,
      taskId,
      st.title,
      st.description,
      st.status,
      st.assignedAgentId,
      st.blockedReason,
      st.targetDepartmentId,
      now,
    );
    broadcast("subtask_update", db.prepare("SELECT * FROM subtasks WHERE id = ?").get(sid));
  }

  appendTaskLog(taskId, "system", `Approved plan seeded ${items.length} subtasks (cross-dept: ${relatedDepts.length})`);
  notifyCeo(pickL(l(
    [`'${task.title}' 승인안 기준 SubTask ${items.length}건을 생성하고 담당자/유관부서 협업을 배정했습니다.`],
    [`Created ${items.length} subtasks from the approved plan for '${task.title}' and assigned owners/cross-department collaboration.`],
    [`'${task.title}' の承認案に基づき SubTask を${items.length}件作成し、担当者と関連部門協業を割り当てました。`],
    [`已基于'${task.title}'的批准方案创建${items.length}个 SubTask，并分配负责人及跨部门协作。`],
  ), lang), taskId);
}

// ---------------------------------------------------------------------------
// SubTask parsing from CLI stream-json output
// ---------------------------------------------------------------------------

// Codex multi-agent: map thread_id → cli_tool_use_id (item.id from spawn_agent)
const codexThreadToSubtask = new Map<string, string>();

function parseAndCreateSubtasks(taskId: string, data: string): void {
  try {
    const lines = data.split("\n").filter(Boolean);
    for (const line of lines) {
      let j: Record<string, unknown>;
      try { j = JSON.parse(line); } catch { continue; }

      // Detect sub-agent spawn: tool_use with tool === "Task" (Claude Code)
      if (j.type === "tool_use" && j.tool === "Task") {
        const toolUseId = (j.id as string) || `sub-${Date.now()}`;
        // Check for duplicate
        const existing = db.prepare(
          "SELECT id FROM subtasks WHERE cli_tool_use_id = ?"
        ).get(toolUseId) as { id: string } | undefined;
        if (existing) continue;

        const input = j.input as Record<string, unknown> | undefined;
        const title = (input?.description as string) ||
                      (input?.prompt as string)?.slice(0, 100) ||
                      "Sub-task";

        createSubtaskFromCli(taskId, toolUseId, title);
      }

      // Detect sub-agent completion: tool_result with tool === "Task" (Claude Code)
      if (j.type === "tool_result" && j.tool === "Task") {
        const toolUseId = j.id as string;
        if (!toolUseId) continue;
        completeSubtaskFromCli(toolUseId);
      }

      // ----- Codex multi-agent: spawn_agent / close_agent -----

      // Codex: spawn_agent started → create subtask
      if (j.type === "item.started") {
        const item = j.item as Record<string, unknown> | undefined;
        if (item?.type === "collab_tool_call" && item?.tool === "spawn_agent") {
          const itemId = (item.id as string) || `codex-spawn-${Date.now()}`;
          const existing = db.prepare(
            "SELECT id FROM subtasks WHERE cli_tool_use_id = ?"
          ).get(itemId) as { id: string } | undefined;
          if (!existing) {
            const prompt = (item.prompt as string) || "Sub-agent";
            const title = prompt.split("\n")[0].replace(/^Task:\s*/, "").slice(0, 100);
            createSubtaskFromCli(taskId, itemId, title);
          }
        }
      }

      // Codex: spawn_agent completed → save thread_id mapping
      // Codex: close_agent completed → complete subtask via thread_id
      if (j.type === "item.completed") {
        const item = j.item as Record<string, unknown> | undefined;
        if (item?.type === "collab_tool_call") {
          if (item.tool === "spawn_agent") {
            const itemId = item.id as string;
            const threadIds = (item.receiver_thread_ids as string[]) || [];
            if (itemId && threadIds[0]) {
              codexThreadToSubtask.set(threadIds[0], itemId);
            }
          } else if (item.tool === "close_agent") {
            const threadIds = (item.receiver_thread_ids as string[]) || [];
            for (const tid of threadIds) {
              const origItemId = codexThreadToSubtask.get(tid);
              if (origItemId) {
                completeSubtaskFromCli(origItemId);
                codexThreadToSubtask.delete(tid);
              }
            }
          }
        }
      }

      // ----- Gemini: plan-based subtask detection from message -----

      if (j.type === "message" && j.content) {
        const content = j.content as string;
        // Detect plan output: {"subtasks": [...]}
        const planMatch = content.match(/\{"subtasks"\s*:\s*\[.*?\]\}/s);
        if (planMatch) {
          try {
            const plan = JSON.parse(planMatch[0]) as { subtasks: { title: string }[] };
            for (const st of plan.subtasks) {
              const stId = `gemini-plan-${st.title.slice(0, 30).replace(/\s/g, "-")}-${Date.now()}`;
              const existing = db.prepare(
                "SELECT id FROM subtasks WHERE task_id = ? AND title = ? AND status != 'done'"
              ).get(taskId, st.title) as { id: string } | undefined;
              if (!existing) {
                createSubtaskFromCli(taskId, stId, st.title);
              }
            }
          } catch { /* ignore malformed JSON */ }
        }
        // Detect completion report: {"subtask_done": "..."}
        const doneMatch = content.match(/\{"subtask_done"\s*:\s*"(.+?)"\}/);
        if (doneMatch) {
          const doneTitle = doneMatch[1];
          const sub = db.prepare(
            "SELECT cli_tool_use_id FROM subtasks WHERE task_id = ? AND title = ? AND status != 'done' LIMIT 1"
          ).get(taskId, doneTitle) as { cli_tool_use_id: string } | undefined;
          if (sub) completeSubtaskFromCli(sub.cli_tool_use_id);
        }
      }
    }
  } catch {
    // Not JSON or not parseable - ignore
  }
}

function spawnCliAgent(
  taskId: string,
  provider: string,
  prompt: string,
  projectPath: string,
  logPath: string,
  model?: string,
  reasoningLevel?: string,
): ChildProcess {
  // Save prompt for debugging
  const promptPath = path.join(logsDir, `${taskId}.prompt.txt`);
  fs.writeFileSync(promptPath, prompt, "utf8");

  const args = buildAgentArgs(provider, model, reasoningLevel);
  const logStream = fs.createWriteStream(logPath, { flags: "w" });

  // Remove CLAUDECODE env var to prevent "nested session" detection
  const cleanEnv = { ...process.env };
  delete cleanEnv.CLAUDECODE;
  delete cleanEnv.CLAUDE_CODE;

  const child = spawn(args[0], args.slice(1), {
    cwd: projectPath,
    env: cleanEnv,
    shell: process.platform === "win32",
    stdio: ["pipe", "pipe", "pipe"],
    detached: process.platform !== "win32",
    windowsHide: true,
  });

  activeProcesses.set(taskId, child);

  child.on("error", (err) => {
    console.error(`[CLImpire] spawn error for ${provider} (task ${taskId}): ${err.message}`);
    logStream.write(`\n[CLImpire] SPAWN ERROR: ${err.message}\n`);
    logStream.end();
    activeProcesses.delete(taskId);
    appendTaskLog(taskId, "error", `Agent spawn failed: ${err.message}`);
  });

  // Deliver prompt via stdin (cross-platform safe)
  child.stdin?.write(prompt);
  child.stdin?.end();

  // Pipe agent output to log file AND broadcast via WebSocket
  child.stdout?.on("data", (chunk: Buffer) => {
    logStream.write(chunk);
    const text = chunk.toString("utf8");
    broadcast("cli_output", { task_id: taskId, stream: "stdout", data: text });
    parseAndCreateSubtasks(taskId, text);
  });
  child.stderr?.on("data", (chunk: Buffer) => {
    logStream.write(chunk);
    broadcast("cli_output", { task_id: taskId, stream: "stderr", data: chunk.toString("utf8") });
  });

  child.on("close", () => {
    logStream.end();
    try { fs.unlinkSync(promptPath); } catch { /* ignore */ }
  });

  if (process.platform !== "win32") child.unref();

  return child;
}

// ---------------------------------------------------------------------------
// HTTP Agent: direct API calls for copilot/antigravity (no CLI dependency)
// ---------------------------------------------------------------------------
const ANTIGRAVITY_ENDPOINTS = [
  "https://cloudcode-pa.googleapis.com",
  "https://daily-cloudcode-pa.sandbox.googleapis.com",
  "https://autopush-cloudcode-pa.sandbox.googleapis.com",
];
const ANTIGRAVITY_DEFAULT_PROJECT = "rising-fact-p41fc";
let copilotTokenCache: { token: string; baseUrl: string; expiresAt: number; sourceHash: string } | null = null;
let antigravityProjectCache: { projectId: string; tokenHash: string } | null = null;
let httpAgentCounter = Date.now() % 1_000_000;
let cachedModels: { data: Record<string, string[]>; loadedAt: number } | null = null;
const MODELS_CACHE_TTL = 60_000;

interface DecryptedOAuthToken {
  accessToken: string | null;
  refreshToken: string | null;
  expiresAt: number | null;
  email: string | null;
}

function getDecryptedOAuthToken(provider: string): DecryptedOAuthToken | null {
  const row = db
    .prepare("SELECT access_token_enc, refresh_token_enc, expires_at, email FROM oauth_credentials WHERE provider = ?")
    .get(provider) as { access_token_enc: string | null; refresh_token_enc: string | null; expires_at: number | null; email: string | null } | undefined;
  if (!row) return null;
  return {
    accessToken: row.access_token_enc ? decryptSecret(row.access_token_enc) : null,
    refreshToken: row.refresh_token_enc ? decryptSecret(row.refresh_token_enc) : null,
    expiresAt: row.expires_at,
    email: row.email,
  };
}

function getProviderModelConfig(): Record<string, { model: string; subModel?: string; reasoningLevel?: string; subModelReasoningLevel?: string }> {
  const row = db.prepare("SELECT value FROM settings WHERE key = 'providerModelConfig'").get() as { value: string } | undefined;
  return row ? JSON.parse(row.value) : {};
}

async function refreshGoogleToken(credential: DecryptedOAuthToken): Promise<string> {
  const expiresAtMs = credential.expiresAt && credential.expiresAt < 1e12
    ? credential.expiresAt * 1000
    : credential.expiresAt;
  if (credential.accessToken && expiresAtMs && expiresAtMs > Date.now() + 60_000) {
    return credential.accessToken;
  }
  if (!credential.refreshToken) {
    throw new Error("Google OAuth token expired and no refresh_token available");
  }
  const clientId = process.env.OAUTH_GOOGLE_CLIENT_ID ?? BUILTIN_GOOGLE_CLIENT_ID;
  const clientSecret = process.env.OAUTH_GOOGLE_CLIENT_SECRET ?? BUILTIN_GOOGLE_CLIENT_SECRET;
  const resp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: credential.refreshToken,
      grant_type: "refresh_token",
    }),
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Google token refresh failed (${resp.status}): ${text}`);
  }
  const data = await resp.json() as { access_token: string; expires_in?: number };
  const newExpiresAt = data.expires_in ? Date.now() + data.expires_in * 1000 : null;
  // Update DB with new access token
  const now = nowMs();
  const accessEnc = encryptSecret(data.access_token);
  db.prepare(
    "UPDATE oauth_credentials SET access_token_enc = ?, expires_at = ?, updated_at = ? WHERE provider = 'google_antigravity'"
  ).run(accessEnc, newExpiresAt, now);
  return data.access_token;
}

async function exchangeCopilotToken(githubToken: string): Promise<{ token: string; baseUrl: string; expiresAt: number }> {
  const sourceHash = createHash("sha256").update(githubToken).digest("hex").slice(0, 16);
  if (copilotTokenCache
      && copilotTokenCache.expiresAt > Date.now() + 5 * 60_000
      && copilotTokenCache.sourceHash === sourceHash) {
    return copilotTokenCache;
  }
  const resp = await fetch("https://api.github.com/copilot_internal/v2/token", {
    headers: {
      Authorization: `Bearer ${githubToken}`,
      Accept: "application/json",
      "User-Agent": "climpire",
    },
  });
  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Copilot token exchange failed (${resp.status}): ${text}`);
  }
  const data = await resp.json() as { token: string; expires_at: number; endpoints?: { api?: string } };
  let baseUrl = "https://api.individual.githubcopilot.com";
  const proxyMatch = data.token.match(/proxy-ep=([^;]+)/);
  if (proxyMatch) {
    baseUrl = `https://${proxyMatch[1].replace(/^proxy\./, "api.")}`;
  }
  if (data.endpoints?.api) {
    baseUrl = data.endpoints.api.replace(/\/$/, "");
  }
  const expiresAt = data.expires_at * 1000;
  copilotTokenCache = { token: data.token, baseUrl, expiresAt, sourceHash };
  return copilotTokenCache;
}

async function loadCodeAssistProject(accessToken: string, signal?: AbortSignal): Promise<string> {
  const tokenHash = createHash("sha256").update(accessToken).digest("hex").slice(0, 16);
  if (antigravityProjectCache && antigravityProjectCache.tokenHash === tokenHash) {
    return antigravityProjectCache.projectId;
  }
  for (const endpoint of ANTIGRAVITY_ENDPOINTS) {
    try {
      const resp = await fetch(`${endpoint}/v1internal:loadCodeAssist`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json",
          "User-Agent": "google-api-nodejs-client/9.15.1",
          "X-Goog-Api-Client": "google-cloud-sdk vscode_cloudshelleditor/0.1",
          "Client-Metadata": JSON.stringify({ ideType: "ANTIGRAVITY", platform: process.platform === "win32" ? "WINDOWS" : "MACOS", pluginType: "GEMINI" }),
        },
        body: JSON.stringify({
          metadata: { ideType: "ANTIGRAVITY", platform: process.platform === "win32" ? "WINDOWS" : "MACOS", pluginType: "GEMINI" },
        }),
        signal,
      });
      if (!resp.ok) continue;
      const data = await resp.json() as any;
      const proj = data?.cloudaicompanionProject?.id ?? data?.cloudaicompanionProject;
      if (typeof proj === "string" && proj) {
        antigravityProjectCache = { projectId: proj, tokenHash };
        return proj;
      }
    } catch { /* try next endpoint */ }
  }
  antigravityProjectCache = { projectId: ANTIGRAVITY_DEFAULT_PROJECT, tokenHash };
  return ANTIGRAVITY_DEFAULT_PROJECT;
}

// ---------------------------------------------------------------------------
// HTTP agent subtask detection (plain-text accumulator for plan JSON patterns)
// ---------------------------------------------------------------------------
function parseHttpAgentSubtasks(taskId: string, textChunk: string, accum: { buf: string }): void {
  accum.buf += textChunk;
  // Only scan when we see a closing brace (potential JSON end)
  if (!accum.buf.includes("}")) return;

  // Detect plan: {"subtasks": [...]}
  const planMatch = accum.buf.match(/\{"subtasks"\s*:\s*\[.*?\]\}/s);
  if (planMatch) {
    try {
      const plan = JSON.parse(planMatch[0]) as { subtasks: { title: string }[] };
      for (const st of plan.subtasks) {
        const stId = `http-plan-${st.title.slice(0, 30).replace(/\s/g, "-")}-${Date.now()}`;
        const existing = db.prepare(
          "SELECT id FROM subtasks WHERE task_id = ? AND title = ? AND status != 'done'"
        ).get(taskId, st.title) as { id: string } | undefined;
        if (!existing) {
          createSubtaskFromCli(taskId, stId, st.title);
        }
      }
    } catch { /* ignore malformed JSON */ }
    // Remove matched portion to avoid re-detection
    accum.buf = accum.buf.slice(accum.buf.indexOf(planMatch[0]) + planMatch[0].length);
  }

  // Detect completion: {"subtask_done": "..."}
  const doneMatch = accum.buf.match(/\{"subtask_done"\s*:\s*"(.+?)"\}/);
  if (doneMatch) {
    const doneTitle = doneMatch[1];
    const sub = db.prepare(
      "SELECT cli_tool_use_id FROM subtasks WHERE task_id = ? AND title = ? AND status != 'done' LIMIT 1"
    ).get(taskId, doneTitle) as { cli_tool_use_id: string } | undefined;
    if (sub) completeSubtaskFromCli(sub.cli_tool_use_id);
    accum.buf = accum.buf.slice(accum.buf.indexOf(doneMatch[0]) + doneMatch[0].length);
  }

  // Prevent unbounded growth: keep only last 2KB
  if (accum.buf.length > 2048) {
    accum.buf = accum.buf.slice(-1024);
  }
}

// Parse OpenAI-compatible SSE stream (for Copilot)
async function parseSSEStream(
  body: ReadableStream<Uint8Array>,
  logStream: fs.WriteStream,
  signal: AbortSignal,
  taskId?: string,
): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";
  const subtaskAccum = { buf: "" };

  const processLine = (trimmed: string) => {
    if (!trimmed || trimmed.startsWith(":")) return;
    if (!trimmed.startsWith("data: ")) return;
    if (trimmed === "data: [DONE]") return;
    try {
      const data = JSON.parse(trimmed.slice(6));
      const delta = data.choices?.[0]?.delta;
      if (delta?.content) {
        logStream.write(delta.content);
        if (taskId) {
          broadcast("cli_output", { task_id: taskId, stream: "stdout", data: delta.content });
          parseHttpAgentSubtasks(taskId, delta.content, subtaskAccum);
        }
      }
    } catch { /* ignore */ }
  };

  for await (const chunk of body as AsyncIterable<Uint8Array>) {
    if (signal.aborted) break;
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) processLine(line.trim());
  }
  if (buffer.trim()) processLine(buffer.trim());
}

// Parse Gemini/Antigravity SSE stream
async function parseGeminiSSEStream(
  body: ReadableStream<Uint8Array>,
  logStream: fs.WriteStream,
  signal: AbortSignal,
  taskId?: string,
): Promise<void> {
  const decoder = new TextDecoder();
  let buffer = "";
  const subtaskAccum = { buf: "" };

  const processLine = (trimmed: string) => {
    if (!trimmed || trimmed.startsWith(":")) return;
    if (!trimmed.startsWith("data: ")) return;
    try {
      const data = JSON.parse(trimmed.slice(6));
      const candidates = data.response?.candidates ?? data.candidates;
      if (Array.isArray(candidates)) {
        for (const candidate of candidates) {
          const parts = candidate?.content?.parts;
          if (Array.isArray(parts)) {
            for (const part of parts) {
              if (part.text) {
                logStream.write(part.text);
                if (taskId) {
                  broadcast("cli_output", { task_id: taskId, stream: "stdout", data: part.text });
                  parseHttpAgentSubtasks(taskId, part.text, subtaskAccum);
                }
              }
            }
          }
        }
      }
    } catch { /* ignore */ }
  };

  for await (const chunk of body as AsyncIterable<Uint8Array>) {
    if (signal.aborted) break;
    buffer += decoder.decode(chunk, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() ?? "";
    for (const line of lines) processLine(line.trim());
  }
  if (buffer.trim()) processLine(buffer.trim());
}

async function executeCopilotAgent(
  prompt: string,
  projectPath: string,
  logStream: fs.WriteStream,
  signal: AbortSignal,
  taskId?: string,
): Promise<void> {
  const modelConfig = getProviderModelConfig();
  const rawModel = modelConfig.copilot?.model || "github-copilot/gpt-4o";
  const model = rawModel.includes("/") ? rawModel.split("/").pop()! : rawModel;

  const cred = getDecryptedOAuthToken("github");
  if (!cred?.accessToken) throw new Error("No GitHub OAuth token found. Connect GitHub Copilot first.");

  logStream.write(`[copilot] Exchanging Copilot token...\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: "[copilot] Exchanging Copilot token...\n" });
  const { token, baseUrl } = await exchangeCopilotToken(cred.accessToken);
  logStream.write(`[copilot] Model: ${model}, Base: ${baseUrl}\n---\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: `[copilot] Model: ${model}, Base: ${baseUrl}\n---\n` });

  const resp = await fetch(`${baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "Editor-Version": "climpire/1.0",
      "Copilot-Integration-Id": "vscode-chat",
    },
    body: JSON.stringify({
      model,
      messages: [
        { role: "system", content: `You are a coding assistant. Project path: ${projectPath}` },
        { role: "user", content: prompt },
      ],
      stream: true,
    }),
    signal,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Copilot API error (${resp.status}): ${text}`);
  }

  await parseSSEStream(resp.body!, logStream, signal, taskId);
  logStream.write(`\n---\n[copilot] Done.\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: "\n---\n[copilot] Done.\n" });
}

async function executeAntigravityAgent(
  prompt: string,
  logStream: fs.WriteStream,
  signal: AbortSignal,
  taskId?: string,
): Promise<void> {
  const modelConfig = getProviderModelConfig();
  const rawModel = modelConfig.antigravity?.model || "google/antigravity-gemini-2.5-pro";
  let model = rawModel;
  if (model.includes("antigravity-")) {
    model = model.slice(model.indexOf("antigravity-") + "antigravity-".length);
  } else if (model.includes("/")) {
    model = model.split("/").pop()!;
  }

  const cred = getDecryptedOAuthToken("google_antigravity");
  if (!cred?.accessToken) throw new Error("No Google OAuth token found. Connect Antigravity first.");

  logStream.write(`[antigravity] Refreshing token...\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: "[antigravity] Refreshing token...\n" });
  const accessToken = await refreshGoogleToken(cred);

  logStream.write(`[antigravity] Discovering project...\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: "[antigravity] Discovering project...\n" });
  const projectId = await loadCodeAssistProject(accessToken, signal);
  logStream.write(`[antigravity] Model: ${model}, Project: ${projectId}\n---\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: `[antigravity] Model: ${model}, Project: ${projectId}\n---\n` });

  const baseEndpoint = ANTIGRAVITY_ENDPOINTS[0];
  const url = `${baseEndpoint}/v1internal:streamGenerateContent?alt=sse`;
  const resp = await fetch(url, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      Accept: "text/event-stream",
      "User-Agent": `antigravity/1.15.8 ${process.platform === "darwin" ? "darwin/arm64" : "linux/amd64"}`,
      "X-Goog-Api-Client": "google-cloud-sdk vscode_cloudshelleditor/0.1",
      "Client-Metadata": JSON.stringify({ ideType: "ANTIGRAVITY", platform: process.platform === "win32" ? "WINDOWS" : "MACOS", pluginType: "GEMINI" }),
    },
    body: JSON.stringify({
      project: projectId,
      model,
      requestType: "agent",
      userAgent: "antigravity",
      requestId: `agent-${randomUUID()}`,
      request: {
        contents: [{ role: "user", parts: [{ text: prompt }] }],
      },
    }),
    signal,
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Antigravity API error (${resp.status}): ${text}`);
  }

  await parseGeminiSSEStream(resp.body!, logStream, signal, taskId);
  logStream.write(`\n---\n[antigravity] Done.\n`);
  if (taskId) broadcast("cli_output", { task_id: taskId, stream: "stderr", data: "\n---\n[antigravity] Done.\n" });
}

function launchHttpAgent(
  taskId: string,
  agent: "copilot" | "antigravity",
  prompt: string,
  projectPath: string,
  logPath: string,
  controller: AbortController,
  fakePid: number,
): void {
  const logStream = fs.createWriteStream(logPath, { flags: "w" });

  const promptPath = path.join(logsDir, `${taskId}.prompt.txt`);
  fs.writeFileSync(promptPath, prompt, "utf8");

  // Register mock ChildProcess so stop logic works uniformly
  const mockProc = {
    pid: fakePid,
    kill: () => { controller.abort(); return true; },
  } as unknown as ChildProcess;
  activeProcesses.set(taskId, mockProc);

  const runTask = (async () => {
    let exitCode = 0;
    try {
      if (agent === "copilot") {
        await executeCopilotAgent(prompt, projectPath, logStream, controller.signal, taskId);
      } else {
        await executeAntigravityAgent(prompt, logStream, controller.signal, taskId);
      }
    } catch (err: any) {
      exitCode = 1;
      if (err.name !== "AbortError") {
        const msg = `[${agent}] Error: ${err.message}\n`;
        logStream.write(msg);
        broadcast("cli_output", { task_id: taskId, stream: "stderr", data: msg });
        console.error(`[CLImpire] HTTP agent error (${agent}, task ${taskId}): ${err.message}`);
      } else {
        logStream.write(`[${agent}] Aborted by user\n`);
        broadcast("cli_output", { task_id: taskId, stream: "stderr", data: `[${agent}] Aborted by user\n` });
      }
    } finally {
      await new Promise<void>((resolve) => logStream.end(resolve));
      try { fs.unlinkSync(promptPath); } catch { /* ignore */ }
      handleTaskRunComplete(taskId, exitCode);
    }
  })();

  runTask.catch(() => {});
}

function killPidTree(pid: number): void {
  if (pid <= 0) return;

  if (process.platform === "win32") {
    // Use synchronous taskkill so stop/delete reflects real termination attempt.
    try {
      execFileSync("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore", timeout: 8000 });
    } catch { /* ignore */ }
    return;
  }

  const signalTree = (sig: NodeJS.Signals) => {
    try { process.kill(-pid, sig); } catch { /* ignore */ }
    try { process.kill(pid, sig); } catch { /* ignore */ }
  };
  const isAlive = () => {
    try { process.kill(pid, 0); return true; } catch { return false; }
  };

  // 1) Graceful stop first
  signalTree("SIGTERM");
  // 2) Escalate if process ignores SIGTERM
  setTimeout(() => {
    if (isAlive()) signalTree("SIGKILL");
  }, 1200);
}

// ---------------------------------------------------------------------------
// Task log helpers
// ---------------------------------------------------------------------------
function appendTaskLog(taskId: string, kind: string, message: string): void {
  const t = nowMs();
  db.prepare(
    "INSERT INTO task_logs (task_id, kind, message, created_at) VALUES (?, ?, ?, ?)"
  ).run(taskId, kind, message, t);
}

// ---------------------------------------------------------------------------
// CLI Detection (ported from claw-kanban)
// ---------------------------------------------------------------------------
interface CliToolStatus {
  installed: boolean;
  version: string | null;
  authenticated: boolean;
  authHint: string;
}

type CliStatusResult = Record<string, CliToolStatus>;

let cachedCliStatus: { data: CliStatusResult; loadedAt: number } | null = null;
const CLI_STATUS_TTL = 30_000;

interface CliToolDef {
  name: string;
  authHint: string;
  checkAuth: () => boolean;
}

function jsonHasKey(filePath: string, key: string): boolean {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const j = JSON.parse(raw);
    return j != null && typeof j === "object" && key in j && j[key] != null;
  } catch {
    return false;
  }
}

function fileExistsNonEmpty(filePath: string): boolean {
  try {
    const stat = fs.statSync(filePath);
    return stat.isFile() && stat.size > 2;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// CLI Usage Types
// ---------------------------------------------------------------------------
interface CliUsageWindow {
  label: string;
  utilization: number;
  resetsAt: string | null;
}

interface CliUsageEntry {
  windows: CliUsageWindow[];
  error: string | null;
}

// ---------------------------------------------------------------------------
// Credential Readers
// ---------------------------------------------------------------------------
function readClaudeToken(): string | null {
  // macOS Keychain first (primary on macOS)
  if (process.platform === "darwin") {
    try {
      const raw = execFileSync("security", [
        "find-generic-password", "-s", "Claude Code-credentials", "-w",
      ], { timeout: 3000 }).toString().trim();
      const j = JSON.parse(raw);
      if (j?.claudeAiOauth?.accessToken) return j.claudeAiOauth.accessToken;
    } catch { /* ignore */ }
  }
  // Fallback: file on disk
  const home = os.homedir();
  try {
    const credsPath = path.join(home, ".claude", ".credentials.json");
    if (fs.existsSync(credsPath)) {
      const j = JSON.parse(fs.readFileSync(credsPath, "utf8"));
      if (j?.claudeAiOauth?.accessToken) return j.claudeAiOauth.accessToken;
    }
  } catch { /* ignore */ }
  return null;
}

function readCodexTokens(): { access_token: string; account_id: string } | null {
  try {
    const authPath = path.join(os.homedir(), ".codex", "auth.json");
    const j = JSON.parse(fs.readFileSync(authPath, "utf8"));
    if (j?.tokens?.access_token && j?.tokens?.account_id) {
      return { access_token: j.tokens.access_token, account_id: j.tokens.account_id };
    }
  } catch { /* ignore */ }
  return null;
}

// Gemini OAuth client credentials (public installed-app creds from Gemini CLI source;
// safe to embed per Google's installed app guidelines)
const GEMINI_OAUTH_CLIENT_ID = "681255809395-oo8ft2oprdrnp9e3aqf6av3hmdib135j.apps.googleusercontent.com";
const GEMINI_OAUTH_CLIENT_SECRET = "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";

interface GeminiCreds {
  access_token: string;
  refresh_token: string;
  expiry_date: number;
  source: "keychain" | "file";
}

function readGeminiCredsFromKeychain(): GeminiCreds | null {
  if (process.platform !== "darwin") return null;
  try {
    const raw = execFileSync("security", [
      "find-generic-password", "-s", "gemini-cli-oauth", "-a", "main-account", "-w",
    ], { timeout: 3000, stdio: ["pipe", "pipe", "pipe"] }).toString().trim();
    if (!raw) return null;
    const stored = JSON.parse(raw);
    if (!stored?.token?.accessToken) return null;
    return {
      access_token: stored.token.accessToken,
      refresh_token: stored.token.refreshToken ?? "",
      expiry_date: stored.token.expiresAt ?? 0,
      source: "keychain",
    };
  } catch { return null; }
}

function readGeminiCredsFromFile(): GeminiCreds | null {
  try {
    const p = path.join(os.homedir(), ".gemini", "oauth_creds.json");
    const j = JSON.parse(fs.readFileSync(p, "utf8"));
    if (j?.access_token) {
      return {
        access_token: j.access_token,
        refresh_token: j.refresh_token ?? "",
        expiry_date: j.expiry_date ?? 0,
        source: "file",
      };
    }
  } catch { /* ignore */ }
  return null;
}

function readGeminiCreds(): GeminiCreds | null {
  // macOS Keychain first, then file fallback
  return readGeminiCredsFromKeychain() ?? readGeminiCredsFromFile();
}

async function freshGeminiToken(): Promise<string | null> {
  const creds = readGeminiCreds();
  if (!creds) return null;
  // If not expired (5-minute buffer), reuse
  if (creds.expiry_date > Date.now() + 300_000) return creds.access_token;
  // Cannot refresh without refresh_token
  if (!creds.refresh_token) return creds.access_token; // try existing token anyway
  // Refresh using Gemini CLI's public OAuth client credentials
  try {
    const resp = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: GEMINI_OAUTH_CLIENT_ID,
        client_secret: GEMINI_OAUTH_CLIENT_SECRET,
        refresh_token: creds.refresh_token,
        grant_type: "refresh_token",
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return creds.access_token; // fall back to existing token
    const data = await resp.json() as { access_token?: string; expires_in?: number; refresh_token?: string };
    if (!data.access_token) return creds.access_token;
    // Persist refreshed token back to file (only if source was file)
    if (creds.source === "file") {
      try {
        const p = path.join(os.homedir(), ".gemini", "oauth_creds.json");
        const raw = JSON.parse(fs.readFileSync(p, "utf8"));
        raw.access_token = data.access_token;
        if (data.refresh_token) raw.refresh_token = data.refresh_token;
        raw.expiry_date = Date.now() + (data.expires_in ?? 3600) * 1000;
        fs.writeFileSync(p, JSON.stringify(raw, null, 2), { mode: 0o600 });
      } catch { /* ignore write failure */ }
    }
    return data.access_token;
  } catch { return creds.access_token; } // fall back to existing token on network error
}

// ---------------------------------------------------------------------------
// Provider Fetch Functions
// ---------------------------------------------------------------------------

// Claude: utilization is already 0-100 (percentage), NOT a fraction
async function fetchClaudeUsage(): Promise<CliUsageEntry> {
  const token = readClaudeToken();
  if (!token) return { windows: [], error: "unauthenticated" };
  try {
    const resp = await fetch("https://api.anthropic.com/api/oauth/usage", {
      headers: {
        "Authorization": `Bearer ${token}`,
        "anthropic-beta": "oauth-2025-04-20",
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return { windows: [], error: `http_${resp.status}` };
    const data = await resp.json() as Record<string, { utilization?: number; resets_at?: string } | null>;
    const windows: CliUsageWindow[] = [];
    const labelMap: Record<string, string> = {
      five_hour: "5-hour",
      seven_day: "7-day",
      seven_day_sonnet: "7-day Sonnet",
      seven_day_opus: "7-day Opus",
    };
    for (const [key, label] of Object.entries(labelMap)) {
      const entry = data[key];
      if (entry) {
        windows.push({
          label,
          utilization: Math.round(entry.utilization ?? 0) / 100, // API returns 0-100, normalize to 0-1
          resetsAt: entry.resets_at ?? null,
        });
      }
    }
    return { windows, error: null };
  } catch {
    return { windows: [], error: "unavailable" };
  }
}

// Codex: uses primary_window/secondary_window with used_percent (0-100), reset_at is Unix seconds
async function fetchCodexUsage(): Promise<CliUsageEntry> {
  const tokens = readCodexTokens();
  if (!tokens) return { windows: [], error: "unauthenticated" };
  try {
    const resp = await fetch("https://chatgpt.com/backend-api/wham/usage", {
      headers: {
        "Authorization": `Bearer ${tokens.access_token}`,
        "ChatGPT-Account-Id": tokens.account_id,
      },
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return { windows: [], error: `http_${resp.status}` };
    const data = await resp.json() as {
      rate_limit?: {
        primary_window?: { used_percent?: number; reset_at?: number };
        secondary_window?: { used_percent?: number; reset_at?: number };
      };
    };
    const windows: CliUsageWindow[] = [];
    if (data.rate_limit?.primary_window) {
      const pw = data.rate_limit.primary_window;
      windows.push({
        label: "5-hour",
        utilization: (pw.used_percent ?? 0) / 100,
        resetsAt: pw.reset_at ? new Date(pw.reset_at * 1000).toISOString() : null,
      });
    }
    if (data.rate_limit?.secondary_window) {
      const sw = data.rate_limit.secondary_window;
      windows.push({
        label: "7-day",
        utilization: (sw.used_percent ?? 0) / 100,
        resetsAt: sw.reset_at ? new Date(sw.reset_at * 1000).toISOString() : null,
      });
    }
    return { windows, error: null };
  } catch {
    return { windows: [], error: "unavailable" };
  }
}

// Gemini: requires project ID from loadCodeAssist, then POST retrieveUserQuota
let geminiProjectCache: { id: string; fetchedAt: number } | null = null;
const GEMINI_PROJECT_TTL = 300_000; // 5 minutes

async function getGeminiProjectId(token: string): Promise<string | null> {
  // 1. Environment variable (CI / custom setups)
  const envProject = process.env.GOOGLE_CLOUD_PROJECT || process.env.GOOGLE_CLOUD_PROJECT_ID;
  if (envProject) return envProject;

  // 2. Gemini CLI settings file
  try {
    const settingsPath = path.join(os.homedir(), ".gemini", "settings.json");
    const j = JSON.parse(fs.readFileSync(settingsPath, "utf8"));
    if (j?.cloudaicompanionProject) return j.cloudaicompanionProject;
  } catch { /* ignore */ }

  // 3. In-memory cache with TTL
  if (geminiProjectCache && Date.now() - geminiProjectCache.fetchedAt < GEMINI_PROJECT_TTL) {
    return geminiProjectCache.id;
  }

  // 4. Fetch via loadCodeAssist API (discovers project for the authenticated user)
  try {
    const resp = await fetch("https://cloudcode-pa.googleapis.com/v1internal:loadCodeAssist", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        metadata: { ideType: "GEMINI_CLI", platform: "PLATFORM_UNSPECIFIED", pluginType: "GEMINI" },
      }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return null;
    const data = await resp.json() as { cloudaicompanionProject?: string };
    if (data.cloudaicompanionProject) {
      geminiProjectCache = { id: data.cloudaicompanionProject, fetchedAt: Date.now() };
      return geminiProjectCache.id;
    }
  } catch { /* ignore */ }
  return null;
}

async function fetchGeminiUsage(): Promise<CliUsageEntry> {
  const token = await freshGeminiToken();
  if (!token) return { windows: [], error: "unauthenticated" };

  const projectId = await getGeminiProjectId(token);
  if (!projectId) return { windows: [], error: "unavailable" };

  try {
    const resp = await fetch("https://cloudcode-pa.googleapis.com/v1internal:retrieveUserQuota", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ project: projectId }),
      signal: AbortSignal.timeout(8000),
    });
    if (!resp.ok) return { windows: [], error: `http_${resp.status}` };
    const data = await resp.json() as {
      buckets?: Array<{ modelId?: string; remainingFraction?: number; resetTime?: string }>;
    };
    const windows: CliUsageWindow[] = [];
    if (data.buckets) {
      for (const b of data.buckets) {
        // Skip _vertex duplicates
        if (b.modelId?.endsWith("_vertex")) continue;
        windows.push({
          label: b.modelId ?? "Quota",
          utilization: Math.round((1 - (b.remainingFraction ?? 1)) * 100) / 100,
          resetsAt: b.resetTime ?? null,
        });
      }
    }
    return { windows, error: null };
  } catch {
    return { windows: [], error: "unavailable" };
  }
}

// ---------------------------------------------------------------------------
// CLI Tool Definitions
// ---------------------------------------------------------------------------

const CLI_TOOLS: CliToolDef[] = [
  {
    name: "claude",
    authHint: "Run: claude login",
    checkAuth: () => {
      const home = os.homedir();
      if (jsonHasKey(path.join(home, ".claude.json"), "oauthAccount")) return true;
      return fileExistsNonEmpty(path.join(home, ".claude", "auth.json"));
    },
  },
  {
    name: "codex",
    authHint: "Run: codex auth login",
    checkAuth: () => {
      const authPath = path.join(os.homedir(), ".codex", "auth.json");
      if (jsonHasKey(authPath, "OPENAI_API_KEY") || jsonHasKey(authPath, "tokens")) return true;
      if (process.env.OPENAI_API_KEY) return true;
      return false;
    },
  },
  {
    name: "gemini",
    authHint: "Run: gemini auth login",
    checkAuth: () => {
      // macOS Keychain
      if (readGeminiCredsFromKeychain()) return true;
      // File-based credentials
      if (jsonHasKey(path.join(os.homedir(), ".gemini", "oauth_creds.json"), "access_token")) return true;
      // Windows gcloud ADC fallback
      const appData = process.env.APPDATA;
      if (appData && jsonHasKey(path.join(appData, "gcloud", "application_default_credentials.json"), "client_id")) return true;
      return false;
    },
  },
  {
    name: "opencode",
    authHint: "Run: opencode auth",
    checkAuth: () => {
      const home = os.homedir();
      if (fileExistsNonEmpty(path.join(home, ".local", "share", "opencode", "auth.json"))) return true;
      const xdgData = process.env.XDG_DATA_HOME;
      if (xdgData && fileExistsNonEmpty(path.join(xdgData, "opencode", "auth.json"))) return true;
      if (process.platform === "darwin") {
        if (fileExistsNonEmpty(path.join(home, "Library", "Application Support", "opencode", "auth.json"))) return true;
      }
      return false;
    },
  },
];

function execWithTimeout(cmd: string, args: string[], timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = execFile(cmd, args, { timeout: timeoutMs }, (err, stdout) => {
      if (err) return reject(err);
      resolve(stdout.trim());
    });
    child.unref?.();
  });
}

async function detectCliTool(tool: CliToolDef): Promise<CliToolStatus> {
  const whichCmd = process.platform === "win32" ? "where" : "which";
  try {
    await execWithTimeout(whichCmd, [tool.name], 3000);
  } catch {
    return { installed: false, version: null, authenticated: false, authHint: tool.authHint };
  }

  let version: string | null = null;
  try {
    version = await execWithTimeout(tool.name, ["--version"], 3000);
    if (version.includes("\n")) version = version.split("\n")[0].trim();
  } catch { /* binary found but --version failed */ }

  const authenticated = tool.checkAuth();
  return { installed: true, version, authenticated, authHint: tool.authHint };
}

async function detectAllCli(): Promise<CliStatusResult> {
  const results = await Promise.all(CLI_TOOLS.map((t) => detectCliTool(t)));
  const out: CliStatusResult = {};
  for (let i = 0; i < CLI_TOOLS.length; i++) {
    out[CLI_TOOLS[i].name] = results[i];
  }
  return out;
}

// ---------------------------------------------------------------------------
// Helpers: progress timers, CEO notifications
// ---------------------------------------------------------------------------

// Track progress report timers so we can cancel them when tasks finish
const progressTimers = new Map<string, ReturnType<typeof setInterval>>();

// Cross-department sequential queue: when a cross-dept task finishes,
// trigger the next department in line (instead of spawning all simultaneously).
// Key: cross-dept task ID → callback to start next department
const crossDeptNextCallbacks = new Map<string, () => void>();

// Subtask delegation sequential queue: delegated task ID → callback to start next delegation
const subtaskDelegationCallbacks = new Map<string, () => void>();

// Map delegated task ID → original subtask ID for completion tracking
const delegatedTaskToSubtask = new Map<string, string>();

// Review consensus workflow state: task_id → current review round
const reviewRoundState = new Map<string, number>();
const reviewInFlight = new Set<string>();
const meetingPresenceUntil = new Map<string, number>();

function startProgressTimer(taskId: string, taskTitle: string, departmentId: string | null): void {
  // Send progress report every 5min for long-running tasks
  const timer = setInterval(() => {
    const currentTask = db.prepare("SELECT status FROM tasks WHERE id = ?").get(taskId) as { status: string } | undefined;
    if (!currentTask || currentTask.status !== "in_progress") {
      clearInterval(timer);
      progressTimers.delete(taskId);
      return;
    }
    const leader = findTeamLeader(departmentId);
    if (leader) {
      sendAgentMessage(
        leader,
        `대표님, '${taskTitle}' 작업 진행 중입니다. 현재 순조롭게 진행되고 있어요.`,
        "report",
        "all",
        null,
        taskId,
      );
    }
  }, 300_000);
  progressTimers.set(taskId, timer);
}

function stopProgressTimer(taskId: string): void {
  const timer = progressTimers.get(taskId);
  if (timer) {
    clearInterval(timer);
    progressTimers.delete(taskId);
  }
}

// ---------------------------------------------------------------------------
// Send CEO notification for all significant workflow events (B4)
// ---------------------------------------------------------------------------
function notifyCeo(content: string, taskId: string | null = null, messageType: string = "status_update"): void {
  const msgId = randomUUID();
  const t = nowMs();
  db.prepare(
    `INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
     VALUES (?, 'system', NULL, 'all', NULL, ?, ?, ?, ?)`
  ).run(msgId, content, messageType, taskId, t);
  broadcast("new_message", {
    id: msgId,
    sender_type: "system",
    content,
    message_type: messageType,
    task_id: taskId,
    created_at: t,
  });
}

function getLeadersByDepartmentIds(deptIds: string[]): AgentRow[] {
  const out: AgentRow[] = [];
  const seen = new Set<string>();
  for (const deptId of deptIds) {
    if (!deptId) continue;
    const leader = findTeamLeader(deptId);
    if (!leader || seen.has(leader.id)) continue;
    out.push(leader);
    seen.add(leader.id);
  }
  return out;
}

function getAllActiveTeamLeaders(): AgentRow[] {
  return db.prepare(`
    SELECT a.*
    FROM agents a
    LEFT JOIN departments d ON a.department_id = d.id
    WHERE a.role = 'team_leader' AND a.status != 'offline'
    ORDER BY d.sort_order ASC, a.name ASC
  `).all() as AgentRow[];
}

function getTaskRelatedDepartmentIds(taskId: string, fallbackDeptId: string | null): string[] {
  const task = db.prepare(
    "SELECT title, description, department_id FROM tasks WHERE id = ?"
  ).get(taskId) as { title: string; description: string | null; department_id: string | null } | undefined;

  const deptSet = new Set<string>();
  if (fallbackDeptId) deptSet.add(fallbackDeptId);
  if (task?.department_id) deptSet.add(task.department_id);

  const subtaskDepts = db.prepare(
    "SELECT DISTINCT target_department_id FROM subtasks WHERE task_id = ? AND target_department_id IS NOT NULL"
  ).all(taskId) as Array<{ target_department_id: string | null }>;
  for (const row of subtaskDepts) {
    if (row.target_department_id) deptSet.add(row.target_department_id);
  }

  const sourceText = `${task?.title ?? ""} ${task?.description ?? ""}`;
  for (const deptId of detectTargetDepartments(sourceText)) {
    deptSet.add(deptId);
  }

  return [...deptSet];
}

function getTaskReviewLeaders(
  taskId: string,
  fallbackDeptId: string | null,
  opts?: { minLeaders?: number; includePlanning?: boolean; fallbackAll?: boolean },
): AgentRow[] {
  const deptIds = getTaskRelatedDepartmentIds(taskId, fallbackDeptId);
  const leaders = getLeadersByDepartmentIds(deptIds);
  const includePlanning = opts?.includePlanning ?? true;
  const minLeaders = opts?.minLeaders ?? 2;
  const fallbackAll = opts?.fallbackAll ?? true;

  const seen = new Set(leaders.map((l) => l.id));
  if (includePlanning) {
    const planningLeader = findTeamLeader("planning");
    if (planningLeader && !seen.has(planningLeader.id)) {
      leaders.unshift(planningLeader);
      seen.add(planningLeader.id);
    }
  }

  // If related departments are not detectable, expand to all team leaders
  // so approval is based on real multi-party communication.
  if (fallbackAll && leaders.length < minLeaders) {
    for (const leader of getAllActiveTeamLeaders()) {
      if (seen.has(leader.id)) continue;
      leaders.push(leader);
      seen.add(leader.id);
    }
  }

  return leaders;
}

interface MeetingMinutesRow {
  id: string;
  task_id: string;
  meeting_type: "planned" | "review";
  round: number;
  title: string;
  status: "in_progress" | "completed" | "revision_requested" | "failed";
  started_at: number;
  completed_at: number | null;
  created_at: number;
}

interface MeetingMinuteEntryRow {
  id: number;
  meeting_id: string;
  seq: number;
  speaker_agent_id: string | null;
  speaker_name: string;
  department_name: string | null;
  role_label: string | null;
  message_type: string;
  content: string;
  created_at: number;
}

function beginMeetingMinutes(
  taskId: string,
  meetingType: "planned" | "review",
  round: number,
  title: string,
): string {
  const meetingId = randomUUID();
  const t = nowMs();
  db.prepare(`
    INSERT INTO meeting_minutes (id, task_id, meeting_type, round, title, status, started_at, created_at)
    VALUES (?, ?, ?, ?, ?, 'in_progress', ?, ?)
  `).run(meetingId, taskId, meetingType, round, title, t, t);
  return meetingId;
}

function appendMeetingMinuteEntry(
  meetingId: string,
  seq: number,
  agent: AgentRow,
  lang: string,
  messageType: string,
  content: string,
): void {
  const deptName = getDeptName(agent.department_id ?? "");
  const roleLabel = getRoleLabel(agent.role, lang as Lang);
  db.prepare(`
    INSERT INTO meeting_minute_entries
      (meeting_id, seq, speaker_agent_id, speaker_name, department_name, role_label, message_type, content, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    meetingId,
    seq,
    agent.id,
    getAgentDisplayName(agent, lang),
    deptName || null,
    roleLabel || null,
    messageType,
    content,
    nowMs(),
  );
}

function finishMeetingMinutes(
  meetingId: string,
  status: "completed" | "revision_requested" | "failed",
): void {
  db.prepare(
    "UPDATE meeting_minutes SET status = ?, completed_at = ? WHERE id = ?"
  ).run(status, nowMs(), meetingId);
}

function markAgentInMeeting(agentId: string, holdMs = 90_000): void {
  meetingPresenceUntil.set(agentId, nowMs() + holdMs);
  const row = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
  if (row?.status === "break") {
    db.prepare("UPDATE agents SET status = 'idle' WHERE id = ?").run(agentId);
    const updated = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId);
    broadcast("agent_status", updated);
  }
}

function isAgentInMeeting(agentId: string): boolean {
  const until = meetingPresenceUntil.get(agentId);
  if (!until) return false;
  if (until < nowMs()) {
    meetingPresenceUntil.delete(agentId);
    return false;
  }
  return true;
}

function callLeadersToCeoOffice(taskId: string, leaders: AgentRow[], phase: "kickoff" | "review"): void {
  leaders.slice(0, 6).forEach((leader, seatIndex) => {
    markAgentInMeeting(leader.id);
    broadcast("ceo_office_call", {
      from_agent_id: leader.id,
      seat_index: seatIndex,
      phase,
      task_id: taskId,
      action: "arrive",
    });
  });
}

function emitMeetingSpeech(
  agentId: string,
  seatIndex: number,
  phase: "kickoff" | "review",
  taskId: string,
  line: string,
): void {
  const preview = summarizeForMeetingBubble(line);
  broadcast("ceo_office_call", {
    from_agent_id: agentId,
    seat_index: seatIndex,
    phase,
    task_id: taskId,
    action: "speak",
    line: preview,
  });
}

function startReviewConsensusMeeting(
  taskId: string,
  taskTitle: string,
  departmentId: string | null,
  onApproved: () => void,
): void {
  if (reviewInFlight.has(taskId)) return;
  reviewInFlight.add(taskId);

  void (async () => {
    let meetingId: string | null = null;
    try {
      const leaders = getTaskReviewLeaders(taskId, departmentId);
      if (leaders.length === 0) {
        reviewInFlight.delete(taskId);
        onApproved();
        return;
      }

      const round = (reviewRoundState.get(taskId) ?? 0) + 1;
      reviewRoundState.set(taskId, round);

      const planningLeader = leaders.find((l) => l.department_id === "planning") ?? leaders[0];
      const otherLeaders = leaders.filter((l) => l.id !== planningLeader.id);
      let needsRevision = false;
      let reviseOwner: AgentRow | null = null;
      const seatIndexByAgent = new Map(leaders.slice(0, 6).map((leader, idx) => [leader.id, idx]));

      const taskCtx = db.prepare(
        "SELECT description, project_path FROM tasks WHERE id = ?"
      ).get(taskId) as { description: string | null; project_path: string | null } | undefined;
      const taskDescription = taskCtx?.description ?? null;
      const projectPath = resolveProjectPath({
        title: taskTitle,
        description: taskDescription,
        project_path: taskCtx?.project_path ?? null,
      });
      const lang = resolveLang(taskDescription ?? taskTitle);
      const transcript: MeetingTranscriptEntry[] = [];
      const oneShotOptions = { projectPath, timeoutMs: 35_000 };
      const wantsRevision = (content: string): boolean => (
        /보완|수정|보류|리스크|추가.?필요|hold|revise|revision|required|pending|risk|block|保留|修正|补充|暂缓/i
      ).test(content);
      meetingId = beginMeetingMinutes(taskId, "review", round, taskTitle);
      let minuteSeq = 1;

      const pushTranscript = (leader: AgentRow, content: string) => {
        transcript.push({
          speaker: getAgentDisplayName(leader, lang),
          department: getDeptName(leader.department_id ?? ""),
          role: getRoleLabel(leader.role, lang as Lang),
          content,
        });
      };
      const speak = (leader: AgentRow, messageType: string, receiverType: string, receiverId: string | null, content: string) => {
        sendAgentMessage(leader, content, messageType, receiverType, receiverId, taskId);
        const seatIndex = seatIndexByAgent.get(leader.id) ?? 0;
        emitMeetingSpeech(leader.id, seatIndex, "review", taskId, content);
        pushTranscript(leader, content);
        if (meetingId) {
          appendMeetingMinuteEntry(meetingId, minuteSeq++, leader, lang, messageType, content);
        }
      };

      callLeadersToCeoOffice(taskId, leaders, "review");
      notifyCeo(pickL(l(
        [`[CEO OFFICE] '${taskTitle}' 리뷰 라운드 ${round} 시작. 팀장 의견 수집 및 상호 승인 진행합니다.`],
        [`[CEO OFFICE] '${taskTitle}' review round ${round} started. Collecting team-lead feedback and mutual approvals.`],
        [`[CEO OFFICE] '${taskTitle}' レビューラウンド${round}を開始しました。チームリーダー意見収集と相互承認を進めます。`],
        [`[CEO OFFICE] 已开始'${taskTitle}'第${round}轮 Review，正在收集团队负责人意见并进行相互审批。`],
      ), lang), taskId);

      const openingPrompt = buildMeetingPrompt(planningLeader, {
        meetingType: "review",
        round,
        taskTitle,
        taskDescription,
        transcript,
        turnObjective: "Kick off the CEO office review discussion and ask each leader for concrete feedback.",
        stanceHint: "Facilitate discussion and commit to synthesizing the final review direction.",
        lang,
      });
      const openingRun = await runAgentOneShot(planningLeader, openingPrompt, oneShotOptions);
      const openingText = chooseSafeReply(openingRun, lang, "opening", planningLeader);
      speak(planningLeader, "chat", "all", null, openingText);
      await sleepMs(randomDelay(720, 1300));

      for (const leader of otherLeaders) {
        const feedbackPrompt = buildMeetingPrompt(leader, {
          meetingType: "review",
          round,
          taskTitle,
          taskDescription,
          transcript,
          turnObjective: "Provide concise review feedback and indicate whether risk is acceptable.",
          stanceHint: "If revision is needed, explicitly state what must be fixed before approval.",
          lang,
        });
        const feedbackRun = await runAgentOneShot(leader, feedbackPrompt, oneShotOptions);
        const feedbackText = chooseSafeReply(feedbackRun, lang, "feedback", leader);
        speak(leader, "chat", "agent", planningLeader.id, feedbackText);
        if (wantsRevision(feedbackText)) {
          needsRevision = true;
          if (!reviseOwner) reviseOwner = leader;
        }
        await sleepMs(randomDelay(650, 1180));
      }

      if (otherLeaders.length === 0) {
        const soloPrompt = buildMeetingPrompt(planningLeader, {
          meetingType: "review",
          round,
          taskTitle,
          taskDescription,
          transcript,
          turnObjective: "As the only reviewer, provide your single-party review conclusion.",
          stanceHint: "Summarize risks, dependencies, and confidence level in one concise message.",
          lang,
        });
        const soloRun = await runAgentOneShot(planningLeader, soloPrompt, oneShotOptions);
        const soloText = chooseSafeReply(soloRun, lang, "feedback", planningLeader);
        speak(planningLeader, "chat", "all", null, soloText);
        await sleepMs(randomDelay(620, 980));
      }

      const summaryPrompt = buildMeetingPrompt(planningLeader, {
        meetingType: "review",
        round,
        taskTitle,
        taskDescription,
        transcript,
        turnObjective: needsRevision
          ? "Synthesize feedback and announce revision plan before the next approval round."
          : "Synthesize feedback and request final all-leader approval.",
        stanceHint: needsRevision
          ? "State that revision items will be reflected and a follow-up approval round will run."
          : "State that the final review package is ready for immediate approval.",
        lang,
      });
      const summaryRun = await runAgentOneShot(planningLeader, summaryPrompt, oneShotOptions);
      const summaryText = chooseSafeReply(summaryRun, lang, "summary", planningLeader);
      speak(planningLeader, "report", "all", null, summaryText);
      await sleepMs(randomDelay(680, 1120));

      for (const leader of leaders) {
        const isReviseOwner = reviseOwner?.id === leader.id;
        const approvalPrompt = buildMeetingPrompt(leader, {
          meetingType: "review",
          round,
          taskTitle,
          taskDescription,
          transcript,
          turnObjective: "State your final approval decision for this review round.",
          stanceHint: !needsRevision
            ? "Approve the current review package if ready; otherwise hold approval with concrete revision items."
            : (isReviseOwner
              ? "Hold approval until your requested revision is reflected."
              : "Agree with conditional approval pending revision reflection."),
          lang,
        });
        const approvalRun = await runAgentOneShot(leader, approvalPrompt, oneShotOptions);
        const approvalText = chooseSafeReply(approvalRun, lang, "approval", leader);
        speak(leader, "status_update", "all", null, approvalText);
        if (wantsRevision(approvalText)) {
          needsRevision = true;
          if (!reviseOwner) reviseOwner = leader;
        }
        await sleepMs(randomDelay(420, 860));
      }

      await sleepMs(randomDelay(540, 920));

      if (needsRevision) {
        appendTaskLog(taskId, "system", `Review consensus round ${round}: revision requested`);
        notifyCeo(pickL(l(
          [`[CEO OFFICE] '${taskTitle}' 승인 보류. 기획팀이 보완안 반영 후 재승인 라운드를 시작합니다.`],
          [`[CEO OFFICE] '${taskTitle}' approval is on hold. Planning will reflect revisions and start a re-approval round.`],
          [`[CEO OFFICE] '${taskTitle}' は承認保留です。企画チームが修正反映後、再承認ラウンドを開始します。`],
          [`[CEO OFFICE] '${taskTitle}'审批暂缓。企划团队将完成修订后发起再次审批。`],
        ), lang), taskId);

        const now = nowMs();
        db.prepare("UPDATE tasks SET status = 'in_progress', updated_at = ? WHERE id = ?").run(now, taskId);
        broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));

        await sleepMs(2600);
        const t2 = nowMs();
        db.prepare("UPDATE tasks SET status = 'review', updated_at = ? WHERE id = ?").run(t2, taskId);
        appendTaskLog(taskId, "system", `Review consensus round ${round}: revision reflected, back to review`);
        broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
        notifyCeo(pickL(l(
          [`[CEO OFFICE] '${taskTitle}' 보완안 반영 완료. 재검토 및 재승인 라운드를 시작합니다.`],
          [`[CEO OFFICE] Revision updates for '${taskTitle}' are complete. Starting re-review and re-approval round.`],
          [`[CEO OFFICE] '${taskTitle}' の修正反映が完了しました。再レビュー・再承認ラウンドを開始します。`],
          [`[CEO OFFICE] '${taskTitle}'修订已完成，开始重新评审与再次审批。`],
        ), lang), taskId);
        if (meetingId) finishMeetingMinutes(meetingId, "revision_requested");
        reviewInFlight.delete(taskId);
        finishReview(taskId, taskTitle);
        return;
      }

      appendTaskLog(taskId, "system", `Review consensus round ${round}: all leaders approved`);
      notifyCeo(pickL(l(
        [`[CEO OFFICE] '${taskTitle}' 전원 Approved 완료. Done 단계로 진행합니다.`],
        [`[CEO OFFICE] '${taskTitle}' is approved by all leaders. Proceeding to Done.`],
        [`[CEO OFFICE] '${taskTitle}' は全リーダー承認済みです。Doneへ進みます。`],
        [`[CEO OFFICE] '${taskTitle}'已获全体负责人批准，进入 Done 阶段。`],
      ), lang), taskId);
      if (meetingId) finishMeetingMinutes(meetingId, "completed");
      reviewInFlight.delete(taskId);
      onApproved();
    } catch (err: any) {
      const msg = err?.message ? String(err.message) : String(err);
      appendTaskLog(taskId, "error", `Review consensus meeting error: ${msg}`);
      const errLang = resolveLang(taskTitle);
      notifyCeo(pickL(l(
        [`[CEO OFFICE] '${taskTitle}' 리뷰 라운드 처리 중 오류가 발생했습니다: ${msg}`],
        [`[CEO OFFICE] Error while processing review round for '${taskTitle}': ${msg}`],
        [`[CEO OFFICE] '${taskTitle}' のレビューラウンド処理中にエラーが発生しました: ${msg}`],
        [`[CEO OFFICE] 处理'${taskTitle}'评审轮次时发生错误：${msg}`],
      ), errLang), taskId);
      if (meetingId) finishMeetingMinutes(meetingId, "failed");
      reviewInFlight.delete(taskId);
    }
  })();
}

function startTaskExecutionForAgent(
  taskId: string,
  execAgent: AgentRow,
  deptId: string | null,
  deptName: string,
): void {
  const execName = execAgent.name_ko || execAgent.name;
  const t = nowMs();
  db.prepare(
    "UPDATE tasks SET status = 'in_progress', assigned_agent_id = ?, started_at = ?, updated_at = ? WHERE id = ?"
  ).run(execAgent.id, t, t, taskId);
  db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(taskId, execAgent.id);
  appendTaskLog(taskId, "system", `${execName} started (approved)`);

  broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
  broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(execAgent.id));

  const provider = execAgent.cli_provider || "claude";
  if (!["claude", "codex", "gemini", "opencode"].includes(provider)) return;

  const taskData = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
    title: string;
    description: string | null;
    project_path: string | null;
  } | undefined;
  if (!taskData) return;

  const projPath = resolveProjectPath(taskData);
  const logFilePath = path.join(logsDir, `${taskId}.log`);
  const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[execAgent.role] || execAgent.role;
  const deptConstraint = deptId ? getDeptRoleConstraint(deptId, deptName) : "";
  const conversationCtx = getRecentConversationContext(execAgent.id);
  const spawnPrompt = [
    `[Task] ${taskData.title}`,
    taskData.description ? `\n${taskData.description}` : "",
    conversationCtx,
    `\n---`,
    `Agent: ${execAgent.name} (${roleLabel}, ${deptName})`,
    execAgent.personality ? `Personality: ${execAgent.personality}` : "",
    deptConstraint,
    `Please complete the task above thoroughly. Use the conversation context above if relevant.`,
  ].filter(Boolean).join("\n");

  appendTaskLog(taskId, "system", `RUN start (agent=${execAgent.name}, provider=${provider})`);
  const modelConfig = getProviderModelConfig();
  const modelForProvider = modelConfig[provider]?.model || undefined;
  const reasoningLevel = modelConfig[provider]?.reasoningLevel || undefined;
  const child = spawnCliAgent(taskId, provider, spawnPrompt, projPath, logFilePath, modelForProvider, reasoningLevel);
  child.on("close", (code) => {
    handleTaskRunComplete(taskId, code ?? 1);
  });

  const lang = resolveLang(taskData.description ?? taskData.title);
  notifyCeo(pickL(l(
    [`${execName}가 '${taskData.title}' 작업을 시작했습니다.`],
    [`${execName} started work on '${taskData.title}'.`],
    [`${execName}が '${taskData.title}' の作業を開始しました。`],
    [`${execName} 已开始处理 '${taskData.title}'。`],
  ), lang), taskId);
  startProgressTimer(taskId, taskData.title, deptId);
}

function startPlannedApprovalMeeting(
  taskId: string,
  taskTitle: string,
  departmentId: string | null,
  onApproved: () => void,
): void {
  const lockKey = `planned:${taskId}`;
  if (reviewInFlight.has(lockKey)) return;
  reviewInFlight.add(lockKey);

  void (async () => {
    let meetingId: string | null = null;
    try {
      const leaders = getTaskReviewLeaders(taskId, departmentId);
      if (leaders.length === 0) {
        reviewInFlight.delete(lockKey);
        onApproved();
        return;
      }

      const round = (reviewRoundState.get(lockKey) ?? 0) + 1;
      reviewRoundState.set(lockKey, round);

      const planningLeader = leaders.find((l) => l.department_id === "planning") ?? leaders[0];
      const otherLeaders = leaders.filter((l) => l.id !== planningLeader.id);
      let needsRevision = false;
      let reviseOwner: AgentRow | null = null;
      const seatIndexByAgent = new Map(leaders.slice(0, 6).map((leader, idx) => [leader.id, idx]));

      const taskCtx = db.prepare(
        "SELECT description, project_path FROM tasks WHERE id = ?"
      ).get(taskId) as { description: string | null; project_path: string | null } | undefined;
      const taskDescription = taskCtx?.description ?? null;
      const projectPath = resolveProjectPath({
        title: taskTitle,
        description: taskDescription,
        project_path: taskCtx?.project_path ?? null,
      });
      const lang = resolveLang(taskDescription ?? taskTitle);
      const transcript: MeetingTranscriptEntry[] = [];
      const oneShotOptions = { projectPath, timeoutMs: 35_000 };
      const wantsRevision = (content: string): boolean => (
        /보완|수정|보류|리스크|추가.?필요|hold|revise|revision|required|pending|risk|block|保留|修正|补充|暂缓/i
      ).test(content);
      meetingId = beginMeetingMinutes(taskId, "planned", round, taskTitle);
      let minuteSeq = 1;

      const pushTranscript = (leader: AgentRow, content: string) => {
        transcript.push({
          speaker: getAgentDisplayName(leader, lang),
          department: getDeptName(leader.department_id ?? ""),
          role: getRoleLabel(leader.role, lang as Lang),
          content,
        });
      };
      const speak = (leader: AgentRow, messageType: string, receiverType: string, receiverId: string | null, content: string) => {
        sendAgentMessage(leader, content, messageType, receiverType, receiverId, taskId);
        const seatIndex = seatIndexByAgent.get(leader.id) ?? 0;
        emitMeetingSpeech(leader.id, seatIndex, "kickoff", taskId, content);
        pushTranscript(leader, content);
        if (meetingId) {
          appendMeetingMinuteEntry(meetingId, minuteSeq++, leader, lang, messageType, content);
        }
      };

      callLeadersToCeoOffice(taskId, leaders, "kickoff");
      notifyCeo(pickL(l(
        [`[CEO OFFICE] '${taskTitle}' Planned 승인 라운드 ${round} 시작. 부서별 의견 수집 후 전원 Approved 확인합니다.`],
        [`[CEO OFFICE] '${taskTitle}' planned approval round ${round} started. Collecting department feedback and confirming all approvals.`],
        [`[CEO OFFICE] '${taskTitle}' のPlanned承認ラウンド${round}を開始。部門別意見を集め、全員承認を確認します。`],
        [`[CEO OFFICE] 已开始'${taskTitle}'第${round}轮 Planned 审批，正在收集各部门意见并确认全员批准。`],
      ), lang), taskId);

      const openingPrompt = buildMeetingPrompt(planningLeader, {
        meetingType: "planned",
        round,
        taskTitle,
        taskDescription,
        transcript,
        turnObjective: "Open the kickoff approval meeting and request concise pre-start feedback from each team leader.",
        stanceHint: "You are facilitating and will synthesize all inputs into one launch plan.",
        lang,
      });
      const openingRun = await runAgentOneShot(planningLeader, openingPrompt, oneShotOptions);
      const openingText = chooseSafeReply(openingRun, lang, "opening", planningLeader);
      speak(planningLeader, "chat", "all", null, openingText);
      await sleepMs(randomDelay(700, 1260));

      for (const leader of otherLeaders) {
        const feedbackPrompt = buildMeetingPrompt(leader, {
          meetingType: "planned",
          round,
          taskTitle,
          taskDescription,
          transcript,
          turnObjective: "Share concise kickoff readiness feedback and dependency risk level.",
          stanceHint: "If revision is needed, explicitly state what must be fixed before approval.",
          lang,
        });
        const feedbackRun = await runAgentOneShot(leader, feedbackPrompt, oneShotOptions);
        const feedbackText = chooseSafeReply(feedbackRun, lang, "feedback", leader);
        speak(leader, "chat", "agent", planningLeader.id, feedbackText);
        if (wantsRevision(feedbackText)) {
          needsRevision = true;
          if (!reviseOwner) reviseOwner = leader;
        }
        await sleepMs(randomDelay(620, 1080));
      }

      const summaryPrompt = buildMeetingPrompt(planningLeader, {
        meetingType: "planned",
        round,
        taskTitle,
        taskDescription,
        transcript,
        turnObjective: needsRevision
          ? "Summarize revision items and announce a follow-up approval round."
          : "Summarize aligned kickoff plan and ask for final approval.",
        stanceHint: needsRevision
          ? "Clearly state supplement reflection first, then re-approval."
          : "Clearly state final kickoff plan is ready now.",
        lang,
      });
      const summaryRun = await runAgentOneShot(planningLeader, summaryPrompt, oneShotOptions);
      const summaryText = chooseSafeReply(summaryRun, lang, "summary", planningLeader);
      speak(planningLeader, "report", "all", null, summaryText);
      await sleepMs(randomDelay(640, 1120));

      for (const leader of leaders) {
        const isReviseOwner = reviseOwner?.id === leader.id;
        const approvalPrompt = buildMeetingPrompt(leader, {
          meetingType: "planned",
          round,
          taskTitle,
          taskDescription,
          transcript,
          turnObjective: "State your final kickoff approval decision for this round.",
          stanceHint: !needsRevision
            ? "Approve kickoff plan now if ready; otherwise hold approval with concrete revision items."
            : (isReviseOwner
              ? "Hold approval until supplement reflection is verified."
              : "Agree with conditional approval pending supplement reflection."),
          lang,
        });
        const approvalRun = await runAgentOneShot(leader, approvalPrompt, oneShotOptions);
        const approvalText = chooseSafeReply(approvalRun, lang, "approval", leader);
        speak(leader, "status_update", "all", null, approvalText);
        if (wantsRevision(approvalText)) {
          needsRevision = true;
          if (!reviseOwner) reviseOwner = leader;
        }
        await sleepMs(randomDelay(420, 840));
      }

      await sleepMs(randomDelay(520, 900));

      if (needsRevision) {
        appendTaskLog(taskId, "system", `Planned approval round ${round}: revision requested`);
        notifyCeo(pickL(l(
          [`[CEO OFFICE] '${taskTitle}' Planned 승인 보류. 보완안 반영 후 재승인 라운드를 진행합니다.`],
          [`[CEO OFFICE] '${taskTitle}' planned approval is on hold. Revisions will be applied and a re-approval round will follow.`],
          [`[CEO OFFICE] '${taskTitle}' のPlanned承認は保留です。修正反映後に再承認ラウンドを行います。`],
          [`[CEO OFFICE] '${taskTitle}'的 Planned 审批已暂缓，修订后将进入再次审批。`],
        ), lang), taskId);
        if (meetingId) finishMeetingMinutes(meetingId, "revision_requested");
        reviewInFlight.delete(lockKey);
        setTimeout(() => startPlannedApprovalMeeting(taskId, taskTitle, departmentId, onApproved), 2200);
        return;
      }

      appendTaskLog(taskId, "system", `Planned approval round ${round}: all leaders approved`);
      notifyCeo(pickL(l(
        [`[CEO OFFICE] '${taskTitle}' Planned 단계 전원 Approved 완료. In Progress로 전환합니다.`],
        [`[CEO OFFICE] '${taskTitle}' is approved by all leaders at Planned stage. Moving to In Progress.`],
        [`[CEO OFFICE] '${taskTitle}' はPlanned段階で全員承認済みです。In Progressへ移行します。`],
        [`[CEO OFFICE] '${taskTitle}'在 Planned 阶段已获全员批准，转为 In Progress。`],
      ), lang), taskId);
      if (meetingId) finishMeetingMinutes(meetingId, "completed");
      reviewRoundState.delete(lockKey);
      reviewInFlight.delete(lockKey);
      onApproved();
    } catch (err: any) {
      const msg = err?.message ? String(err.message) : String(err);
      appendTaskLog(taskId, "error", `Planned approval meeting error: ${msg}`);
      const errLang = resolveLang(taskTitle);
      notifyCeo(pickL(l(
        [`[CEO OFFICE] '${taskTitle}' Planned 승인 회의 처리 중 오류가 발생했습니다: ${msg}`],
        [`[CEO OFFICE] Error while processing planned approval meeting for '${taskTitle}': ${msg}`],
        [`[CEO OFFICE] '${taskTitle}' のPlanned承認会議処理中にエラーが発生しました: ${msg}`],
        [`[CEO OFFICE] 处理'${taskTitle}'的 Planned 审批会议时发生错误：${msg}`],
      ), errLang), taskId);
      if (meetingId) finishMeetingMinutes(meetingId, "failed");
      reviewInFlight.delete(lockKey);
    }
  })();
}

// ---------------------------------------------------------------------------
// Run completion handler — enhanced with review flow + CEO reporting
// ---------------------------------------------------------------------------
function handleTaskRunComplete(taskId: string, exitCode: number): void {
  activeProcesses.delete(taskId);
  stopProgressTimer(taskId);

  // Get latest task snapshot early for stop/delete race handling.
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
    assigned_agent_id: string | null;
    department_id: string | null;
    title: string;
    description: string | null;
    status: string;
  } | undefined;
  const stopRequested = stopRequestedTasks.has(taskId);
  stopRequestedTasks.delete(taskId);

  // If task was stopped/deleted or no longer in-progress, ignore late close events.
  if (!task || stopRequested || task.status !== "in_progress") {
    if (task) {
      appendTaskLog(
        taskId,
        "system",
        `RUN completion ignored (status=${task.status}, exit=${exitCode}, stop_requested=${stopRequested ? "yes" : "no"})`,
      );
    }
    crossDeptNextCallbacks.delete(taskId);
    subtaskDelegationCallbacks.delete(taskId);
    reviewInFlight.delete(taskId);
    reviewInFlight.delete(`planned:${taskId}`);
    reviewRoundState.delete(taskId);
    reviewRoundState.delete(`planned:${taskId}`);
    return;
  }

  // Clean up Codex thread→subtask mappings for this task's subtasks
  for (const [tid, itemId] of codexThreadToSubtask) {
    const row = db.prepare("SELECT id FROM subtasks WHERE cli_tool_use_id = ? AND task_id = ?").get(itemId, taskId);
    if (row) codexThreadToSubtask.delete(tid);
  }

  const t = nowMs();
  const logKind = exitCode === 0 ? "completed" : "failed";

  appendTaskLog(taskId, "system", `RUN ${logKind} (exit code: ${exitCode})`);

  // Read log file for result
  const logPath = path.join(logsDir, `${taskId}.log`);
  let result: string | null = null;
  try {
    if (fs.existsSync(logPath)) {
      const raw = fs.readFileSync(logPath, "utf8");
      result = raw.slice(-2000);
    }
  } catch { /* ignore */ }

  if (result) {
    db.prepare("UPDATE tasks SET result = ? WHERE id = ?").run(result, taskId);
  }

  // Auto-complete own-department subtasks on CLI success; foreign ones get delegated
  if (exitCode === 0) {
    const pendingSubtasks = db.prepare(
      "SELECT id, target_department_id FROM subtasks WHERE task_id = ? AND status != 'done'"
    ).all(taskId) as Array<{ id: string; target_department_id: string | null }>;
    if (pendingSubtasks.length > 0) {
      const now = nowMs();
      for (const sub of pendingSubtasks) {
        // Only auto-complete subtasks without a foreign department target
        if (!sub.target_department_id) {
          db.prepare(
            "UPDATE subtasks SET status = 'done', completed_at = ? WHERE id = ?"
          ).run(now, sub.id);
          const updated = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(sub.id);
          broadcast("subtask_update", updated);
        }
      }
    }
    // Trigger delegation for foreign-department subtasks
    processSubtaskDelegations(taskId);
  }

  // Update agent status back to idle
  if (task?.assigned_agent_id) {
    db.prepare(
      "UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?"
    ).run(task.assigned_agent_id);

    if (exitCode === 0) {
      db.prepare(
        "UPDATE agents SET stats_tasks_done = stats_tasks_done + 1, stats_xp = stats_xp + 10 WHERE id = ?"
      ).run(task.assigned_agent_id);
    }

    const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(task.assigned_agent_id) as Record<string, unknown> | undefined;
    broadcast("agent_status", agent);
  }

  if (exitCode === 0) {
    // ── SUCCESS: Move to 'review' for team leader check ──
    db.prepare(
      "UPDATE tasks SET status = 'review', updated_at = ? WHERE id = ?"
    ).run(t, taskId);

    appendTaskLog(taskId, "system", "Status → review (team leader review pending)");

    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
    broadcast("task_update", updatedTask);

    // Notify: task entering review
    if (task) {
      const lang = resolveLang(task.description ?? task.title);
      const leader = findTeamLeader(task.department_id);
      const leaderName = leader
        ? getAgentDisplayName(leader, lang)
        : pickL(l(["팀장"], ["Team Lead"], ["チームリーダー"], ["组长"]), lang);
      notifyCeo(pickL(l(
        [`${leaderName}이(가) '${task.title}' 결과를 검토 중입니다.`],
        [`${leaderName} is reviewing the result for '${task.title}'.`],
        [`${leaderName}が '${task.title}' の成果をレビュー中です。`],
        [`${leaderName} 正在审核 '${task.title}' 的结果。`],
      ), lang), taskId);
    }

    // Schedule team leader review message (2-3s delay)
    setTimeout(() => {
      if (!task) return;
      const leader = findTeamLeader(task.department_id);
      if (!leader) {
        // No team leader — auto-approve
        finishReview(taskId, task.title);
        return;
      }

      // Read the task result and pretty-parse it for the report
      let reportBody = "";
      try {
        const logFile = path.join(logsDir, `${taskId}.log`);
        if (fs.existsSync(logFile)) {
          const raw = fs.readFileSync(logFile, "utf8");
          const pretty = prettyStreamJson(raw);
          // Take the last ~500 chars of the pretty output as summary
          reportBody = pretty.length > 500 ? "..." + pretty.slice(-500) : pretty;
        }
      } catch { /* ignore */ }

      // If worktree exists, include diff summary in the report
      const wtInfo = taskWorktrees.get(taskId);
      let diffSummary = "";
      if (wtInfo) {
        diffSummary = getWorktreeDiffSummary(wtInfo.projectPath, taskId);
        if (diffSummary && diffSummary !== "변경사항 없음") {
          appendTaskLog(taskId, "system", `Worktree diff summary:\n${diffSummary}`);
        }
      }

      // Team leader sends completion report with actual result content + diff
      let reportContent = reportBody
        ? `대표님, '${task.title}' 업무 완료 보고드립니다.\n\n📋 결과:\n${reportBody}`
        : `대표님, '${task.title}' 업무 완료 보고드립니다. 작업이 성공적으로 마무리되었습니다.`;

      if (diffSummary && diffSummary !== "변경사항 없음" && diffSummary !== "diff 조회 실패") {
        reportContent += `\n\n📝 변경사항 (branch: ${wtInfo?.branchName}):\n${diffSummary}`;
      }

      sendAgentMessage(
        leader,
        reportContent,
        "report",
        "all",
        null,
        taskId,
      );

      // After another 2-3s: team leader approves → move to done
      setTimeout(() => {
        finishReview(taskId, task.title);
      }, 2500);
    }, 2500);

  } else {
    // ── FAILURE: Reset to inbox, team leader reports failure ──
    db.prepare(
      "UPDATE tasks SET status = 'inbox', updated_at = ? WHERE id = ?"
    ).run(t, taskId);

    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
    broadcast("task_update", updatedTask);

    // Clean up worktree on failure — failed work shouldn't persist
    const failWtInfo = taskWorktrees.get(taskId);
    if (failWtInfo) {
      cleanupWorktree(failWtInfo.projectPath, taskId);
      appendTaskLog(taskId, "system", "Worktree cleaned up (task failed)");
    }

    if (task) {
      const leader = findTeamLeader(task.department_id);
      if (leader) {
        setTimeout(() => {
          // Read error output for failure report
          let errorBody = "";
          try {
            const logFile = path.join(logsDir, `${taskId}.log`);
            if (fs.existsSync(logFile)) {
              const raw = fs.readFileSync(logFile, "utf8");
              const pretty = prettyStreamJson(raw);
              errorBody = pretty.length > 300 ? "..." + pretty.slice(-300) : pretty;
            }
          } catch { /* ignore */ }

          const failContent = errorBody
            ? `대표님, '${task.title}' 작업에 문제가 발생했습니다 (종료코드: ${exitCode}).\n\n❌ 오류 내용:\n${errorBody}\n\n재배정하거나 업무 내용을 수정한 후 다시 시도해주세요.`
            : `대표님, '${task.title}' 작업에 문제가 발생했습니다 (종료코드: ${exitCode}). 에이전트를 재배정하거나 업무 내용을 수정한 후 다시 시도해주세요.`;

          sendAgentMessage(
            leader,
            failContent,
            "report",
            "all",
            null,
            taskId,
          );
        }, 1500);
      }
      notifyCeo(`'${task.title}' 작업 실패 (exit code: ${exitCode}).`, taskId);
    }

    // Even on failure, trigger next cross-dept cooperation so the queue doesn't stall
    const nextCallback = crossDeptNextCallbacks.get(taskId);
    if (nextCallback) {
      crossDeptNextCallbacks.delete(taskId);
      setTimeout(nextCallback, 3000);
    }

    // Even on failure, trigger next subtask delegation so the queue doesn't stall
    const subtaskNext = subtaskDelegationCallbacks.get(taskId);
    if (subtaskNext) {
      subtaskDelegationCallbacks.delete(taskId);
      setTimeout(subtaskNext, 3000);
    }
  }
}

// Move a reviewed task to 'done'
function finishReview(taskId: string, taskTitle: string): void {
  const lang = resolveLang(taskTitle);
  const currentTask = db.prepare("SELECT status, department_id FROM tasks WHERE id = ?").get(taskId) as { status: string; department_id: string | null } | undefined;
  if (!currentTask || currentTask.status !== "review") return; // Already moved or cancelled

  const remainingSubtasks = db.prepare(
    "SELECT COUNT(*) as cnt FROM subtasks WHERE task_id = ? AND status != 'done'"
  ).get(taskId) as { cnt: number };
  if (remainingSubtasks.cnt > 0) {
    notifyCeo(pickL(l(
      [`'${taskTitle}' 는 아직 ${remainingSubtasks.cnt}개 서브태스크가 남아 있어 Review 단계에서 대기합니다.`],
      [`'${taskTitle}' is waiting in Review because ${remainingSubtasks.cnt} subtasks are still unfinished.`],
      [`'${taskTitle}' は未完了サブタスクが${remainingSubtasks.cnt}件あるため、Reviewで待機しています。`],
      [`'${taskTitle}' 仍有 ${remainingSubtasks.cnt} 个 SubTask 未完成，当前在 Review 阶段等待。`],
    ), lang), taskId);
    appendTaskLog(taskId, "system", `Review hold: waiting for ${remainingSubtasks.cnt} unfinished subtasks`);
    return;
  }

  startReviewConsensusMeeting(taskId, taskTitle, currentTask.department_id, () => {
    const t = nowMs();
    const latestTask = db.prepare("SELECT status, department_id FROM tasks WHERE id = ?").get(taskId) as { status: string; department_id: string | null } | undefined;
    if (!latestTask || latestTask.status !== "review") return;

    // If task has a worktree, merge the branch back before marking done
    const wtInfo = taskWorktrees.get(taskId);
    let mergeNote = "";
    if (wtInfo) {
      const mergeResult = mergeWorktree(wtInfo.projectPath, taskId);

      if (mergeResult.success) {
        appendTaskLog(taskId, "system", `Git merge 완료: ${mergeResult.message}`);
        cleanupWorktree(wtInfo.projectPath, taskId);
        appendTaskLog(taskId, "system", "Worktree cleaned up after successful merge");
        mergeNote = " (병합 완료)";
      } else {
        appendTaskLog(taskId, "system", `Git merge 실패: ${mergeResult.message}`);

        const conflictLeader = findTeamLeader(latestTask.department_id);
        const conflictLeaderName = conflictLeader?.name_ko || conflictLeader?.name || "팀장";
        const conflictFiles = mergeResult.conflicts?.length
          ? `\n충돌 파일: ${mergeResult.conflicts.join(", ")}`
          : "";
        notifyCeo(
          `${conflictLeaderName}: '${taskTitle}' 병합 중 충돌이 발생했습니다. 수동 해결이 필요합니다.${conflictFiles}\n` +
          `브랜치: ${wtInfo.branchName}`,
          taskId,
        );

        mergeNote = " (병합 충돌 - 수동 해결 필요)";
      }
    }

    db.prepare(
      "UPDATE tasks SET status = 'done', completed_at = ?, updated_at = ? WHERE id = ?"
    ).run(t, t, taskId);

    appendTaskLog(taskId, "system", "Status → done (all leaders approved)");

    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
    broadcast("task_update", updatedTask);

    refreshCliUsageData().then((usage) => broadcast("cli_usage_update", usage)).catch(() => {});

    const leader = findTeamLeader(latestTask.department_id);
    const leaderName = leader
      ? getAgentDisplayName(leader, lang)
      : pickL(l(["팀장"], ["Team Lead"], ["チームリーダー"], ["组长"]), lang);
    notifyCeo(pickL(l(
      [`${leaderName}: '${taskTitle}' 최종 승인 완료 보고드립니다.${mergeNote}`],
      [`${leaderName}: Final approval completed for '${taskTitle}'.${mergeNote}`],
      [`${leaderName}: '${taskTitle}' の最終承認が完了しました。${mergeNote}`],
      [`${leaderName}：'${taskTitle}' 最终审批已完成。${mergeNote}`],
    ), lang), taskId);

    reviewRoundState.delete(taskId);
    reviewInFlight.delete(taskId);

    const nextCallback = crossDeptNextCallbacks.get(taskId);
    if (nextCallback) {
      crossDeptNextCallbacks.delete(taskId);
      nextCallback();
    }

    const subtaskNext = subtaskDelegationCallbacks.get(taskId);
    if (subtaskNext) {
      subtaskDelegationCallbacks.delete(taskId);
      subtaskNext();
    }
  });
}

// ===========================================================================
// API ENDPOINTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------
const buildHealthPayload = () => ({
  ok: true,
  version: PKG_VERSION,
  app: "CLImpire",
  dbPath,
});

app.get("/health", (_req, res) => res.json(buildHealthPayload()));
app.get("/healthz", (_req, res) => res.json(buildHealthPayload()));
app.get("/api/health", (_req, res) => res.json(buildHealthPayload()));

// ---------------------------------------------------------------------------
// Departments
// ---------------------------------------------------------------------------
app.get("/api/departments", (_req, res) => {
  const departments = db.prepare(`
    SELECT d.*,
      (SELECT COUNT(*) FROM agents a WHERE a.department_id = d.id) AS agent_count
    FROM departments d
    ORDER BY d.sort_order ASC
  `).all();
  res.json({ departments });
});

app.get("/api/departments/:id", (req, res) => {
  const id = String(req.params.id);
  const department = db.prepare("SELECT * FROM departments WHERE id = ?").get(id);
  if (!department) return res.status(404).json({ error: "not_found" });

  const agents = db.prepare("SELECT * FROM agents WHERE department_id = ? ORDER BY role, name").all(id);
  res.json({ department, agents });
});

// ---------------------------------------------------------------------------
// Agents
// ---------------------------------------------------------------------------
app.get("/api/agents", (_req, res) => {
  const agents = db.prepare(`
    SELECT a.*, d.name AS department_name, d.name_ko AS department_name_ko, d.color AS department_color
    FROM agents a
    LEFT JOIN departments d ON a.department_id = d.id
    ORDER BY a.department_id, a.role, a.name
  `).all();
  res.json({ agents });
});

app.get("/api/agents/:id", (req, res) => {
  const id = String(req.params.id);
  const agent = db.prepare(`
    SELECT a.*, d.name AS department_name, d.name_ko AS department_name_ko, d.color AS department_color
    FROM agents a
    LEFT JOIN departments d ON a.department_id = d.id
    WHERE a.id = ?
  `).get(id);
  if (!agent) return res.status(404).json({ error: "not_found" });

  // Include recent tasks
  const recentTasks = db.prepare(
    "SELECT * FROM tasks WHERE assigned_agent_id = ? ORDER BY updated_at DESC LIMIT 10"
  ).all(id);

  res.json({ agent, recent_tasks: recentTasks });
});

app.patch("/api/agents/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  if (!existing) return res.status(404).json({ error: "not_found" });

  const body = req.body ?? {};
  const allowedFields = [
    "name", "name_ko", "department_id", "role", "cli_provider",
    "avatar_emoji", "personality", "status", "current_task_id",
  ];

  const updates: string[] = [];
  const params: unknown[] = [];

  for (const field of allowedFields) {
    if (field in body) {
      updates.push(`${field} = ?`);
      params.push(body[field]);
    }
  }

  if (updates.length === 0) {
    return res.status(400).json({ error: "no_fields_to_update" });
  }

  params.push(id);
  db.prepare(`UPDATE agents SET ${updates.join(", ")} WHERE id = ?`).run(...params);

  const updated = db.prepare("SELECT * FROM agents WHERE id = ?").get(id);
  broadcast("agent_status", updated);
  res.json({ ok: true, agent: updated });
});

app.post("/api/agents/:id/spawn", (req, res) => {
  const id = String(req.params.id);
  const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(id) as {
    id: string;
    name: string;
    cli_provider: string | null;
    current_task_id: string | null;
    status: string;
  } | undefined;
  if (!agent) return res.status(404).json({ error: "not_found" });

  const provider = agent.cli_provider || "claude";
  if (!["claude", "codex", "gemini", "opencode", "copilot", "antigravity"].includes(provider)) {
    return res.status(400).json({ error: "unsupported_provider", provider });
  }

  const taskId = agent.current_task_id;
  if (!taskId) {
    return res.status(400).json({ error: "no_task_assigned", message: "Assign a task to this agent first." });
  }

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
    id: string;
    title: string;
    description: string | null;
    project_path: string | null;
  } | undefined;
  if (!task) {
    return res.status(400).json({ error: "task_not_found" });
  }

  const projectPath = task.project_path || process.cwd();
  const logPath = path.join(logsDir, `${taskId}.log`);

  const prompt = `${task.title}\n\n${task.description || ""}`;

  appendTaskLog(taskId, "system", `RUN start (agent=${agent.name}, provider=${provider})`);

  const spawnModelConfig = getProviderModelConfig();
  const spawnModel = spawnModelConfig[provider]?.model || undefined;
  const spawnReasoningLevel = spawnModelConfig[provider]?.reasoningLevel || undefined;

  if (provider === "copilot" || provider === "antigravity") {
    const controller = new AbortController();
    const fakePid = -(++httpAgentCounter);
    // Update agent status before launching
    db.prepare("UPDATE agents SET status = 'working' WHERE id = ?").run(id);
    db.prepare("UPDATE tasks SET status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?")
      .run(nowMs(), nowMs(), taskId);
    const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(id);
    broadcast("agent_status", updatedAgent);
    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
    launchHttpAgent(taskId, provider, prompt, projectPath, logPath, controller, fakePid);
    return res.json({ ok: true, pid: fakePid, logPath, cwd: projectPath });
  }

  const child = spawnCliAgent(taskId, provider, prompt, projectPath, logPath, spawnModel, spawnReasoningLevel);

  child.on("close", (code) => {
    handleTaskRunComplete(taskId, code ?? 1);
  });

  // Update agent status
  db.prepare("UPDATE agents SET status = 'working' WHERE id = ?").run(id);
  db.prepare("UPDATE tasks SET status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?")
    .run(nowMs(), nowMs(), taskId);

  const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(id);
  broadcast("agent_status", updatedAgent);
  broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));

  res.json({ ok: true, pid: child.pid ?? null, logPath, cwd: projectPath });
});

// ---------------------------------------------------------------------------
// Tasks
// ---------------------------------------------------------------------------
app.get("/api/tasks", (req, res) => {
  const statusFilter = firstQueryValue(req.query.status);
  const deptFilter = firstQueryValue(req.query.department_id);
  const agentFilter = firstQueryValue(req.query.agent_id);

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (statusFilter) {
    conditions.push("t.status = ?");
    params.push(statusFilter);
  }
  if (deptFilter) {
    conditions.push("t.department_id = ?");
    params.push(deptFilter);
  }
  if (agentFilter) {
    conditions.push("t.assigned_agent_id = ?");
    params.push(agentFilter);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";

  const tasks = db.prepare(`
    SELECT t.*,
      a.name AS agent_name,
      a.avatar_emoji AS agent_avatar,
      d.name AS department_name,
      d.icon AS department_icon,
      (SELECT COUNT(*) FROM subtasks WHERE task_id = t.id) AS subtask_total,
      (SELECT COUNT(*) FROM subtasks WHERE task_id = t.id AND status = 'done') AS subtask_done
    FROM tasks t
    LEFT JOIN agents a ON t.assigned_agent_id = a.id
    LEFT JOIN departments d ON t.department_id = d.id
    ${where}
    ORDER BY t.priority DESC, t.updated_at DESC
  `).all(...params);

  res.json({ tasks });
});

app.post("/api/tasks", (req, res) => {
  const body = req.body ?? {};
  const id = randomUUID();
  const t = nowMs();

  const title = body.title;
  if (!title || typeof title !== "string") {
    return res.status(400).json({ error: "title_required" });
  }

  db.prepare(`
    INSERT INTO tasks (id, title, description, department_id, assigned_agent_id, status, priority, task_type, project_path, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    id,
    title,
    body.description ?? null,
    body.department_id ?? null,
    body.assigned_agent_id ?? null,
    body.status ?? "inbox",
    body.priority ?? 0,
    body.task_type ?? "general",
    body.project_path ?? null,
    t,
    t,
  );

  appendTaskLog(id, "system", `Task created: ${title}`);

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", task);
  res.json({ id, task });
});

app.get("/api/tasks/:id", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare(`
    SELECT t.*,
      a.name AS agent_name,
      a.avatar_emoji AS agent_avatar,
      a.cli_provider AS agent_provider,
      d.name AS department_name,
      d.icon AS department_icon
    FROM tasks t
    LEFT JOIN agents a ON t.assigned_agent_id = a.id
    LEFT JOIN departments d ON t.department_id = d.id
    WHERE t.id = ?
  `).get(id);
  if (!task) return res.status(404).json({ error: "not_found" });

  const logs = db.prepare(
    "SELECT * FROM task_logs WHERE task_id = ? ORDER BY created_at DESC LIMIT 200"
  ).all(id);

  const subtasks = db.prepare(
    "SELECT * FROM subtasks WHERE task_id = ? ORDER BY created_at"
  ).all(id);

  res.json({ task, logs, subtasks });
});

app.get("/api/tasks/:id/meeting-minutes", (req, res) => {
  const id = String(req.params.id);
  const exists = db.prepare("SELECT id FROM tasks WHERE id = ?").get(id) as { id: string } | undefined;
  if (!exists) return res.status(404).json({ error: "not_found" });

  const meetings = db.prepare(
    "SELECT * FROM meeting_minutes WHERE task_id = ? ORDER BY started_at DESC, round DESC"
  ).all(id) as MeetingMinutesRow[];

  const data = meetings.map((meeting) => {
    const entries = db.prepare(
      "SELECT * FROM meeting_minute_entries WHERE meeting_id = ? ORDER BY seq ASC, id ASC"
    ).all(meeting.id) as MeetingMinuteEntryRow[];
    return { ...meeting, entries };
  });

  res.json({ meetings: data });
});

app.patch("/api/tasks/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "not_found" });

  const body = req.body ?? {};
  const allowedFields = [
    "title", "description", "department_id", "assigned_agent_id",
    "status", "priority", "task_type", "project_path", "result",
  ];

  const updates: string[] = ["updated_at = ?"];
  const params: unknown[] = [nowMs()];

  for (const field of allowedFields) {
    if (field in body) {
      updates.push(`${field} = ?`);
      params.push(body[field]);
    }
  }

  // Handle completed_at for status changes
  if (body.status === "done" && !("completed_at" in body)) {
    updates.push("completed_at = ?");
    params.push(nowMs());
  }
  if (body.status === "in_progress" && !("started_at" in body)) {
    updates.push("started_at = ?");
    params.push(nowMs());
  }

  params.push(id);
  db.prepare(`UPDATE tasks SET ${updates.join(", ")} WHERE id = ?`).run(...params);

  appendTaskLog(id, "system", `Task updated: ${Object.keys(body).join(", ")}`);

  const updated = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updated);
  res.json({ ok: true, task: updated });
});

app.delete("/api/tasks/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    assigned_agent_id: string | null;
  } | undefined;
  if (!existing) return res.status(404).json({ error: "not_found" });

  // Kill any running process
  const activeChild = activeProcesses.get(id);
  if (activeChild?.pid) {
    stopRequestedTasks.add(id);
    if (activeChild.pid < 0) {
      activeChild.kill();
    } else {
      killPidTree(activeChild.pid);
    }
    activeProcesses.delete(id);
  }

  // Reset agent if assigned
  if (existing.assigned_agent_id) {
    db.prepare(
      "UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ? AND current_task_id = ?"
    ).run(existing.assigned_agent_id, id);
  }

  db.prepare("DELETE FROM task_logs WHERE task_id = ?").run(id);
  db.prepare("DELETE FROM messages WHERE task_id = ?").run(id);
  db.prepare("DELETE FROM tasks WHERE id = ?").run(id);

  // Clean up log files
  for (const suffix of [".log", ".prompt.txt"]) {
    const filePath = path.join(logsDir, `${id}${suffix}`);
    try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch { /* ignore */ }
  }

  broadcast("task_update", { id, deleted: true });
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// SubTask endpoints
// ---------------------------------------------------------------------------

// GET /api/subtasks?active=1 — active subtasks for in_progress tasks
app.get("/api/subtasks", (req, res) => {
  const active = firstQueryValue(req.query.active);
  let subtasks;
  if (active === "1") {
    subtasks = db.prepare(`
      SELECT s.* FROM subtasks s
      JOIN tasks t ON s.task_id = t.id
      WHERE t.status = 'in_progress'
      ORDER BY s.created_at
    `).all();
  } else {
    subtasks = db.prepare("SELECT * FROM subtasks ORDER BY created_at").all();
  }
  res.json({ subtasks });
});

// POST /api/tasks/:id/subtasks — create subtask manually
app.post("/api/tasks/:id/subtasks", (req, res) => {
  const taskId = String(req.params.id);
  const task = db.prepare("SELECT id FROM tasks WHERE id = ?").get(taskId);
  if (!task) return res.status(404).json({ error: "task_not_found" });

  const body = req.body ?? {};
  if (!body.title || typeof body.title !== "string") {
    return res.status(400).json({ error: "title_required" });
  }

  const id = randomUUID();
  db.prepare(`
    INSERT INTO subtasks (id, task_id, title, description, status, assigned_agent_id, created_at)
    VALUES (?, ?, ?, ?, 'pending', ?, ?)
  `).run(id, taskId, body.title, body.description ?? null, body.assigned_agent_id ?? null, nowMs());

  // Detect foreign department for manual subtask creation too
  const parentTaskDept = db.prepare(
    "SELECT department_id FROM tasks WHERE id = ?"
  ).get(taskId) as { department_id: string | null } | undefined;
  const targetDeptId = analyzeSubtaskDepartment(body.title, parentTaskDept?.department_id ?? null);
  if (targetDeptId) {
    const targetDeptName = getDeptName(targetDeptId);
    db.prepare(
      "UPDATE subtasks SET target_department_id = ?, status = 'blocked', blocked_reason = ? WHERE id = ?"
    ).run(targetDeptId, `${targetDeptName} 협업 대기`, id);
  }

  const subtask = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(id);
  broadcast("subtask_update", subtask);
  res.json(subtask);
});

// PATCH /api/subtasks/:id — update subtask
app.patch("/api/subtasks/:id", (req, res) => {
  const id = String(req.params.id);
  const existing = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  if (!existing) return res.status(404).json({ error: "not_found" });

  const body = req.body ?? {};
  const allowedFields = ["title", "description", "status", "assigned_agent_id", "blocked_reason", "target_department_id", "delegated_task_id"];
  const updates: string[] = [];
  const params: unknown[] = [];

  for (const field of allowedFields) {
    if (field in body) {
      updates.push(`${field} = ?`);
      params.push(body[field]);
    }
  }

  // Auto-set completed_at when transitioning to done
  if (body.status === "done" && existing.status !== "done") {
    updates.push("completed_at = ?");
    params.push(nowMs());
  }

  if (updates.length === 0) return res.status(400).json({ error: "no_fields" });

  params.push(id);
  db.prepare(`UPDATE subtasks SET ${updates.join(", ")} WHERE id = ?`).run(...params);

  const subtask = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(id);
  broadcast("subtask_update", subtask);
  res.json(subtask);
});

app.post("/api/tasks/:id/assign", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    assigned_agent_id: string | null;
    title: string;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  const agentId = req.body?.agent_id;
  if (!agentId || typeof agentId !== "string") {
    return res.status(400).json({ error: "agent_id_required" });
  }

  const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as {
    id: string;
    name: string;
    department_id: string | null;
  } | undefined;
  if (!agent) return res.status(404).json({ error: "agent_not_found" });

  const t = nowMs();

  // Unassign previous agent if different
  if (task.assigned_agent_id && task.assigned_agent_id !== agentId) {
    db.prepare(
      "UPDATE agents SET current_task_id = NULL WHERE id = ? AND current_task_id = ?"
    ).run(task.assigned_agent_id, id);
  }

  // Update task
  db.prepare(
    "UPDATE tasks SET assigned_agent_id = ?, department_id = COALESCE(department_id, ?), status = CASE WHEN status = 'inbox' THEN 'planned' ELSE status END, updated_at = ? WHERE id = ?"
  ).run(agentId, agent.department_id, t, id);

  // Update agent
  db.prepare("UPDATE agents SET current_task_id = ? WHERE id = ?").run(id, agentId);

  appendTaskLog(id, "system", `Assigned to agent: ${agent.name}`);

  // Create assignment message
  const msgId = randomUUID();
  db.prepare(
    `INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
     VALUES (?, 'ceo', NULL, 'agent', ?, ?, 'task_assign', ?, ?)`
  ).run(msgId, agentId, `New task assigned: ${task.title}`, id, t);

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId);

  broadcast("task_update", updatedTask);
  broadcast("agent_status", updatedAgent);
  broadcast("new_message", {
    id: msgId,
    sender_type: "ceo",
    receiver_type: "agent",
    receiver_id: agentId,
    content: `New task assigned: ${task.title}`,
    message_type: "task_assign",
    task_id: id,
    created_at: t,
  });

  // B4: Notify CEO about assignment via team leader
  const leader = findTeamLeader(agent.department_id);
  if (leader) {
    const agentRow = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
    const agentName = agentRow?.name_ko || agent.name;
    sendAgentMessage(
      leader,
      `${leader.name_ko || leader.name}이(가) ${agentName}에게 '${task.title}' 업무를 할당했습니다.`,
      "status_update",
      "all",
      null,
      id,
    );
  }

  res.json({ ok: true, task: updatedTask, agent: updatedAgent });
});

app.post("/api/tasks/:id/run", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    title: string;
    description: string | null;
    assigned_agent_id: string | null;
    project_path: string | null;
    status: string;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  if (task.status === "in_progress") {
    return res.status(400).json({ error: "already_running" });
  }

  // Get the agent (or use provided agent_id)
  const agentId = task.assigned_agent_id || (req.body?.agent_id as string | undefined);
  if (!agentId) {
    return res.status(400).json({ error: "no_agent_assigned", message: "Assign an agent before running." });
  }

  const agent = db.prepare(`
    SELECT a.*, d.name AS department_name, d.name_ko AS department_name_ko
    FROM agents a LEFT JOIN departments d ON a.department_id = d.id
    WHERE a.id = ?
  `).get(agentId) as {
    id: string;
    name: string;
    name_ko: string | null;
    role: string;
    cli_provider: string | null;
    personality: string | null;
    department_id: string | null;
    department_name: string | null;
    department_name_ko: string | null;
  } | undefined;
  if (!agent) return res.status(400).json({ error: "agent_not_found" });

  // Guard: agent already working on another task
  const agentBusy = activeProcesses.has(
    (db.prepare("SELECT current_task_id FROM agents WHERE id = ? AND status = 'working'").get(agentId) as { current_task_id: string | null } | undefined)?.current_task_id ?? ""
  );
  if (agentBusy) {
    return res.status(400).json({ error: "agent_busy", message: `${agent.name} is already working on another task.` });
  }

  const provider = agent.cli_provider || "claude";
  if (!["claude", "codex", "gemini", "opencode", "copilot", "antigravity"].includes(provider)) {
    return res.status(400).json({ error: "unsupported_provider", provider });
  }

  const projectPath = resolveProjectPath(task) || (req.body?.project_path as string | undefined) || process.cwd();
  const logPath = path.join(logsDir, `${id}.log`);

  // Try to create a Git worktree for agent isolation
  const worktreePath = createWorktree(projectPath, id, agent.name);
  const agentCwd = worktreePath || projectPath;

  if (worktreePath) {
    appendTaskLog(id, "system", `Git worktree created: ${worktreePath} (branch: climpire/${id.slice(0, 8)})`);
  }

  // Build rich prompt with agent context + conversation history + role constraint
  const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[agent.role] || agent.role;
  const deptConstraint = agent.department_id ? getDeptRoleConstraint(agent.department_id, agent.department_name || agent.department_id) : "";
  const conversationCtx = getRecentConversationContext(agentId);
  // Non-CLI or non-multi-agent providers: instruct agent to output subtask plan as JSON
  const needsPlanInstruction = provider === "gemini" || provider === "copilot" || provider === "antigravity";
  const subtaskInstruction = needsPlanInstruction ? `

[작업 계획 출력 규칙]
작업을 시작하기 전에 아래 JSON 형식으로 계획을 출력하세요:
\`\`\`json
{"subtasks": [{"title": "서브태스크 제목1"}, {"title": "서브태스크 제목2"}]}
\`\`\`
각 서브태스크를 완료할 때마다 아래 형식으로 보고하세요:
\`\`\`json
{"subtask_done": "완료된 서브태스크 제목"}
\`\`\`
` : "";

  // Resolve model config for this provider
  const modelConfig = getProviderModelConfig();
  const mainModel = modelConfig[provider]?.model || undefined;
  const subModel = modelConfig[provider]?.subModel || undefined;
  const mainReasoningLevel = modelConfig[provider]?.reasoningLevel || undefined;

  // Sub-agent model hint (best-effort via prompt for claude/codex)
  const subReasoningLevel = modelConfig[provider]?.subModelReasoningLevel || undefined;
  const subModelHint = subModel && (provider === "claude" || provider === "codex")
    ? `\n[Sub-agent model preference] When spawning sub-agents (Task tool), prefer using model: ${subModel}${subReasoningLevel ? ` with reasoning effort: ${subReasoningLevel}` : ""}`
    : "";

  const prompt = [
    `[Task] ${task.title}`,
    task.description ? `\n${task.description}` : "",
    conversationCtx,
    `\n---`,
    `Agent: ${agent.name} (${roleLabel}, ${agent.department_name || "Unassigned"})`,
    agent.personality ? `Personality: ${agent.personality}` : "",
    deptConstraint,
    worktreePath ? `NOTE: You are working in an isolated Git worktree branch (climpire/${id.slice(0, 8)}). Commit your changes normally.` : "",
    subtaskInstruction,
    subModelHint,
    `Please complete the task above thoroughly. Use the conversation context above if relevant.`,
  ].filter(Boolean).join("\n");

  appendTaskLog(id, "system", `RUN start (agent=${agent.name}, provider=${provider})`);

  // HTTP agent for copilot/antigravity
  if (provider === "copilot" || provider === "antigravity") {
    const controller = new AbortController();
    const fakePid = -(++httpAgentCounter);

    const t = nowMs();
    db.prepare(
      "UPDATE tasks SET status = 'in_progress', assigned_agent_id = ?, started_at = ?, updated_at = ? WHERE id = ?"
    ).run(agentId, t, t, id);
    db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(id, agentId);

    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
    const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId);
    broadcast("task_update", updatedTask);
    broadcast("agent_status", updatedAgent);

    const worktreeNote = worktreePath ? ` (격리 브랜치: climpire/${id.slice(0, 8)})` : "";
    notifyCeo(`${agent.name_ko || agent.name}가 '${task.title}' 작업을 시작했습니다.${worktreeNote}`, id);

    const taskRow = db.prepare("SELECT department_id FROM tasks WHERE id = ?").get(id) as { department_id: string | null } | undefined;
    startProgressTimer(id, task.title, taskRow?.department_id ?? null);

    launchHttpAgent(id, provider, prompt, agentCwd, logPath, controller, fakePid);
    return res.json({ ok: true, pid: fakePid, logPath, cwd: agentCwd, worktree: !!worktreePath });
  }

  const child = spawnCliAgent(id, provider, prompt, agentCwd, logPath, mainModel, mainReasoningLevel);

  child.on("close", (code) => {
    handleTaskRunComplete(id, code ?? 1);
  });

  const t = nowMs();

  // Update task status
  db.prepare(
    "UPDATE tasks SET status = 'in_progress', assigned_agent_id = ?, started_at = ?, updated_at = ? WHERE id = ?"
  ).run(agentId, t, t, id);

  // Update agent status
  db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(id, agentId);

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId);
  broadcast("task_update", updatedTask);
  broadcast("agent_status", updatedAgent);

  // B4: Notify CEO that task started
  const worktreeNote = worktreePath ? ` (격리 브랜치: climpire/${id.slice(0, 8)})` : "";
  notifyCeo(`${agent.name_ko || agent.name}가 '${task.title}' 작업을 시작했습니다.${worktreeNote}`, id);

  // B2: Start progress report timer for long-running tasks
  const taskRow = db.prepare("SELECT department_id FROM tasks WHERE id = ?").get(id) as { department_id: string | null } | undefined;
  startProgressTimer(id, task.title, taskRow?.department_id ?? null);

  res.json({ ok: true, pid: child.pid ?? null, logPath, cwd: agentCwd, worktree: !!worktreePath });
});

app.post("/api/tasks/:id/stop", (req, res) => {
  const id = String(req.params.id);
  // mode=pause → pending (can resume), mode=cancel or default → cancelled
  const mode = String(req.body?.mode ?? req.query.mode ?? "cancel");
  const targetStatus = mode === "pause" ? "pending" : "cancelled";

  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    title: string;
    assigned_agent_id: string | null;
    department_id: string | null;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  stopProgressTimer(id);

  const activeChild = activeProcesses.get(id);
  if (!activeChild?.pid) {
    // No active process; just update status
    db.prepare("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?").run(targetStatus, nowMs(), id);
    const rolledBack = rollbackTaskWorktree(id, `stop_${targetStatus}_no_active_process`);
    if (task.assigned_agent_id) {
      db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?").run(task.assigned_agent_id);
    }
    const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
    broadcast("task_update", updatedTask);
    if (targetStatus === "pending") {
      notifyCeo(`'${task.title}' 작업이 보류 상태로 전환되었습니다.${rolledBack ? " 코드 변경분은 git rollback 처리되었습니다." : ""}`, id);
    } else {
      notifyCeo(`'${task.title}' 작업이 취소되었습니다.${rolledBack ? " 코드 변경분은 git rollback 처리되었습니다." : ""}`, id);
    }
    return res.json({
      ok: true,
      stopped: false,
      status: targetStatus,
      rolled_back: rolledBack,
      message: "No active process found.",
    });
  }

  // For HTTP agents (negative PID), call kill() which triggers AbortController
  // For CLI agents (positive PID), use OS-level process kill
  stopRequestedTasks.add(id);
  if (activeChild.pid < 0) {
    activeChild.kill();
  } else {
    killPidTree(activeChild.pid);
  }
  activeProcesses.delete(id);

  const actionLabel = targetStatus === "pending" ? "PAUSE" : "STOP";
  appendTaskLog(id, "system", `${actionLabel} sent to pid ${activeChild.pid}`);

  const rolledBack = rollbackTaskWorktree(id, `stop_${targetStatus}`);

  const t = nowMs();
  db.prepare("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?").run(targetStatus, t, id);

  if (task.assigned_agent_id) {
    db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?").run(task.assigned_agent_id);
    const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(task.assigned_agent_id);
    broadcast("agent_status", updatedAgent);
  }

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updatedTask);

  // CEO notification
  if (targetStatus === "pending") {
    notifyCeo(`'${task.title}' 작업이 보류 상태로 전환되었습니다.${rolledBack ? " 코드 변경분은 git rollback 처리되었습니다." : ""}`, id);
  } else {
    notifyCeo(`'${task.title}' 작업이 취소되었습니다.${rolledBack ? " 코드 변경분은 git rollback 처리되었습니다." : ""}`, id);
  }

  res.json({ ok: true, stopped: true, status: targetStatus, pid: activeChild.pid, rolled_back: rolledBack });
});

// Resume a pending or cancelled task → move back to planned (ready to re-run)
app.post("/api/tasks/:id/resume", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    title: string;
    status: string;
    assigned_agent_id: string | null;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  if (task.status !== "pending" && task.status !== "cancelled") {
    return res.status(400).json({ error: "invalid_status", message: `Cannot resume from '${task.status}'` });
  }

  const targetStatus = task.assigned_agent_id ? "planned" : "inbox";
  const t = nowMs();
  db.prepare("UPDATE tasks SET status = ?, updated_at = ? WHERE id = ?").run(targetStatus, t, id);

  appendTaskLog(id, "system", `RESUME: ${task.status} → ${targetStatus}`);

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updatedTask);

  notifyCeo(`'${task.title}' 작업이 복구되었습니다. (${targetStatus})`, id);

  res.json({ ok: true, status: targetStatus });
});

// ---------------------------------------------------------------------------
// Agent auto-reply & task delegation logic
// ---------------------------------------------------------------------------
interface AgentRow {
  id: string;
  name: string;
  name_ko: string;
  role: string;
  personality: string | null;
  status: string;
  department_id: string | null;
  current_task_id: string | null;
  avatar_emoji: string;
  cli_provider: string | null;
}

const ROLE_PRIORITY: Record<string, number> = {
  team_leader: 0, senior: 1, junior: 2, intern: 3,
};

const ROLE_LABEL: Record<string, string> = {
  team_leader: "팀장", senior: "시니어", junior: "주니어", intern: "인턴",
};

const DEPT_KEYWORDS: Record<string, string[]> = {
  dev:        ["개발", "코딩", "프론트", "백엔드", "API", "서버", "코드", "버그", "프로그램", "앱", "웹"],
  design:     ["디자인", "UI", "UX", "목업", "피그마", "아이콘", "로고", "배너", "레이아웃", "시안"],
  planning:   ["기획", "전략", "분석", "리서치", "보고서", "PPT", "발표", "시장", "조사", "제안"],
  operations: ["운영", "배포", "인프라", "모니터링", "서버관리", "CI", "CD", "DevOps", "장애"],
  qa:         ["QA", "QC", "품질", "테스트", "검수", "버그리포트", "회귀", "자동화테스트", "성능테스트", "리뷰"],
  devsecops:  ["보안", "취약점", "인증", "SSL", "방화벽", "해킹", "침투", "파이프라인", "컨테이너", "도커", "쿠버네티스", "암호화"],
};

function pickRandom<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function sendAgentMessage(
  agent: AgentRow,
  content: string,
  messageType: string = "chat",
  receiverType: string = "agent",
  receiverId: string | null = null,
  taskId: string | null = null,
): void {
  const id = randomUUID();
  const t = nowMs();
  db.prepare(`
    INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
    VALUES (?, 'agent', ?, ?, ?, ?, ?, ?, ?)
  `).run(id, agent.id, receiverType, receiverId, content, messageType, taskId, t);

  broadcast("new_message", {
    id,
    sender_type: "agent",
    sender_id: agent.id,
    receiver_type: receiverType,
    receiver_id: receiverId,
    content,
    message_type: messageType,
    task_id: taskId,
    created_at: t,
    sender_name: agent.name,
    sender_avatar: agent.avatar_emoji ?? "🤖",
  });
}

// ---- Language detection & multilingual response system ----

type Lang = "ko" | "en" | "ja" | "zh";

const SUPPORTED_LANGS: readonly Lang[] = ["ko", "en", "ja", "zh"] as const;

function isLang(value: unknown): value is Lang {
  return typeof value === "string" && SUPPORTED_LANGS.includes(value as Lang);
}

function readSettingString(key: string): string | undefined {
  const row = db.prepare("SELECT value FROM settings WHERE key = ?").get(key) as { value: string } | undefined;
  if (!row) return undefined;
  try {
    const parsed = JSON.parse(row.value);
    return typeof parsed === "string" ? parsed : row.value;
  } catch {
    return row.value;
  }
}

function getPreferredLanguage(): Lang {
  const settingLang = readSettingString("language");
  return isLang(settingLang) ? settingLang : "en";
}

function resolveLang(text?: string, fallback?: Lang): Lang {
  const settingLang = readSettingString("language");
  if (isLang(settingLang)) return settingLang;
  const trimmed = typeof text === "string" ? text.trim() : "";
  if (trimmed) return detectLang(trimmed);
  return fallback ?? getPreferredLanguage();
}

function detectLang(text: string): Lang {
  const ko = text.match(/[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]/g)?.length ?? 0;
  const ja = text.match(/[\u3040-\u309F\u30A0-\u30FF]/g)?.length ?? 0;
  const zh = text.match(/[\u4E00-\u9FFF]/g)?.length ?? 0;
  const total = text.replace(/\s/g, "").length || 1;
  if (ko / total > 0.15) return "ko";
  if (ja / total > 0.15) return "ja";
  if (zh / total > 0.3) return "zh";
  return "en";
}

// Bilingual response templates: { ko, en, ja, zh }
type L10n = Record<Lang, string[]>;

function l(ko: string[], en: string[], ja?: string[], zh?: string[]): L10n {
  return {
    ko,
    en,
    ja: ja ?? en.map(s => s),  // fallback to English
    zh: zh ?? en.map(s => s),
  };
}

function pickL(pool: L10n, lang: Lang): string {
  const arr = pool[lang];
  return arr[Math.floor(Math.random() * arr.length)];
}

// Agent personality flair by agent name + language
function getFlairs(agentName: string, lang: Lang): string[] {
  const flairs: Record<string, Record<Lang, string[]>> = {
    Aria:  { ko: ["코드 리뷰 중에", "리팩토링 구상하면서", "PR 체크하면서"],
             en: ["reviewing code", "planning a refactor", "checking PRs"],
             ja: ["コードレビュー中に", "リファクタリングを考えながら", "PR確認しながら"],
             zh: ["审查代码中", "规划重构时", "检查PR时"] },
    Bolt:  { ko: ["빠르게 코딩하면서", "API 설계하면서", "성능 튜닝하면서"],
             en: ["coding fast", "designing APIs", "tuning performance"],
             ja: ["高速コーディング中", "API設計しながら", "パフォーマンスチューニング中"],
             zh: ["快速编码中", "设计API时", "调优性能时"] },
    Nova:  { ko: ["새로운 기술 공부하면서", "프로토타입 만들면서", "실험적인 코드 짜면서"],
             en: ["studying new tech", "building a prototype", "writing experimental code"],
             ja: ["新技術を勉強しながら", "プロトタイプ作成中", "実験的なコード書き中"],
             zh: ["学习新技术中", "制作原型时", "编写实验代码时"] },
    Pixel: { ko: ["디자인 시안 작업하면서", "컴포넌트 정리하면서", "UI 가이드 업데이트하면서"],
             en: ["working on mockups", "organizing components", "updating the UI guide"],
             ja: ["デザインモックアップ作業中", "コンポーネント整理しながら", "UIガイド更新中"],
             zh: ["制作设计稿中", "整理组件时", "更新UI指南时"] },
    Luna:  { ko: ["애니메이션 작업하면서", "컬러 팔레트 고민하면서", "사용자 경험 분석하면서"],
             en: ["working on animations", "refining the color palette", "analyzing UX"],
             ja: ["アニメーション作業中", "カラーパレット検討中", "UX分析しながら"],
             zh: ["制作动画中", "调整调色板时", "分析用户体验时"] },
    Sage:  { ko: ["시장 분석 보고서 보면서", "전략 문서 정리하면서", "경쟁사 리서치하면서"],
             en: ["reviewing market analysis", "organizing strategy docs", "researching competitors"],
             ja: ["市場分析レポート確認中", "戦略文書整理中", "競合リサーチしながら"],
             zh: ["查看市场分析报告", "整理战略文件时", "调研竞品时"] },
    Clio:  { ko: ["데이터 분석하면서", "기획서 작성하면서", "사용자 인터뷰 정리하면서"],
             en: ["analyzing data", "drafting a proposal", "organizing user interviews"],
             ja: ["データ分析中", "企画書作成中", "ユーザーインタビュー整理中"],
             zh: ["分析数据中", "撰写企划书时", "整理用户访谈时"] },
    Atlas: { ko: ["서버 모니터링하면서", "배포 파이프라인 점검하면서", "운영 지표 확인하면서"],
             en: ["monitoring servers", "checking deploy pipelines", "reviewing ops metrics"],
             ja: ["サーバー監視中", "デプロイパイプライン点検中", "運用指標確認中"],
             zh: ["监控服务器中", "检查部署流水线时", "查看运营指标时"] },
    Turbo: { ko: ["자동화 스크립트 돌리면서", "CI/CD 최적화하면서", "인프라 정리하면서"],
             en: ["running automation scripts", "optimizing CI/CD", "cleaning up infra"],
             ja: ["自動化スクリプト実行中", "CI/CD最適化中", "インフラ整理中"],
             zh: ["运行自动化脚本中", "优化CI/CD时", "整理基础设施时"] },
    Hawk:  { ko: ["테스트 케이스 리뷰하면서", "버그 리포트 분석하면서", "품질 지표 확인하면서"],
             en: ["reviewing test cases", "analyzing bug reports", "checking quality metrics"],
             ja: ["テストケースレビュー中", "バグレポート分析中", "品質指標確認中"],
             zh: ["审查测试用例中", "分析缺陷报告时", "查看质量指标时"] },
    Lint:  { ko: ["자동화 테스트 작성하면서", "코드 검수하면서", "회귀 테스트 돌리면서"],
             en: ["writing automated tests", "inspecting code", "running regression tests"],
             ja: ["自動テスト作成中", "コード検査中", "回帰テスト実行中"],
             zh: ["编写自动化测试中", "检查代码时", "运行回归测试时"] },
    Vault: { ko: ["보안 감사 진행하면서", "취약점 스캔 결과 보면서", "인증 로직 점검하면서"],
             en: ["running a security audit", "reviewing vuln scan results", "checking auth logic"],
             ja: ["セキュリティ監査中", "脆弱性スキャン結果確認中", "認証ロジック点検中"],
             zh: ["进行安全审计中", "查看漏洞扫描结果时", "检查认证逻辑时"] },
    Pipe:  { ko: ["파이프라인 구축하면서", "컨테이너 설정 정리하면서", "배포 자동화 하면서"],
             en: ["building pipelines", "configuring containers", "automating deployments"],
             ja: ["パイプライン構築中", "コンテナ設定整理中", "デプロイ自動化中"],
             zh: ["构建流水线中", "配置容器时", "自动化部署时"] },
  };
  const agentFlairs = flairs[agentName];
  if (agentFlairs) return agentFlairs[lang] ?? agentFlairs.en;
  const defaults: Record<Lang, string[]> = {
    ko: ["업무 처리하면서", "작업 진행하면서", "일하면서"],
    en: ["working on tasks", "making progress", "getting things done"],
    ja: ["業務処理中", "作業進行中", "仕事しながら"],
    zh: ["处理业务中", "推进工作时", "忙着干活时"],
  };
  return defaults[lang];
}

// Role labels per language
const ROLE_LABEL_L10N: Record<string, Record<Lang, string>> = {
  team_leader: { ko: "팀장", en: "Team Lead", ja: "チームリーダー", zh: "组长" },
  senior:      { ko: "시니어", en: "Senior", ja: "シニア", zh: "高级" },
  junior:      { ko: "주니어", en: "Junior", ja: "ジュニア", zh: "初级" },
  intern:      { ko: "인턴", en: "Intern", ja: "インターン", zh: "实习生" },
};

function getRoleLabel(role: string, lang: Lang): string {
  return ROLE_LABEL_L10N[role]?.[lang] ?? ROLE_LABEL[role] ?? role;
}

// Intent classifiers per language
function classifyIntent(msg: string, lang: Lang) {
  const checks: Record<string, RegExp[]> = {
    greeting: [
      /안녕|하이|반가|좋은\s*(아침|오후|저녁)/i,
      /hello|hi\b|hey|good\s*(morning|afternoon|evening)|howdy|what'?s\s*up/i,
      /こんにちは|おはよう|こんばんは|やあ|どうも/i,
      /你好|嗨|早上好|下午好|晚上好/i,
    ],
    presence: [
      /자리|있어|계세요|계신가|거기|응답|들려|보여|어디야|어딨/i,
      /are you (there|here|around|available|at your desk)|you there|anybody|present/i,
      /いますか|席に|いる？|応答/i,
      /在吗|在不在|有人吗/i,
    ],
    whatDoing: [
      /뭐\s*해|뭐하|뭘\s*해|뭐\s*하고|뭐\s*하는|하는\s*중|진행\s*중|바쁘|바빠|한가/i,
      /what are you (doing|up to|working on)|busy|free|what'?s going on|occupied/i,
      /何してる|忙しい|暇|何やってる/i,
      /在做什么|忙吗|有空吗|在干嘛/i,
    ],
    report: [
      /보고|현황|상태|진행|어디까지|결과|리포트|성과/i,
      /report|status|progress|update|how('?s| is) (it|the|your)|results/i,
      /報告|進捗|状況|ステータス/i,
      /报告|进度|状态|进展/i,
    ],
    praise: [
      /잘했|수고|고마|감사|훌륭|대단|멋져|최고|짱/i,
      /good (job|work)|well done|thank|great|awesome|amazing|excellent|nice|kudos|bravo/i,
      /よくやった|お疲れ|ありがとう|素晴らしい|すごい/i,
      /做得好|辛苦|谢谢|太棒了|厉害/i,
    ],
    encourage: [
      /힘내|화이팅|파이팅|응원|열심히|잘\s*부탁|잘\s*해|잘해봐/i,
      /keep (it )?up|go for it|fighting|you (got|can do) (this|it)|cheer|hang in there/i,
      /頑張|ファイト|応援/i,
      /加油|努力|拜托/i,
    ],
    joke: [
      /ㅋ|ㅎ|웃|재밌|장난|농담|심심|놀자/i,
      /lol|lmao|haha|joke|funny|bored|play/i,
      /笑|面白い|冗談|暇/i,
      /哈哈|笑|开玩笑|无聊/i,
    ],
    complaint: [
      /느려|답답|왜\s*이래|언제\s*돼|빨리|지연|늦/i,
      /slow|frustrat|why (is|so)|when (will|is)|hurry|delay|late|taking (too )?long/i,
      /遅い|イライラ|なぜ|いつ|急いで/i,
      /慢|着急|为什么|快点|延迟/i,
    ],
    opinion: [
      /어때|생각|의견|아이디어|제안|건의|어떨까|괜찮/i,
      /what do you think|opinion|idea|suggest|how about|thoughts|recommend/i,
      /どう思う|意見|アイデア|提案/i,
      /怎么看|意见|想法|建议/i,
    ],
    canDo: [
      /가능|할\s*수|되나|될까|할까|해줘|해\s*줄|맡아|부탁/i,
      /can you|could you|possible|able to|handle|take care|would you|please/i,
      /できる|可能|お願い|頼む|やって/i,
      /能不能|可以|拜托|帮忙|处理/i,
    ],
    question: [
      /\?|뭐|어디|언제|왜|어떻게|무엇|몇/i,
      /\?|what|where|when|why|how|which|who/i,
      /\?|何|どこ|いつ|なぜ|どう/i,
      /\?|什么|哪里|什么时候|为什么|怎么/i,
    ],
  };

  const langIdx = { ko: 0, en: 1, ja: 2, zh: 3 }[lang];
  const result: Record<string, boolean> = {};
  for (const [key, patterns] of Object.entries(checks)) {
    // Check ALL language patterns (user may mix languages)
    result[key] = patterns.some(p => p.test(msg));
  }
  return result;
}

function generateChatReply(agent: AgentRow, ceoMessage: string): string {
  const msg = ceoMessage.trim();
  const lang = resolveLang(msg);
  const name = lang === "ko" ? (agent.name_ko || agent.name) : agent.name;
  const dept = agent.department_id ? getDeptName(agent.department_id) : "";
  const role = getRoleLabel(agent.role, lang);
  const nameTag = dept ? (lang === "ko" ? `${dept} ${role} ${name}` : `${name}, ${role} of ${dept}`) : `${role} ${name}`;
  const flairs = getFlairs(agent.name, lang);
  const flair = () => pickRandom(flairs);
  const intent = classifyIntent(msg, lang);

  // Current task info
  let taskTitle = "";
  if (agent.current_task_id) {
    const t = db.prepare("SELECT title FROM tasks WHERE id = ?").get(agent.current_task_id) as { title: string } | undefined;
    if (t) taskTitle = t.title;
  }

  // ---- Offline ----
  if (agent.status === "offline") return pickL(l(
    [`[자동응답] ${nameTag}은(는) 현재 오프라인입니다. 복귀 후 확인하겠습니다.`],
    [`[Auto-reply] ${name} is currently offline. I'll check when I'm back.`],
    [`[自動応答] ${name}は現在オフラインです。復帰後確認します。`],
    [`[自动回复] ${name}目前离线，回来后会确认。`],
  ), lang);

  // ---- Break ----
  if (agent.status === "break") {
    if (intent.presence) return pickL(l(
      [`앗, 대표님! 잠깐 커피 타러 갔었습니다. 바로 자리 복귀했습니다! ☕`, `네! 휴식 중이었는데 돌아왔습니다. 무슨 일이신가요?`, `여기 있습니다! 잠시 환기하고 왔어요. 말씀하세요~ 😊`],
      [`Oh! I just stepped out for coffee. I'm back now! ☕`, `Yes! I was on a short break but I'm here. What do you need?`, `I'm here! Just took a quick breather. What's up? 😊`],
      [`あ、少し休憩していました！戻りました！☕`, `はい！少し休んでいましたが、戻りました。何でしょう？`],
      [`啊，刚去倒了杯咖啡。回来了！☕`, `在的！刚休息了一下，有什么事吗？`],
    ), lang);
    if (intent.greeting) return pickL(l(
      [`안녕하세요, 대표님! 잠깐 쉬고 있었는데, 말씀하세요! ☕`, `네~ 대표님! ${name}입니다. 잠시 브레이크 중이었어요. 무슨 일이세요?`],
      [`Hi! I was on a quick break. How can I help? ☕`, `Hey! ${name} here. Was taking a breather. What's going on?`],
      [`こんにちは！少し休憩中でした。何でしょう？☕`],
      [`你好！我刚在休息。有什么事吗？☕`],
    ), lang);
    return pickL(l(
      [`앗, 잠시 쉬고 있었습니다! 바로 확인하겠습니다 😅`, `네, 대표님! 휴식 끝내고 바로 보겠습니다!`, `복귀했습니다! 말씀하신 건 바로 처리할게요 ☕`],
      [`Oh, I was taking a break! Let me check right away 😅`, `Got it! Break's over, I'll look into it now!`, `I'm back! I'll handle that right away ☕`],
      [`あ、休憩中でした！すぐ確認します 😅`, `戻りました！すぐ対応します ☕`],
      [`啊，刚在休息！马上看 😅`, `回来了！马上处理 ☕`],
    ), lang);
  }

  // ---- Working ----
  if (agent.status === "working") {
    const taskKo = taskTitle ? ` "${taskTitle}" 작업` : " 할당된 업무";
    const taskEn = taskTitle ? ` "${taskTitle}"` : " my current task";
    const taskJa = taskTitle ? ` "${taskTitle}"` : " 現在のタスク";
    const taskZh = taskTitle ? ` "${taskTitle}"` : " 当前任务";

    if (intent.presence) return pickL(l(
      [`네! 자리에 있습니다. 지금${taskKo} 진행 중이에요. 말씀하세요!`, `여기 있습니다, 대표님! ${flair()} 열심히 하고 있어요 💻`, `네~ 자리에서${taskKo} 처리 중입니다. 무슨 일이세요?`],
      [`Yes! I'm here. Currently working on${taskEn}. What do you need?`, `I'm at my desk! ${flair()} and making good progress 💻`, `Right here! Working on${taskEn}. What's up?`],
      [`はい！席にいます。${taskJa}を進行中です。何でしょう？`, `ここにいますよ！${flair()}頑張っています 💻`],
      [`在的！正在处理${taskZh}。有什么事？`, `我在工位上！正在${flair()} 💻`],
    ), lang);
    if (intent.greeting) return pickL(l(
      [`안녕하세요, 대표님! ${nameTag}입니다. ${flair()} 작업 중이에요 😊`, `네, 대표님! 지금${taskKo}에 집중 중인데, 말씀하세요!`],
      [`Hi! ${nameTag} here. Currently ${flair()} 😊`, `Hello! I'm focused on${taskEn} right now, but go ahead!`],
      [`こんにちは！${name}です。${flair()}作業中です 😊`],
      [`你好！${name}在这。正在${flair()} 😊`],
    ), lang);
    if (intent.whatDoing) return pickL(l(
      [`지금${taskKo} 진행 중입니다! ${flair()} 순조롭게 되고 있어요 📊`, `${flair()}${taskKo} 처리하고 있습니다. 70% 정도 진행됐어요!`, `현재${taskKo}에 몰두 중입니다. 곧 완료될 것 같아요! 💪`],
      [`Working on${taskEn} right now! ${flair()} — going smoothly 📊`, `I'm ${flair()} on${taskEn}. About 70% done!`, `Deep into${taskEn} at the moment. Should be done soon! 💪`],
      [`${taskJa}を進行中です！${flair()}順調です 📊`, `${flair()}${taskJa}に取り組んでいます。もうすぐ完了です！💪`],
      [`正在处理${taskZh}！${flair()}进展顺利 📊`, `${flair()}处理${taskZh}中，大概完成70%了！💪`],
    ), lang);
    if (intent.report) return pickL(l(
      [`${taskKo} 순조롭게 진행되고 있습니다. ${flair()} 마무리 단계에요! 📊`, `현재${taskKo} 진행률 약 70%입니다. 예정대로 완료 가능할 것 같습니다!`],
      [`${taskEn} is progressing well. ${flair()} — wrapping up! 📊`, `About 70% done on${taskEn}. On track for completion!`],
      [`${taskJa}は順調に進んでいます。${flair()}まもなく完了です！📊`],
      [`${taskZh}进展顺利。${flair()}快收尾了！📊`],
    ), lang);
    if (intent.complaint) return pickL(l(
      [`죄송합니다, 대표님. 최대한 속도 내서 처리하겠습니다! 🏃‍♂️`, `빠르게 진행하고 있습니다! 조금만 더 시간 주시면 곧 마무리됩니다.`],
      [`Sorry about that! I'll pick up the pace 🏃‍♂️`, `Working as fast as I can! Just need a bit more time.`],
      [`申し訳ありません！最速で対応します 🏃‍♂️`],
      [`抱歉！我会加快速度 🏃‍♂️`],
    ), lang);
    if (intent.canDo) return pickL(l(
      [`지금 작업 중이라 바로는 어렵지만, 완료 후 바로 착수하겠습니다! 📝`, `현 작업 마무리되면 바로 가능합니다! 메모해두겠습니다.`],
      [`I'm tied up right now, but I'll jump on it as soon as I finish! 📝`, `Can do! Let me wrap up my current task first.`],
      [`今は作業中ですが、完了後すぐ取りかかります！📝`],
      [`现在在忙，完成后马上开始！📝`],
    ), lang);
    return pickL(l(
      [`네, 확인했습니다! 현재 작업 마무리 후 확인하겠습니다 📝`, `알겠습니다, 대표님. ${flair()} 일단 메모해두겠습니다!`],
      [`Got it! I'll check after finishing my current task 📝`, `Noted! I'll get to it once I'm done here.`],
      [`了解しました！現在の作業完了後に確認します 📝`],
      [`收到！完成当前工作后确认 📝`],
    ), lang);
  }

  // ---- Idle (default) ----

  if (intent.presence) return pickL(l(
    [`네! 자리에 있습니다, 대표님. ${nameTag}입니다. 말씀하세요! 😊`, `여기 있어요! 대기 중이었습니다. 무슨 일이세요?`, `네~ 자리에 있습니다! 업무 지시 기다리고 있었어요.`, `항상 대기 중입니다, 대표님! ${name} 여기 있어요 ✋`],
    [`Yes, I'm here! ${nameTag}. What do you need? 😊`, `Right here! I was on standby. What's up?`, `I'm at my desk! Ready for anything.`, `Always ready! ${name} is here ✋`],
    [`はい！席にいます。${name}です。何でしょう？😊`, `ここにいますよ！待機中でした。`, `席にいます！指示をお待ちしています ✋`],
    [`在的！${name}在这。有什么事吗？😊`, `我在！一直待命中。有什么需要？`, `随时准备就绪！${name}在这 ✋`],
  ), lang);
  if (intent.greeting) return pickL(l(
    [`안녕하세요, 대표님! ${nameTag}입니다. 오늘도 좋은 하루 보내고 계신가요? 😊`, `안녕하세요! ${nameTag}입니다. 필요하신 게 있으시면 편하게 말씀하세요!`, `네, 대표님! ${name}입니다. 오늘도 파이팅이요! 🔥`, `반갑습니다, 대표님! ${dept} ${name}, 준비 완료입니다!`],
    [`Hello! ${nameTag} here. Having a good day? 😊`, `Hi! ${nameTag}. Feel free to let me know if you need anything!`, `Hey! ${name} here. Let's make today count! 🔥`, `Good to see you! ${name} from ${dept}, ready to go!`],
    [`こんにちは！${name}です。今日もよろしくお願いします 😊`, `${name}です。何かあればお気軽にどうぞ！`, `今日も頑張りましょう！🔥`],
    [`你好！${name}在这。今天也加油！😊`, `${name}随时准备好了，有什么需要请说！🔥`],
  ), lang);
  if (intent.whatDoing) return pickL(l(
    [`지금은 대기 중이에요! ${flair()} 스킬업 하고 있었습니다 📚`, `특별한 업무는 없어서 ${flair()} 개인 학습 중이었어요.`, `한가한 상태입니다! 새로운 업무 주시면 바로 착수할 수 있어요 🙌`],
    [`I'm on standby! Was ${flair()} to sharpen my skills 📚`, `Nothing assigned right now, so I was ${flair()}.`, `I'm free! Give me something to do and I'll jump right in 🙌`],
    [`待機中です！${flair()}スキルアップしていました 📚`, `特に業務はないので、${flair()}個人学習中でした。`],
    [`待命中！正在${flair()}提升技能 📚`, `没有特别的任务，正在${flair()}学习中。`],
  ), lang);
  if (intent.praise) return pickL(l(
    [`감사합니다, 대표님! 더 열심히 하겠습니다! 💪`, `대표님 칭찬에 힘이 불끈! 오늘도 최선을 다할게요 😊`, `앗, 감사합니다~ 대표님이 알아주시니 더 보람차네요! ✨`],
    [`Thank you! I'll keep up the great work! 💪`, `That means a lot! I'll do my best 😊`, `Thanks! Really motivating to hear that ✨`],
    [`ありがとうございます！もっと頑張ります！💪`, `嬉しいです！最善を尽くします 😊`],
    [`谢谢！会继续努力的！💪`, `太开心了！会做到最好 😊`],
  ), lang);
  if (intent.encourage) return pickL(l(
    [`감사합니다! 대표님 응원 덕분에 힘이 납니다! 💪`, `네! 화이팅입니다! 기대에 꼭 부응할게요 🔥`],
    [`Thanks! Your support means everything! 💪`, `You got it! I won't let you down 🔥`],
    [`ありがとうございます！頑張ります！💪`, `期待に応えます！🔥`],
    [`谢谢鼓励！一定不辜负期望！💪🔥`],
  ), lang);
  if (intent.report) return pickL(l(
    [`현재 대기 상태이고, 할당된 업무는 없습니다. 새 업무 주시면 바로 시작할 수 있어요! 📋`, `대기 중이라 여유 있습니다. 업무 지시 기다리고 있어요!`],
    [`Currently on standby with no assigned tasks. Ready to start anything! 📋`, `I'm available! Just waiting for the next assignment.`],
    [`現在待機中で、割り当てタスクはありません。いつでも開始できます！📋`],
    [`目前待命中，没有分配任务。随时可以开始！📋`],
  ), lang);
  if (intent.joke) return pickL(l(
    [`ㅎㅎ 대표님 오늘 기분 좋으신가 봐요! 😄`, `ㅋㅋ 대표님이랑 일하면 분위기가 좋아요~`, `😂 잠깐 웃고 다시 집중! 업무 주시면 바로 달리겠습니다!`],
    [`Haha, you're in a good mood today! 😄`, `Love the vibes! Working with you is always fun~`, `😂 Good laugh! Alright, ready to get back to work!`],
    [`ハハ、今日はいい気分ですね！😄`, `😂 いい雰囲気！仕事に戻りましょう！`],
    [`哈哈，今天心情不错啊！😄`, `😂 笑完了，准备干活！`],
  ), lang);
  if (intent.complaint) return pickL(l(
    [`죄송합니다, 대표님! 더 빠르게 움직이겠습니다.`, `말씀 새겨듣겠습니다. 개선해서 보여드리겠습니다! 🙏`],
    [`Sorry about that! I'll step it up.`, `I hear you. I'll improve and show results! 🙏`],
    [`申し訳ありません！もっと速く動きます。`, `改善してお見せします！🙏`],
    [`抱歉！会加快行动。`, `记住了，会改进的！🙏`],
  ), lang);
  if (intent.opinion) return pickL(l(
    [`제 의견으로는요... ${dept} 관점에서 한번 검토해보겠습니다! 🤔`, `좋은 질문이시네요! 관련해서 정리해서 말씀드릴게요.`, `${dept}에서 보기엔 긍정적으로 보입니다. 자세한 내용 분석 후 말씀드릴게요 📊`],
    [`From a ${dept} perspective, let me think about that... 🤔`, `Great question! Let me put together my thoughts on this.`, `Looks promising from where I sit. I'll analyze the details and get back to you 📊`],
    [`${dept}の観点から検討してみます！🤔`, `いい質問ですね！整理してお伝えします。`],
    [`从${dept}角度看，让我想想... 🤔`, `好问题！我整理一下想法再回复您 📊`],
  ), lang);
  if (intent.canDo) return pickL(l(
    [`물론이죠! 바로 시작할 수 있습니다. 상세 내용 말씀해주세요! 🚀`, `가능합니다, 대표님! 지금 여유 있으니 바로 착수하겠습니다.`, `네, 맡겨주세요! ${name}이(가) 책임지고 처리하겠습니다 💪`],
    [`Absolutely! I can start right away. Just give me the details! 🚀`, `Can do! I'm free right now, so I'll get on it.`, `Leave it to me! ${name} will handle it 💪`],
    [`もちろんです！すぐ始められます。詳細を教えてください！🚀`, `お任せください！${name}が責任持って対応します 💪`],
    [`当然可以！马上开始。请告诉我详情！🚀`, `交给我吧！${name}负责处理 💪`],
  ), lang);
  if (intent.question) return pickL(l(
    [`확인해보겠습니다! 잠시만요 🔍`, `음, 좋은 질문이시네요. 찾아보고 말씀드리겠습니다!`, `관련 내용 파악해서 빠르게 답변 드리겠습니다.`],
    [`Let me check on that! One moment 🔍`, `Good question! Let me look into it and get back to you.`, `I'll find out and get back to you ASAP.`],
    [`確認してみます！少々お待ちください 🔍`, `いい質問ですね。調べてお伝えします！`],
    [`让我查一下！稍等 🔍`, `好问题！我查查看。`],
  ), lang);
  return pickL(l(
    [`네, 확인했습니다! 추가로 필요하신 게 있으면 말씀해주세요.`, `네! ${name} 잘 들었습니다 😊 지시사항 있으시면 편하게 말씀하세요.`, `알겠습니다, 대표님! 관련해서 진행할게요.`, `확인했습니다! 바로 반영하겠습니다 📝`],
    [`Got it! Let me know if you need anything else.`, `Understood! ${name} is on it 😊`, `Roger that! I'll get moving on this.`, `Noted! I'll take care of it 📝`],
    [`了解しました！他に必要なことがあればお知らせください。`, `承知しました！${name}が対応します 😊`, `かしこまりました！すぐ対応します 📝`],
    [`收到！有其他需要随时说。`, `明白了！${name}这就去办 😊`, `了解！马上处理 📝`],
  ), lang);
}

// ---- Announcement reply logic (team leaders respond) ----

function generateAnnouncementReply(agent: AgentRow, announcement: string, lang: Lang): string {
  const name = lang === "ko" ? (agent.name_ko || agent.name) : agent.name;
  const dept = agent.department_id ? getDeptName(agent.department_id) : "";
  const role = getRoleLabel(agent.role, lang);

  // Detect announcement type
  const isUrgent = /긴급|중요|즉시|urgent|important|immediately|critical|緊急|紧急/i.test(announcement);
  const isGoodNews = /축하|달성|성공|감사|congrat|achieve|success|thank|おめでとう|祝贺|恭喜/i.test(announcement);
  const isPolicy = /정책|방침|규칙|변경|policy|change|rule|update|方針|政策/i.test(announcement);
  const isMeeting = /회의|미팅|모임|meeting|gather|会議|开会/i.test(announcement);

  if (isUrgent) return pickL(l(
    [`${dept} ${name}, 확인했습니다! 즉시 팀에 전달하고 대응하겠습니다! 🚨`, `네, 긴급 확인! ${dept}에서 바로 조치 취하겠습니다.`, `${name} 확인했습니다! 팀원들에게 즉시 공유하겠습니다.`],
    [`${name} from ${dept} — acknowledged! I'll relay this to my team immediately! 🚨`, `Urgent noted! ${dept} is on it right away.`, `${name} here — confirmed! Sharing with the team ASAP.`],
    [`${dept}の${name}、確認しました！チームにすぐ伝達します！🚨`],
    [`${dept}${name}收到！立即传达给团队！🚨`],
  ), lang);
  if (isGoodNews) return pickL(l(
    [`축하합니다! ${dept}도 함께 기뻐요! 🎉`, `좋은 소식이네요! ${dept} 팀원들에게도 공유하겠습니다 😊`, `${name} 확인! 정말 좋은 소식입니다! 👏`],
    [`Congratulations! ${dept} is thrilled! 🎉`, `Great news! I'll share this with my team 😊`, `${name} here — wonderful to hear! 👏`],
    [`おめでとうございます！${dept}も喜んでいます！🎉`],
    [`恭喜！${dept}也很高兴！🎉`],
  ), lang);
  if (isMeeting) return pickL(l(
    [`${dept} ${name}, 확인했습니다! 일정 잡아두겠습니다 📅`, `네, 참석하겠습니다! ${dept} 팀원들에게도 전달할게요.`, `${name} 확인! 미팅 준비하겠습니다.`],
    [`${name} from ${dept} — noted! I'll block the time 📅`, `Will be there! I'll let my team know too.`, `${name} confirmed! I'll prepare for the meeting.`],
    [`${name}確認しました！スケジュール押さえます 📅`],
    [`${name}收到！会安排时间 📅`],
  ), lang);
  if (isPolicy) return pickL(l(
    [`${dept} ${name}, 확인했습니다. 팀 내 공유하고 반영하겠습니다 📋`, `네, 정책 변경 확인! ${dept}에서 필요한 조치 검토하겠습니다.`],
    [`${name} from ${dept} — understood. I'll share with the team and align accordingly 📋`, `Policy update noted! ${dept} will review and adjust.`],
    [`${name}確認しました。チーム内に共有し反映します 📋`],
    [`${name}收到，会在团队内传达并落实 📋`],
  ), lang);
  // Generic
  return pickL(l(
    [`${dept} ${name}, 확인했습니다! 👍`, `네, 공지 확인! ${dept}에서 참고하겠습니다.`, `${name} 확인했습니다. 팀에 공유하겠습니다!`, `알겠습니다! ${dept} 업무에 반영하겠습니다 📝`],
    [`${name} from ${dept} — acknowledged! 👍`, `Noted! ${dept} will take this into account.`, `${name} here — confirmed. I'll share with the team!`, `Got it! We'll factor this into ${dept}'s work 📝`],
    [`${dept}の${name}、確認しました！👍`, `承知しました！チームに共有します！`],
    [`${dept}${name}收到！👍`, `明白了！会传达给团队！`],
  ), lang);
}

function scheduleAnnouncementReplies(announcement: string): void {
  const lang = resolveLang(announcement);
  const teamLeaders = db.prepare(
    "SELECT * FROM agents WHERE role = 'team_leader' AND status != 'offline'"
  ).all() as AgentRow[];

  let delay = 1500; // First reply after 1.5s
  for (const leader of teamLeaders) {
    const replyDelay = delay + Math.random() * 1500; // stagger each leader by 1.5-3s
    setTimeout(() => {
      const reply = generateAnnouncementReply(leader, announcement, lang);
      sendAgentMessage(leader, reply, "chat", "all", null, null);
    }, replyDelay);
    delay += 1500 + Math.random() * 1500;
  }
}

// ---- Task delegation logic for team leaders ----

function detectTargetDepartments(message: string): string[] {
  const found: string[] = [];
  for (const [deptId, keywords] of Object.entries(DEPT_KEYWORDS)) {
    for (const kw of keywords) {
      if (message.includes(kw)) { found.push(deptId); break; }
    }
  }
  return found;
}

/** Detect @mentions in messages — returns department IDs and agent IDs */
function detectMentions(message: string): { deptIds: string[]; agentIds: string[] } {
  const deptIds: string[] = [];
  const agentIds: string[] = [];

  // Match @부서이름 patterns (both with and without 팀 suffix)
  const depts = db.prepare("SELECT id, name, name_ko FROM departments").all() as { id: string; name: string; name_ko: string }[];
  for (const dept of depts) {
    const nameKo = dept.name_ko.replace("팀", "");
    if (
      message.includes(`@${dept.name_ko}`) ||
      message.includes(`@${nameKo}`) ||
      message.includes(`@${dept.name}`) ||
      message.includes(`@${dept.id}`)
    ) {
      deptIds.push(dept.id);
    }
  }

  // Match @에이전트이름 patterns
  const agents = db.prepare("SELECT id, name, name_ko FROM agents").all() as { id: string; name: string; name_ko: string | null }[];
  for (const agent of agents) {
    if (
      (agent.name_ko && message.includes(`@${agent.name_ko}`)) ||
      message.includes(`@${agent.name}`)
    ) {
      agentIds.push(agent.id);
    }
  }

  return { deptIds, agentIds };
}

/** Handle mention-based delegation: create task in mentioned department */
function handleMentionDelegation(
  originLeader: AgentRow,
  targetDeptId: string,
  ceoMessage: string,
  lang: Lang,
): void {
  const crossLeader = findTeamLeader(targetDeptId);
  if (!crossLeader) return;
  const crossDeptName = getDeptName(targetDeptId);
  const crossLeaderName = lang === "ko" ? (crossLeader.name_ko || crossLeader.name) : crossLeader.name;
  const originLeaderName = lang === "ko" ? (originLeader.name_ko || originLeader.name) : originLeader.name;
  const taskTitle = ceoMessage.length > 60 ? ceoMessage.slice(0, 57) + "..." : ceoMessage;

  // Origin team leader sends mention request to target team leader
  const mentionReq = pickL(l(
    [`${crossLeaderName}님! 대표님 지시입니다: "${taskTitle}" — ${crossDeptName}에서 처리 부탁드립니다! 🏷️`, `${crossLeaderName}님, 대표님이 직접 요청하셨습니다. "${taskTitle}" 건, ${crossDeptName} 담당으로 진행해주세요!`],
    [`${crossLeaderName}! CEO directive for ${crossDeptName}: "${taskTitle}" — please handle this! 🏷️`, `${crossLeaderName}, CEO requested this for your team: "${taskTitle}"`],
    [`${crossLeaderName}さん！CEO指示です："${taskTitle}" — ${crossDeptName}で対応お願いします！🏷️`],
    [`${crossLeaderName}，CEO指示："${taskTitle}" — 请${crossDeptName}处理！🏷️`],
  ), lang);
  sendAgentMessage(originLeader, mentionReq, "task_assign", "agent", crossLeader.id, null);

  // Broadcast delivery animation event for UI
  broadcast("cross_dept_delivery", {
    from_agent_id: originLeader.id,
    to_agent_id: crossLeader.id,
    task_title: taskTitle,
  });

  // Target team leader acknowledges and delegates
  const ackDelay = 1500 + Math.random() * 1000;
  setTimeout(() => {
    // Use the full delegation flow for the target department
    handleTaskDelegation(crossLeader, ceoMessage, "");
  }, ackDelay);
}

function findBestSubordinate(deptId: string, excludeId: string): AgentRow | null {
  // Find subordinates in department, prefer: idle > break, higher role first
  const agents = db.prepare(
    `SELECT * FROM agents WHERE department_id = ? AND id != ? AND role != 'team_leader' ORDER BY
       CASE status WHEN 'idle' THEN 0 WHEN 'break' THEN 1 WHEN 'working' THEN 2 ELSE 3 END,
       CASE role WHEN 'senior' THEN 0 WHEN 'junior' THEN 1 WHEN 'intern' THEN 2 ELSE 3 END`
  ).all(deptId, excludeId) as AgentRow[];
  return agents[0] ?? null;
}

function findTeamLeader(deptId: string | null): AgentRow | null {
  if (!deptId) return null;
  return (db.prepare(
    "SELECT * FROM agents WHERE department_id = ? AND role = 'team_leader' LIMIT 1"
  ).get(deptId) as AgentRow | undefined) ?? null;
}

function getDeptName(deptId: string): string {
  const d = db.prepare("SELECT name_ko FROM departments WHERE id = ?").get(deptId) as { name_ko: string } | undefined;
  return d?.name_ko ?? deptId;
}

// Role enforcement: restrict agents to their department's domain
function getDeptRoleConstraint(deptId: string, deptName: string): string {
  const constraints: Record<string, string> = {
    planning: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Planning). Focus ONLY on planning, strategy, market analysis, requirements, and documentation. Do NOT write production code, create design assets, or run tests. If coding/design is needed, describe requirements and specifications instead.`,
    dev: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Development). Focus ONLY on coding, debugging, code review, and technical implementation. Do NOT create design mockups, write business strategy documents, or perform QA testing.`,
    design: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Design). Focus ONLY on UI/UX design, visual assets, design specs, and prototyping. Do NOT write production backend code, run tests, or make infrastructure changes.`,
    qa: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (QA/QC). Focus ONLY on testing, quality assurance, test automation, and bug reporting. Do NOT write production code or create design assets.`,
    devsecops: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (DevSecOps). Focus ONLY on infrastructure, security audits, CI/CD pipelines, container orchestration, and deployment. Do NOT write business logic or create design assets.`,
    operations: `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName} (Operations). Focus ONLY on operations, automation, monitoring, maintenance, and process optimization. Do NOT write production code or create design assets.`,
  };
  return constraints[deptId] || `IMPORTANT ROLE CONSTRAINT: You belong to ${deptName}. Focus on tasks within your department's expertise.`;
}

// ---------------------------------------------------------------------------
// Subtask cross-department delegation: sequential per-subtask delegation
// ---------------------------------------------------------------------------

interface SubtaskRow {
  id: string;
  task_id: string;
  title: string;
  description: string | null;
  status: string;
  target_department_id: string | null;
  delegated_task_id: string | null;
  blocked_reason: string | null;
}

/**
 * Build a context-rich prompt for the delegated agent, showing full project context
 * and all subtask statuses so the agent understands the bigger picture.
 */
function buildSubtaskDelegationPrompt(
  parentTask: { id: string; title: string; description: string | null; project_path: string | null },
  subtask: SubtaskRow,
  execAgent: AgentRow,
  targetDeptId: string,
  targetDeptName: string,
): string {
  const lang = resolveLang(parentTask.description ?? parentTask.title);
  // Gather all sibling subtasks for context
  const allSubtasks = db.prepare(
    "SELECT id, title, status, target_department_id FROM subtasks WHERE task_id = ? ORDER BY created_at"
  ).all(parentTask.id) as Array<{ id: string; title: string; status: string; target_department_id: string | null }>;

  const statusIcon: Record<string, string> = {
    done: "✅", in_progress: "🔨", pending: "⏳", blocked: "🔒",
  };

  const subtaskLines = allSubtasks.map(st => {
    const icon = statusIcon[st.status] || "⏳";
    const deptLabel = st.target_department_id ? getDeptName(st.target_department_id) : getDeptName(parentTask.description ? "" : "");
    const parentDept = db.prepare("SELECT department_id FROM tasks WHERE id = ?").get(parentTask.id) as { department_id: string | null } | undefined;
    const dept = st.target_department_id ? getDeptName(st.target_department_id) : getDeptName(parentDept?.department_id ?? "");
    const marker = st.id === subtask.id
      ? pickL(l(
        [" ← 당신의 담당"],
        [" <- assigned to you"],
        [" ← あなたの担当"],
        [" <- 你的负责项"],
      ), lang)
      : "";
    return `${icon} ${st.title} (${dept} - ${st.status})${marker}`;
  }).join("\n");

  const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[execAgent.role] || execAgent.role;
  const deptConstraint = getDeptRoleConstraint(targetDeptId, targetDeptName);
  const conversationCtx = getRecentConversationContext(execAgent.id);
  const agentDisplayName = getAgentDisplayName(execAgent, lang);
  const header = pickL(l(
    [`[프로젝트 협업 업무 - ${targetDeptName}]`],
    [`[Project collaboration task - ${targetDeptName}]`],
    [`[プロジェクト協業タスク - ${targetDeptName}]`],
    [`[项目协作任务 - ${targetDeptName}]`],
  ), lang);
  const originalTaskLabel = pickL(l(["원본 업무"], ["Original task"], ["元タスク"], ["原始任务"]), lang);
  const ceoRequestLabel = pickL(l(["CEO 요청"], ["CEO request"], ["CEO依頼"], ["CEO指示"]), lang);
  const allSubtasksLabel = pickL(l(["전체 서브태스크 현황"], ["All subtask status"], ["全サブタスク状況"], ["全部 SubTask 状态"]), lang);
  const deptOwnedLabel = pickL(l(
    [`[${targetDeptName} 담당 업무]`],
    [`[${targetDeptName} owned task]`],
    [`[${targetDeptName}担当タスク]`],
    [`[${targetDeptName}负责任务]`],
  ), lang);
  const titleLabel = pickL(l(["제목"], ["Title"], ["タイトル"], ["标题"]), lang);
  const descriptionLabel = pickL(l(["설명"], ["Description"], ["説明"], ["说明"]), lang);
  const finalInstruction = pickL(l(
    ["위 프로젝트의 전체 맥락을 파악한 뒤, 담당 업무만 수행해주세요."],
    ["Understand the full project context, then execute only the assigned scope."],
    ["プロジェクト全体の文脈を把握したうえで、担当範囲のみを実行してください。"],
    ["先理解项目全局上下文，再只执行你负责的范围。"],
  ), lang);

  return [
    header,
    ``,
    `${originalTaskLabel}: ${parentTask.title}`,
    parentTask.description ? `${ceoRequestLabel}: ${parentTask.description}` : "",
    ``,
    `[${allSubtasksLabel}]`,
    subtaskLines,
    ``,
    deptOwnedLabel,
    `${titleLabel}: ${subtask.title}`,
    subtask.description ? `${descriptionLabel}: ${subtask.description}` : "",
    conversationCtx ? `\n${conversationCtx}` : "",
    ``,
    `---`,
    `Agent: ${agentDisplayName} (${roleLabel}, ${targetDeptName})`,
    execAgent.personality ? `Personality: ${execAgent.personality}` : "",
    deptConstraint,
    ``,
    finalInstruction,
  ].filter(Boolean).join("\n");
}

/**
 * Process all foreign-department subtasks after the main agent completes.
 * Kicks off sequential delegation starting from index 0.
 */
function processSubtaskDelegations(taskId: string): void {
  const foreignSubtasks = db.prepare(
    "SELECT * FROM subtasks WHERE task_id = ? AND target_department_id IS NOT NULL AND delegated_task_id IS NULL ORDER BY created_at"
  ).all(taskId) as SubtaskRow[];

  if (foreignSubtasks.length === 0) return;

  const parentTask = db.prepare(
    "SELECT * FROM tasks WHERE id = ?"
  ).get(taskId) as { id: string; title: string; description: string | null; project_path: string | null; department_id: string | null } | undefined;
  if (!parentTask) return;
  const lang = resolveLang(parentTask.description ?? parentTask.title);

  notifyCeo(pickL(l(
    [`'${parentTask.title}' 의 외부 부서 서브태스크 ${foreignSubtasks.length}건을 순차 위임합니다.`],
    [`Delegating ${foreignSubtasks.length} external-department subtasks for '${parentTask.title}' in sequence.`],
    [`'${parentTask.title}' の他部門サブタスク${foreignSubtasks.length}件を順次委任します。`],
    [`将按顺序委派'${parentTask.title}'的${foreignSubtasks.length}个外部门 SubTask。`],
  ), lang), taskId);
  delegateSubtaskSequential(foreignSubtasks, 0, parentTask);
}

/**
 * Sequentially delegate one subtask at a time to foreign departments.
 * When one finishes, the callback triggers the next.
 */
function delegateSubtaskSequential(
  subtasks: SubtaskRow[],
  index: number,
  parentTask: { id: string; title: string; description: string | null; project_path: string | null; department_id: string | null },
): void {
  const lang = resolveLang(parentTask.description ?? parentTask.title);
  if (index >= subtasks.length) {
    // All delegations complete — check if everything is done
    const remaining = db.prepare(
      "SELECT COUNT(*) as cnt FROM subtasks WHERE task_id = ? AND status != 'done'"
    ).get(parentTask.id) as { cnt: number };
    if (remaining.cnt === 0) {
      notifyCeo(pickL(l(
        [`'${parentTask.title}' 의 모든 서브태스크(부서간 협업 포함)가 완료되었습니다. ✅`],
        [`All subtasks for '${parentTask.title}' (including cross-department collaboration) are complete. ✅`],
        [`'${parentTask.title}' の全サブタスク（部門間協業含む）が完了しました。✅`],
        [`'${parentTask.title}'的全部 SubTask（含跨部门协作）已完成。✅`],
      ), lang), parentTask.id);
    }
    return;
  }

  const subtask = subtasks[index];
  const targetDeptId = subtask.target_department_id!;
  const targetDeptName = getDeptName(targetDeptId);

  const crossLeader = findTeamLeader(targetDeptId);
  if (!crossLeader) {
    // No team leader — mark subtask as done with note and skip
    db.prepare(
      "UPDATE subtasks SET status = 'done', completed_at = ?, blocked_reason = NULL WHERE id = ?"
    ).run(nowMs(), subtask.id);
    const updated = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(subtask.id);
    broadcast("subtask_update", updated);
    delegateSubtaskSequential(subtasks, index + 1, parentTask);
    return;
  }

  // Find the originator team leader for messaging
  const originLeader = findTeamLeader(parentTask.department_id);
  const originLeaderName = originLeader
    ? getAgentDisplayName(originLeader, lang)
    : pickL(l(["팀장"], ["Team Lead"], ["チームリーダー"], ["组长"]), lang);
  const crossLeaderName = getAgentDisplayName(crossLeader, lang);

  // Notify queue progress
  if (subtasks.length > 1) {
    notifyCeo(pickL(l(
      [`서브태스크 위임 진행: ${targetDeptName} (${index + 1}/${subtasks.length})`],
      [`Subtask delegation in progress: ${targetDeptName} (${index + 1}/${subtasks.length})`],
      [`サブタスク委任進行中: ${targetDeptName} (${index + 1}/${subtasks.length})`],
      [`SubTask 委派进行中：${targetDeptName}（${index + 1}/${subtasks.length}）`],
    ), lang), parentTask.id);
  }

  // Send cooperation request message
  if (originLeader) {
    sendAgentMessage(
      originLeader,
      pickL(l(
        [`${crossLeaderName}님, '${parentTask.title}' 프로젝트의 서브태스크 "${subtask.title}" 협조 부탁드립니다! 🤝`],
        [`${crossLeaderName}, please support subtask "${subtask.title}" for project '${parentTask.title}'! 🤝`],
        [`${crossLeaderName}さん、'${parentTask.title}' のサブタスク「${subtask.title}」の協力をお願いします！🤝`],
        [`${crossLeaderName}，请协助项目'${parentTask.title}'的 SubTask「${subtask.title}」！🤝`],
      ), lang),
      "chat", "agent", crossLeader.id, parentTask.id,
    );
  }

  // Broadcast delivery animation
  broadcast("cross_dept_delivery", {
    from_agent_id: originLeader?.id || null,
    to_agent_id: crossLeader.id,
    task_title: subtask.title,
  });

  // Delegate after short delay
  const ackDelay = 1500 + Math.random() * 1000;
  setTimeout(() => {
    const crossSub = findBestSubordinate(targetDeptId, crossLeader.id);
    const execAgent = crossSub || crossLeader;
    const execName = getAgentDisplayName(execAgent, lang);

    // Acknowledge
    sendAgentMessage(
      crossLeader,
      crossSub
        ? pickL(l(
          [`네, ${originLeaderName}님! "${subtask.title}" 건, ${execName}에게 배정하겠습니다 👍`],
          [`Got it, ${originLeaderName}! I'll assign "${subtask.title}" to ${execName}. 👍`],
          [`了解です、${originLeaderName}さん！「${subtask.title}」は${execName}に割り当てます 👍`],
          [`收到，${originLeaderName}！「${subtask.title}」我会分配给${execName} 👍`],
        ), lang)
        : pickL(l(
          [`네, ${originLeaderName}님! "${subtask.title}" 건, 제가 직접 처리하겠습니다 👍`],
          [`Understood, ${originLeaderName}! I'll handle "${subtask.title}" myself. 👍`],
          [`承知しました、${originLeaderName}さん！「${subtask.title}」は私が直接対応します 👍`],
          [`明白，${originLeaderName}！「${subtask.title}」由我亲自处理 👍`],
        ), lang),
      "chat", "agent", null, parentTask.id,
    );

    // Create delegated task
    const delegatedTaskId = randomUUID();
    const ct = nowMs();
    const delegatedTitle = pickL(l(
      [`[서브태스크 협업] ${subtask.title}`],
      [`[Subtask Collaboration] ${subtask.title}`],
      [`[サブタスク協業] ${subtask.title}`],
      [`[SubTask 协作] ${subtask.title}`],
    ), lang);
    const delegatedDescription = pickL(l(
      [`[서브태스크 위임 from ${getDeptName(parentTask.department_id ?? "")}] ${parentTask.description || parentTask.title}`],
      [`[Subtask delegated from ${getDeptName(parentTask.department_id ?? "")}] ${parentTask.description || parentTask.title}`],
      [`[サブタスク委任元 ${getDeptName(parentTask.department_id ?? "")}] ${parentTask.description || parentTask.title}`],
      [`[SubTask 委派来源 ${getDeptName(parentTask.department_id ?? "")}] ${parentTask.description || parentTask.title}`],
    ), lang);
    db.prepare(`
      INSERT INTO tasks (id, title, description, department_id, status, priority, task_type, project_path, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'planned', 1, 'general', ?, ?, ?)
    `).run(delegatedTaskId, delegatedTitle, delegatedDescription, targetDeptId, parentTask.project_path, ct, ct);
    appendTaskLog(delegatedTaskId, "system", `Subtask delegation from '${parentTask.title}' → ${targetDeptName}`);
    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(delegatedTaskId));

    // Assign agent
    const ct2 = nowMs();
    db.prepare(
      "UPDATE tasks SET assigned_agent_id = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
    ).run(execAgent.id, ct2, ct2, delegatedTaskId);
    db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(delegatedTaskId, execAgent.id);
    appendTaskLog(delegatedTaskId, "system", `${crossLeaderName} → ${execName}`);

    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(delegatedTaskId));
    broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(execAgent.id));

    // Link subtask to delegated task
    db.prepare(
      "UPDATE subtasks SET delegated_task_id = ?, status = 'in_progress', blocked_reason = NULL WHERE id = ?"
    ).run(delegatedTaskId, subtask.id);
    const updatedSub = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(subtask.id);
    broadcast("subtask_update", updatedSub);

    // Track mapping for completion handler
    delegatedTaskToSubtask.set(delegatedTaskId, subtask.id);

    // Register callback for next delegation in sequence
    if (index + 1 < subtasks.length) {
      subtaskDelegationCallbacks.set(delegatedTaskId, () => {
        const nextDelay = 2000 + Math.random() * 1000;
        setTimeout(() => {
          delegateSubtaskSequential(subtasks, index + 1, parentTask);
        }, nextDelay);
      });
    } else {
      // Last one — register a final check callback
      subtaskDelegationCallbacks.set(delegatedTaskId, () => {
        delegateSubtaskSequential(subtasks, index + 1, parentTask);
      });
    }

    // Build prompt and spawn CLI agent
    const execProvider = execAgent.cli_provider || "claude";
    if (["claude", "codex", "gemini", "opencode"].includes(execProvider)) {
      const projPath = resolveProjectPath({ project_path: parentTask.project_path, description: parentTask.description, title: parentTask.title });
      const logFilePath = path.join(logsDir, `${delegatedTaskId}.log`);
      const spawnPrompt = buildSubtaskDelegationPrompt(parentTask, subtask, execAgent, targetDeptId, targetDeptName);

      appendTaskLog(delegatedTaskId, "system", `RUN start (agent=${execAgent.name}, provider=${execProvider})`);
      const delegateModelConfig = getProviderModelConfig();
      const delegateModel = delegateModelConfig[execProvider]?.model || undefined;
      const delegateReasoningLevel = delegateModelConfig[execProvider]?.reasoningLevel || undefined;
      const child = spawnCliAgent(delegatedTaskId, execProvider, spawnPrompt, projPath, logFilePath, delegateModel, delegateReasoningLevel);
      child.on("close", (code) => {
        handleSubtaskDelegationComplete(delegatedTaskId, subtask.id, code ?? 1);
      });

      notifyCeo(pickL(l(
        [`${targetDeptName} ${execName}가 서브태스크 '${subtask.title}' 작업을 시작했습니다.`],
        [`${targetDeptName} ${execName} started subtask '${subtask.title}'.`],
        [`${targetDeptName}の${execName}がサブタスク「${subtask.title}」を開始しました。`],
        [`${targetDeptName} 的 ${execName} 已开始 SubTask「${subtask.title}」。`],
      ), lang), delegatedTaskId);
      startProgressTimer(delegatedTaskId, delegatedTitle, targetDeptId);
    }
  }, ackDelay);
}

/**
 * Handle completion of a delegated subtask task.
 */
function handleSubtaskDelegationComplete(delegatedTaskId: string, subtaskId: string, exitCode: number): void {
  // Use standard completion flow for the delegated task itself
  handleTaskRunComplete(delegatedTaskId, exitCode);

  if (exitCode === 0) {
    // Mark the linked subtask as done
    db.prepare(
      "UPDATE subtasks SET status = 'done', completed_at = ?, blocked_reason = NULL WHERE id = ?"
    ).run(nowMs(), subtaskId);
  } else {
    // Mark subtask as blocked with failure reason
    const lang = getPreferredLanguage();
    const blockedReason = pickL(l(
      ["위임 작업 실패"],
      ["Delegated task failed"],
      ["委任タスク失敗"],
      ["委派任务失败"],
    ), lang);
    db.prepare(
      "UPDATE subtasks SET status = 'blocked', blocked_reason = ? WHERE id = ?"
    ).run(blockedReason, subtaskId);
  }

  const updatedSub = db.prepare("SELECT * FROM subtasks WHERE id = ?").get(subtaskId);
  broadcast("subtask_update", updatedSub);

  // Check if ALL subtasks of the parent task are now done
  const sub = db.prepare("SELECT task_id FROM subtasks WHERE id = ?").get(subtaskId) as { task_id: string } | undefined;
  if (sub && exitCode === 0) {
    const remaining = db.prepare(
      "SELECT COUNT(*) as cnt FROM subtasks WHERE task_id = ? AND status != 'done'"
    ).get(sub.task_id) as { cnt: number };
    if (remaining.cnt === 0) {
      const parentTask = db.prepare("SELECT title, description, status FROM tasks WHERE id = ?").get(sub.task_id) as { title: string; description: string | null; status: string } | undefined;
      if (parentTask) {
        const lang = resolveLang(parentTask.description ?? parentTask.title);
        notifyCeo(pickL(l(
          [`'${parentTask.title}' 의 모든 서브태스크(부서간 협업 포함)가 완료되었습니다. ✅`],
          [`All subtasks for '${parentTask.title}' (including cross-department collaboration) are complete. ✅`],
          [`'${parentTask.title}' の全サブタスク（部門間協業含む）が完了しました。✅`],
          [`'${parentTask.title}'的全部 SubTask（含跨部门协作）已完成。✅`],
        ), lang), sub.task_id);
        if (parentTask.status === "review") {
          setTimeout(() => finishReview(sub.task_id, parentTask.title), 1200);
        }
      }
    }
  }

  // Trigger next delegation callback (handled via subtaskDelegationCallbacks in finishReview)
  // The callback is triggered after finishReview completes for the delegated task
}

// ---------------------------------------------------------------------------
// Sequential cross-department cooperation: one department at a time
// ---------------------------------------------------------------------------
interface CrossDeptContext {
  teamLeader: AgentRow;
  taskTitle: string;
  ceoMessage: string;
  leaderDeptId: string;
  leaderDeptName: string;
  leaderName: string;
  lang: Lang;
  taskId: string;
}

function startCrossDeptCooperation(
  deptIds: string[],
  index: number,
  ctx: CrossDeptContext,
  onAllDone?: () => void,
): void {
  if (index >= deptIds.length) {
    onAllDone?.();
    return;
  }

  const crossDeptId = deptIds[index];
  const crossLeader = findTeamLeader(crossDeptId);
  if (!crossLeader) {
    // Skip this dept, try next
    startCrossDeptCooperation(deptIds, index + 1, ctx, onAllDone);
    return;
  }

  const { teamLeader, taskTitle, ceoMessage, leaderDeptName, leaderName, lang, taskId } = ctx;
  const crossDeptName = getDeptName(crossDeptId);
  const crossLeaderName = lang === "ko" ? (crossLeader.name_ko || crossLeader.name) : crossLeader.name;

  // Notify remaining queue
  if (deptIds.length > 1) {
    const remaining = deptIds.length - index;
    notifyCeo(pickL(l(
      [`협업 요청 진행 중: ${crossDeptName} (${index + 1}/${deptIds.length}, 남은 ${remaining}팀 순차 진행)`],
      [`Collaboration request in progress: ${crossDeptName} (${index + 1}/${deptIds.length}, ${remaining} team(s) remaining in queue)`],
      [`協業依頼進行中: ${crossDeptName} (${index + 1}/${deptIds.length}、残り${remaining}チーム)`],
      [`协作请求进行中：${crossDeptName}（${index + 1}/${deptIds.length}，队列剩余${remaining}个团队）`],
    ), lang), taskId);
  }

  const coopReq = pickL(l(
    [`${crossLeaderName}님, 안녕하세요! 대표님 지시로 "${taskTitle}" 업무 진행 중인데, ${crossDeptName} 협조가 필요합니다. 도움 부탁드려요! 🤝`, `${crossLeaderName}님! "${taskTitle}" 건으로 ${crossDeptName} 지원이 필요합니다. 시간 되시면 협의 부탁드립니다.`],
    [`Hi ${crossLeaderName}! We're working on "${taskTitle}" per CEO's directive and need ${crossDeptName}'s support. Could you help? 🤝`, `${crossLeaderName}, we need ${crossDeptName}'s input on "${taskTitle}". Let's sync when you have a moment.`],
    [`${crossLeaderName}さん、CEO指示の"${taskTitle}"で${crossDeptName}の協力が必要です。お願いします！🤝`],
    [`${crossLeaderName}，CEO安排的"${taskTitle}"需要${crossDeptName}配合，麻烦协调一下！🤝`],
  ), lang);
  sendAgentMessage(teamLeader, coopReq, "chat", "agent", crossLeader.id, taskId);

  // Broadcast delivery animation event for UI
  broadcast("cross_dept_delivery", {
    from_agent_id: teamLeader.id,
    to_agent_id: crossLeader.id,
    task_title: taskTitle,
  });

  // Cross-department leader acknowledges AND creates a real task
  const crossAckDelay = 1500 + Math.random() * 1000;
  setTimeout(() => {
    const crossSub = findBestSubordinate(crossDeptId, crossLeader.id);
    const crossSubName = crossSub
      ? (lang === "ko" ? (crossSub.name_ko || crossSub.name) : crossSub.name)
      : null;

    const crossAckMsg = crossSub
      ? pickL(l(
        [`네, ${leaderName}님! 확인했습니다. ${crossSubName}에게 바로 배정하겠습니다 👍`, `알겠습니다! ${crossSubName}가 지원하도록 하겠습니다. 진행 상황 공유드릴게요.`],
        [`Sure, ${leaderName}! I'll assign ${crossSubName} to support right away 👍`, `Got it! ${crossSubName} will handle the ${crossDeptName} side. I'll keep you posted.`],
        [`了解しました、${leaderName}さん！${crossSubName}を割り当てます 👍`],
        [`好的，${leaderName}！安排${crossSubName}支援 👍`],
      ), lang)
      : pickL(l(
        [`네, ${leaderName}님! 확인했습니다. 제가 직접 처리하겠습니다 👍`],
        [`Sure, ${leaderName}! I'll handle it personally 👍`],
        [`了解しました！私が直接対応します 👍`],
        [`好的！我亲自来处理 👍`],
      ), lang);
    sendAgentMessage(crossLeader, crossAckMsg, "chat", "agent", null, taskId);

    // Create actual task in the cross-department
    const crossTaskId = randomUUID();
    const ct = nowMs();
    const crossTaskTitle = pickL(l(
      [`[협업] ${taskTitle}`],
      [`[Collaboration] ${taskTitle}`],
      [`[協業] ${taskTitle}`],
      [`[协作] ${taskTitle}`],
    ), lang);
    const crossDetectedPath = detectProjectPath(ceoMessage);
    db.prepare(`
      INSERT INTO tasks (id, title, description, department_id, status, priority, task_type, project_path, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'planned', 1, 'general', ?, ?, ?)
    `).run(crossTaskId, crossTaskTitle, `[Cross-dept from ${leaderDeptName}] ${ceoMessage}`, crossDeptId, crossDetectedPath, ct, ct);
    appendTaskLog(crossTaskId, "system", `Cross-dept request from ${leaderName} (${leaderDeptName})`);
    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(crossTaskId));

    // Delegate to cross-dept subordinate and spawn CLI
    const execAgent = crossSub || crossLeader;
    const execName = lang === "ko" ? (execAgent.name_ko || execAgent.name) : execAgent.name;
    const ct2 = nowMs();
    db.prepare(
      "UPDATE tasks SET assigned_agent_id = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
    ).run(execAgent.id, ct2, ct2, crossTaskId);
    db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(crossTaskId, execAgent.id);
    appendTaskLog(crossTaskId, "system", `${crossLeaderName} → ${execName}`);

    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(crossTaskId));
    broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(execAgent.id));

    // Register callback to start next department when this one finishes
    if (index + 1 < deptIds.length) {
      crossDeptNextCallbacks.set(crossTaskId, () => {
        const nextDelay = 2000 + Math.random() * 1000;
        setTimeout(() => {
          startCrossDeptCooperation(deptIds, index + 1, ctx, onAllDone);
        }, nextDelay);
      });
    } else if (onAllDone) {
      // Last department in the queue: continue only after this cross task completes review.
      crossDeptNextCallbacks.set(crossTaskId, () => {
        const nextDelay = 1200 + Math.random() * 800;
        setTimeout(() => onAllDone(), nextDelay);
      });
    }

    // Actually spawn the CLI agent
    const execProvider = execAgent.cli_provider || "claude";
    if (["claude", "codex", "gemini", "opencode"].includes(execProvider)) {
      const crossTaskData = db.prepare("SELECT * FROM tasks WHERE id = ?").get(crossTaskId) as {
        title: string; description: string | null; project_path: string | null;
      } | undefined;
      if (crossTaskData) {
        const projPath = resolveProjectPath(crossTaskData);
        const logFilePath = path.join(logsDir, `${crossTaskId}.log`);
        const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[execAgent.role] || execAgent.role;
        const deptConstraint = getDeptRoleConstraint(crossDeptId, crossDeptName);
        const crossConversationCtx = getRecentConversationContext(execAgent.id);
        const spawnPrompt = [
          `[Task] ${crossTaskData.title}`,
          crossTaskData.description ? `\n${crossTaskData.description}` : "",
          crossConversationCtx,
          `\n---`,
          `Agent: ${execAgent.name} (${roleLabel}, ${crossDeptName})`,
          execAgent.personality ? `Personality: ${execAgent.personality}` : "",
          deptConstraint,
          `Please complete the task above thoroughly. Use the conversation context above if relevant.`,
        ].filter(Boolean).join("\n");

        appendTaskLog(crossTaskId, "system", `RUN start (agent=${execAgent.name}, provider=${execProvider})`);
        const crossModelConfig = getProviderModelConfig();
        const crossModel = crossModelConfig[execProvider]?.model || undefined;
        const crossReasoningLevel = crossModelConfig[execProvider]?.reasoningLevel || undefined;
        const child = spawnCliAgent(crossTaskId, execProvider, spawnPrompt, projPath, logFilePath, crossModel, crossReasoningLevel);
        child.on("close", (code) => {
          handleTaskRunComplete(crossTaskId, code ?? 1);
        });

        notifyCeo(pickL(l(
          [`${crossDeptName} ${execName}가 '${taskTitle}' 협업 작업을 시작했습니다.`],
          [`${crossDeptName} ${execName} started collaboration work for '${taskTitle}'.`],
          [`${crossDeptName}の${execName}が「${taskTitle}」の協業作業を開始しました。`],
          [`${crossDeptName} 的 ${execName} 已开始「${taskTitle}」协作工作。`],
        ), lang), crossTaskId);
        startProgressTimer(crossTaskId, crossTaskData.title, crossDeptId);
      }
    }
  }, crossAckDelay);
}

/**
 * Detect project path from CEO message.
 * Recognizes:
 * 1. Absolute paths: /Users/classys/Projects/foo, ~/Projects/bar
 * 2. Project names: "climpire 프로젝트", "claw-kanban에서"
 * 3. Known project directories under ~/Projects
 */
function detectProjectPath(message: string): string | null {
  const homeDir = os.homedir();
  const projectsDir = path.join(homeDir, "Projects");
  const projectsDirLower = path.join(homeDir, "projects");

  // 1. Explicit absolute path in message
  const absMatch = message.match(/(?:^|\s)(\/[\w./-]+)/);
  if (absMatch) {
    const p = absMatch[1];
    // Check if it's a real directory
    try {
      if (fs.statSync(p).isDirectory()) return p;
    } catch {}
    // Check parent directory
    const parent = path.dirname(p);
    try {
      if (fs.statSync(parent).isDirectory()) return parent;
    } catch {}
  }

  // 2. ~ path
  const tildeMatch = message.match(/~\/([\w./-]+)/);
  if (tildeMatch) {
    const expanded = path.join(homeDir, tildeMatch[1]);
    try {
      if (fs.statSync(expanded).isDirectory()) return expanded;
    } catch {}
  }

  // 3. Scan known project directories and match by name
  let knownProjects: string[] = [];
  for (const pDir of [projectsDir, projectsDirLower]) {
    try {
      const entries = fs.readdirSync(pDir, { withFileTypes: true });
      knownProjects = knownProjects.concat(
        entries.filter(e => e.isDirectory() && !e.name.startsWith('.')).map(e => e.name)
      );
    } catch {}
  }

  // Match project names in the message (case-insensitive)
  const msgLower = message.toLowerCase();
  for (const proj of knownProjects) {
    if (msgLower.includes(proj.toLowerCase())) {
      // Return the actual path
      const fullPath = path.join(projectsDir, proj);
      try {
        if (fs.statSync(fullPath).isDirectory()) return fullPath;
      } catch {}
      const fullPathLower = path.join(projectsDirLower, proj);
      try {
        if (fs.statSync(fullPathLower).isDirectory()) return fullPathLower;
      } catch {}
    }
  }

  return null;
}

/** Resolve project path: task.project_path → detect from message → cwd */
function resolveProjectPath(task: { project_path?: string | null; description?: string | null; title?: string }): string {
  if (task.project_path) return task.project_path;
  // Try to detect from description or title
  const detected = detectProjectPath(task.description || "") || detectProjectPath(task.title || "");
  return detected || process.cwd();
}

function handleTaskDelegation(
  teamLeader: AgentRow,
  ceoMessage: string,
  ceoMsgId: string,
): void {
  const lang = resolveLang(ceoMessage);
  const leaderName = lang === "ko" ? (teamLeader.name_ko || teamLeader.name) : teamLeader.name;
  const leaderDeptId = teamLeader.department_id!;
  const leaderDeptName = getDeptName(leaderDeptId);

  // --- Step 1: Team leader acknowledges (1~2 sec) ---
  const ackDelay = 1000 + Math.random() * 1000;
  setTimeout(() => {
    const subordinate = findBestSubordinate(leaderDeptId, teamLeader.id);

    const taskId = randomUUID();
    const t = nowMs();
    const taskTitle = ceoMessage.length > 60 ? ceoMessage.slice(0, 57) + "..." : ceoMessage;
    const detectedPath = detectProjectPath(ceoMessage);
    db.prepare(`
      INSERT INTO tasks (id, title, description, department_id, status, priority, task_type, project_path, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'planned', 1, 'general', ?, ?, ?)
    `).run(taskId, taskTitle, `[CEO] ${ceoMessage}`, leaderDeptId, detectedPath, t, t);
    appendTaskLog(taskId, "system", `CEO → ${leaderName}: ${ceoMessage}`);
    if (detectedPath) {
      appendTaskLog(taskId, "system", `Project path detected: ${detectedPath}`);
    }

    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));

    const mentionedDepts = [...new Set(
      detectTargetDepartments(ceoMessage).filter((d) => d !== leaderDeptId)
    )];
    const isPlanningLead = leaderDeptId === "planning";

    if (isPlanningLead) {
      const relatedLabel = mentionedDepts.length > 0
        ? mentionedDepts.map(getDeptName).join(", ")
        : pickL(l(["없음"], ["None"], ["なし"], ["无"]), lang);
      appendTaskLog(taskId, "system", `Planning pre-check related departments: ${relatedLabel}`);
      notifyCeo(pickL(l(
        [`[기획팀] '${taskTitle}' 유관부서 사전 파악 완료: ${relatedLabel}`],
        [`[Planning] Related departments identified for '${taskTitle}': ${relatedLabel}`],
        [`[企画] '${taskTitle}' の関連部門の事前把握が完了: ${relatedLabel}`],
        [`[企划] 已完成'${taskTitle}'相关部门预识别：${relatedLabel}`],
      ), lang), taskId);
    }

    const runCrossDeptBeforeDelegationIfNeeded = (next: () => void) => {
      if (!(isPlanningLead && mentionedDepts.length > 0)) {
        next();
        return;
      }

      const crossDeptNames = mentionedDepts.map(getDeptName).join(", ");
      notifyCeo(pickL(l(
        [`[CEO OFFICE] 기획팀 선행 협업 처리 시작: ${crossDeptNames}`],
        [`[CEO OFFICE] Planning pre-collaboration started with: ${crossDeptNames}`],
        [`[CEO OFFICE] 企画チームの先行協業を開始: ${crossDeptNames}`],
        [`[CEO OFFICE] 企划团队前置协作已启动：${crossDeptNames}`],
      ), lang), taskId);
      startCrossDeptCooperation(
        mentionedDepts,
        0,
        { teamLeader, taskTitle, ceoMessage, leaderDeptId, leaderDeptName, leaderName, lang, taskId },
        () => {
          notifyCeo(pickL(l(
            ["[CEO OFFICE] 유관부서 선행 처리 완료. 이제 내부 업무 하달을 시작합니다."],
            ["[CEO OFFICE] Related-department pre-processing complete. Starting internal delegation now."],
            ["[CEO OFFICE] 関連部門の先行処理が完了。これより内部委任を開始します。"],
            ["[CEO OFFICE] 相关部门前置处理完成，现开始内部下达。"],
          ), lang), taskId);
          next();
        },
      );
    };

    const runCrossDeptAfterMainIfNeeded = () => {
      if (isPlanningLead || mentionedDepts.length === 0) return;
      const crossDelay = 3000 + Math.random() * 1000;
      setTimeout(() => {
        startCrossDeptCooperation(mentionedDepts, 0, {
          teamLeader, taskTitle, ceoMessage, leaderDeptId, leaderDeptName, leaderName, lang, taskId,
        });
      }, crossDelay);
    };

    if (subordinate) {
      const subName = lang === "ko" ? (subordinate.name_ko || subordinate.name) : subordinate.name;
      const subRole = getRoleLabel(subordinate.role, lang);

      let ackMsg: string;
      if (isPlanningLead && mentionedDepts.length > 0) {
        const crossDeptNames = mentionedDepts.map(getDeptName).join(", ");
        ackMsg = pickL(l(
          [`네, 대표님! 먼저 ${crossDeptNames} 유관부서 목록을 확정하고 회의/선행 협업을 완료한 뒤 ${subRole} ${subName}에게 하달하겠습니다. 📋`, `알겠습니다! 기획팀에서 유관부서 선처리까지 마친 뒤 ${subName}에게 최종 하달하겠습니다.`],
          [`Understood. I'll first confirm related departments (${crossDeptNames}), finish cross-team pre-processing, then delegate to ${subRole} ${subName}. 📋`],
          [`了解しました。まず関連部門（${crossDeptNames}）を確定し、先行協業完了後に${subRole} ${subName}へ委任します。📋`],
          [`收到。先确认相关部门（${crossDeptNames}）并完成前置协作后，再下达给${subRole} ${subName}。📋`],
        ), lang);
      } else if (mentionedDepts.length > 0) {
        const crossDeptNames = mentionedDepts.map(getDeptName).join(", ");
        ackMsg = pickL(l(
          [`네, 대표님! 먼저 팀장 승인 회의를 진행한 뒤 ${subRole} ${subName}에게 하달하고, ${crossDeptNames} 협업도 연계하겠습니다. 📋`, `알겠습니다! 팀장 회의에서 착수안 승인 완료 후 ${subName} 배정과 ${crossDeptNames} 협업 조율을 진행하겠습니다 🤝`],
          [`Understood. We'll run the team-lead approval meeting first, then delegate to ${subRole} ${subName} and coordinate with ${crossDeptNames}. 📋`, `Got it. After kickoff approval in the leaders' meeting, I'll assign ${subName} and sync with ${crossDeptNames}. 🤝`],
          [`了解しました。まずチームリーダー承認会議を行い、その後 ${subRole} ${subName} へ委任し、${crossDeptNames} との協業も調整します。📋`],
          [`收到。先进行团队负责人审批会议，审批后再下达给${subRole} ${subName}，并协调${crossDeptNames}协作。📋`],
        ), lang);
      } else {
        ackMsg = pickL(l(
          [`네, 대표님! 먼저 팀장 승인 회의를 소집하고, 승인 완료 후 ${subRole} ${subName}에게 하달하겠습니다. 📋`, `알겠습니다! 우리 팀 ${subName}가 적임자이며, 회의 승인 직후 지시하겠습니다. 🚀`, `확인했습니다, 대표님! 팀장 회의 후 ${subName}에게 전달하고 진행 관리하겠습니다.`],
          [`Understood. I'll convene the team-lead approval meeting first, then assign to ${subRole} ${subName} after approval. 📋`, `Got it. ${subName} is the best fit, and I'll delegate right after leaders approve. 🚀`, `Confirmed. After the leaders' meeting, I'll hand this off to ${subName} and manage execution.`],
          [`了解しました。まずチームリーダー承認会議を招集し、承認後に ${subRole} ${subName} へ委任します。📋`, `承知しました。${subName} が最適任なので、会議承認直後に指示します。🚀`],
          [`收到。先召集团队负责人审批会议，审批通过后再分配给${subRole} ${subName}。📋`, `明白。${subName}最合适，会在会议批准后立即下达。🚀`],
        ), lang);
      }
      sendAgentMessage(teamLeader, ackMsg, "chat", "agent", null, taskId);

      const delegateToSubordinate = () => {
        // --- Step 2: Delegate to subordinate (2~3 sec) ---
        const delegateDelay = 2000 + Math.random() * 1000;
        setTimeout(() => {
          const t2 = nowMs();
          db.prepare(
            "UPDATE tasks SET assigned_agent_id = ?, status = 'planned', updated_at = ? WHERE id = ?"
          ).run(subordinate.id, t2, taskId);
          db.prepare("UPDATE agents SET current_task_id = ? WHERE id = ?").run(taskId, subordinate.id);
          appendTaskLog(taskId, "system", `${leaderName} → ${subName}`);

          broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
          broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(subordinate.id));

          const delegateMsg = pickL(l(
            [`${subName}, 대표님 지시사항이야. "${ceoMessage}" — 확인하고 진행해줘!`, `${subName}! 긴급 업무야. "${ceoMessage}" — 우선순위 높게 처리 부탁해.`, `${subName}, 새 업무 할당이야: "${ceoMessage}" — 진행 상황 수시로 공유해줘 👍`],
            [`${subName}, directive from the CEO: "${ceoMessage}" — please handle this!`, `${subName}! Priority task: "${ceoMessage}" — needs immediate attention.`, `${subName}, new assignment: "${ceoMessage}" — keep me posted on progress 👍`],
            [`${subName}、CEOからの指示だよ。"${ceoMessage}" — 確認して進めて！`, `${subName}！優先タスク: "${ceoMessage}" — よろしく頼む 👍`],
            [`${subName}，CEO的指示："${ceoMessage}" — 请跟进处理！`, `${subName}！优先任务："${ceoMessage}" — 随时更新进度 👍`],
          ), lang);
          sendAgentMessage(teamLeader, delegateMsg, "task_assign", "agent", subordinate.id, taskId);

          // --- Step 3: Subordinate acknowledges (1~2 sec) ---
          const subAckDelay = 1000 + Math.random() * 1000;
          setTimeout(() => {
            const leaderRole = getRoleLabel(teamLeader.role, lang);
            const subAckMsg = pickL(l(
              [`네, ${leaderRole} ${leaderName}님! 확인했습니다. 바로 착수하겠습니다! 💪`, `알겠습니다! 바로 시작하겠습니다. 진행 상황 공유 드리겠습니다.`, `확인했습니다, ${leaderName}님! 최선을 다해 처리하겠습니다 🔥`],
              [`Yes, ${leaderName}! Confirmed. Starting right away! 💪`, `Got it! On it now. I'll keep you updated on progress.`, `Confirmed, ${leaderName}! I'll give it my best 🔥`],
              [`はい、${leaderName}さん！了解しました。すぐ取りかかります！💪`, `承知しました！進捗共有します 🔥`],
              [`好的，${leaderName}！收到，马上开始！💪`, `明白了！会及时汇报进度 🔥`],
            ), lang);
            sendAgentMessage(subordinate, subAckMsg, "chat", "agent", null, taskId);
            startTaskExecutionForAgent(taskId, subordinate, leaderDeptId, leaderDeptName);
            runCrossDeptAfterMainIfNeeded();
          }, subAckDelay);
        }, delegateDelay);
      };

      startPlannedApprovalMeeting(taskId, taskTitle, leaderDeptId, () => {
        seedApprovedPlanSubtasks(taskId, leaderDeptId);
        runCrossDeptBeforeDelegationIfNeeded(delegateToSubordinate);
      });
    } else {
      // No subordinate — team leader handles it themselves
      const selfMsg = pickL(l(
        [`네, 대표님! 먼저 팀장 승인 회의를 진행하고, 팀 내 가용 인력이 없어 승인 후 제가 직접 처리하겠습니다. 💪`, `알겠습니다! 팀장 회의 승인 완료 후 제가 직접 진행하겠습니다.`],
        [`Understood. We'll complete the team-lead approval meeting first, and since no one is available I'll execute it myself after approval. 💪`, `Got it. I'll proceed personally after the leaders' approval meeting.`],
        [`了解しました。まずチームリーダー承認会議を行い、空き要員がいないため承認後は私が直接対応します。💪`],
        [`收到。先进行团队负责人审批会议，因无可用成员，审批后由我亲自执行。💪`],
      ), lang);
      sendAgentMessage(teamLeader, selfMsg, "chat", "agent", null, taskId);

      const t2 = nowMs();
      db.prepare(
        "UPDATE tasks SET assigned_agent_id = ?, status = 'planned', updated_at = ? WHERE id = ?"
      ).run(teamLeader.id, t2, taskId);
      db.prepare("UPDATE agents SET current_task_id = ? WHERE id = ?").run(taskId, teamLeader.id);
      appendTaskLog(taskId, "system", `${leaderName} self-assigned (planned)`);

      broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
      broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(teamLeader.id));

      startPlannedApprovalMeeting(taskId, taskTitle, leaderDeptId, () => {
        seedApprovedPlanSubtasks(taskId, leaderDeptId);
        runCrossDeptBeforeDelegationIfNeeded(() => {
          startTaskExecutionForAgent(taskId, teamLeader, leaderDeptId, leaderDeptName);
          runCrossDeptAfterMainIfNeeded();
        });
      });
    }
  }, ackDelay);
}

// ---- Non-team-leader agents: simple chat reply ----

function scheduleAgentReply(agentId: string, ceoMessage: string, messageType: string): void {
  const agent = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
  if (!agent) return;

  // If it's a task_assign to a team leader, use delegation flow
  if (messageType === "task_assign" && agent.role === "team_leader" && agent.department_id) {
    handleTaskDelegation(agent, ceoMessage, "");
    return;
  }

  if (agent.status === "offline") {
    const lang = resolveLang(ceoMessage);
    sendAgentMessage(agent, buildCliFailureMessage(agent, lang, "offline"));
    return;
  }

  // Regular 1:1 reply via real CLI run
  const delay = 1000 + Math.random() * 2000;
  setTimeout(() => {
    void (async () => {
      const activeTask = agent.current_task_id
        ? db.prepare("SELECT title, description, project_path FROM tasks WHERE id = ?").get(agent.current_task_id) as {
          title: string;
          description: string | null;
          project_path: string | null;
        } | undefined
        : undefined;
      const detectedPath = detectProjectPath(ceoMessage);
      const projectPath = detectedPath
        || (activeTask ? resolveProjectPath(activeTask) : process.cwd());

      const built = buildDirectReplyPrompt(agent, ceoMessage, messageType);
      const run = await runAgentOneShot(agent, built.prompt, { projectPath });
      const reply = chooseSafeReply(run, built.lang, "direct", agent);
      sendAgentMessage(agent, reply);
    })();
  }, delay);
}

// ---------------------------------------------------------------------------
// Messages / Chat
// ---------------------------------------------------------------------------
app.get("/api/messages", (req, res) => {
  const receiverType = firstQueryValue(req.query.receiver_type);
  const receiverId = firstQueryValue(req.query.receiver_id);
  const limitRaw = firstQueryValue(req.query.limit);
  const limit = Math.min(Math.max(Number(limitRaw) || 50, 1), 500);

  const conditions: string[] = [];
  const params: unknown[] = [];

  if (receiverType && receiverId) {
    // Conversation with a specific agent: show messages TO and FROM that agent
    conditions.push(
      "((receiver_type = ? AND receiver_id = ?) OR (sender_type = 'agent' AND sender_id = ?) OR receiver_type = 'all')"
    );
    params.push(receiverType, receiverId, receiverId);
  } else if (receiverType) {
    conditions.push("receiver_type = ?");
    params.push(receiverType);
  } else if (receiverId) {
    conditions.push("(receiver_id = ? OR receiver_type = 'all')");
    params.push(receiverId);
  }

  const where = conditions.length ? `WHERE ${conditions.join(" AND ")}` : "";
  params.push(limit);

  const messages = db.prepare(`
    SELECT m.*,
      a.name AS sender_name,
      a.avatar_emoji AS sender_avatar
    FROM messages m
    LEFT JOIN agents a ON m.sender_type = 'agent' AND m.sender_id = a.id
    ${where}
    ORDER BY m.created_at DESC
    LIMIT ?
  `).all(...params);

  res.json({ messages: messages.reverse() }); // return in chronological order
});

app.post("/api/messages", (req, res) => {
  const body = req.body ?? {};
  const id = randomUUID();
  const t = nowMs();

  const content = body.content;
  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "content_required" });
  }

  const senderType = body.sender_type || "ceo";
  const senderId = body.sender_id ?? null;
  const receiverType = body.receiver_type || "all";
  const receiverId = body.receiver_id ?? null;
  const messageType = body.message_type || "chat";
  const taskId = body.task_id ?? null;

  db.prepare(`
    INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(id, senderType, senderId, receiverType, receiverId, content, messageType, taskId, t);

  const msg = {
    id,
    sender_type: senderType,
    sender_id: senderId,
    receiver_type: receiverType,
    receiver_id: receiverId,
    content,
    message_type: messageType,
    task_id: taskId,
    created_at: t,
  };

  broadcast("new_message", msg);

  // Schedule agent auto-reply when CEO messages an agent
  if (senderType === "ceo" && receiverType === "agent" && receiverId) {
    scheduleAgentReply(receiverId, content, messageType);

    // Check for @mentions to other departments/agents
    const mentions = detectMentions(content);
    if (mentions.deptIds.length > 0 || mentions.agentIds.length > 0) {
      const senderAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(receiverId) as AgentRow | undefined;
      if (senderAgent) {
        const lang = resolveLang(content);
        const mentionDelay = 4000 + Math.random() * 2000; // After the main delegation starts
        setTimeout(() => {
          // Handle department mentions
          for (const deptId of mentions.deptIds) {
            if (deptId === senderAgent.department_id) continue; // Skip own department
            handleMentionDelegation(senderAgent, deptId, content, lang);
          }
          // Handle agent mentions — find their department and delegate there
          for (const agentId of mentions.agentIds) {
            const mentioned = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
            if (mentioned && mentioned.department_id && mentioned.department_id !== senderAgent.department_id) {
              if (!mentions.deptIds.includes(mentioned.department_id)) {
                handleMentionDelegation(senderAgent, mentioned.department_id, content, lang);
              }
            }
          }
        }, mentionDelay);
      }
    }
  }

  res.json({ ok: true, message: msg });
});

app.post("/api/announcements", (req, res) => {
  const body = req.body ?? {};
  const content = body.content;
  if (!content || typeof content !== "string") {
    return res.status(400).json({ error: "content_required" });
  }

  const id = randomUUID();
  const t = nowMs();

  db.prepare(`
    INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, created_at)
    VALUES (?, 'ceo', NULL, 'all', NULL, ?, 'announcement', ?)
  `).run(id, content, t);

  const msg = {
    id,
    sender_type: "ceo",
    sender_id: null,
    receiver_type: "all",
    receiver_id: null,
    content,
    message_type: "announcement",
    created_at: t,
  };

  broadcast("announcement", msg);

  // Team leaders respond to announcements with staggered delays
  scheduleAnnouncementReplies(content);

  // Check for @mentions in announcements — trigger delegation
  const mentions = detectMentions(content);
  if (mentions.deptIds.length > 0 || mentions.agentIds.length > 0) {
    const mentionDelay = 5000 + Math.random() * 2000;
    setTimeout(() => {
      const processedDepts = new Set<string>();

      for (const deptId of mentions.deptIds) {
        if (processedDepts.has(deptId)) continue;
        processedDepts.add(deptId);
        const leader = findTeamLeader(deptId);
        if (leader) {
          handleTaskDelegation(leader, content, "");
        }
      }

      for (const agentId of mentions.agentIds) {
        const mentioned = db.prepare("SELECT * FROM agents WHERE id = ?").get(agentId) as AgentRow | undefined;
        if (mentioned?.department_id && !processedDepts.has(mentioned.department_id)) {
          processedDepts.add(mentioned.department_id);
          const leader = findTeamLeader(mentioned.department_id);
          if (leader) {
            handleTaskDelegation(leader, content, "");
          }
        }
      }
    }, mentionDelay);
  }

  res.json({ ok: true, message: msg });
});

// Delete conversation messages
app.delete("/api/messages", (req, res) => {
  const agentId = firstQueryValue(req.query.agent_id);
  const scope = firstQueryValue(req.query.scope) || "conversation"; // "conversation" or "all"

  if (scope === "all") {
    // Delete all messages (announcements + conversations)
    const result = db.prepare("DELETE FROM messages").run();
    broadcast("messages_cleared", { scope: "all" });
    return res.json({ ok: true, deleted: result.changes });
  }

  if (agentId) {
    // Delete messages for a specific agent conversation + announcements shown in that chat
    const result = db.prepare(
      `DELETE FROM messages WHERE
        (sender_type = 'ceo' AND receiver_type = 'agent' AND receiver_id = ?)
        OR (sender_type = 'agent' AND sender_id = ?)
        OR receiver_type = 'all'
        OR message_type = 'announcement'`
    ).run(agentId, agentId);
    broadcast("messages_cleared", { scope: "agent", agent_id: agentId });
    return res.json({ ok: true, deleted: result.changes });
  }

  // Delete only announcements/broadcasts
  const result = db.prepare(
    "DELETE FROM messages WHERE receiver_type = 'all' OR message_type = 'announcement'"
  ).run();
  broadcast("messages_cleared", { scope: "announcements" });
  res.json({ ok: true, deleted: result.changes });
});

// ---------------------------------------------------------------------------
// CLI Status
// ---------------------------------------------------------------------------
app.get("/api/cli-status", async (_req, res) => {
  const refresh = _req.query.refresh === "1";
  const now = Date.now();

  if (!refresh && cachedCliStatus && now - cachedCliStatus.loadedAt < CLI_STATUS_TTL) {
    return res.json({ providers: cachedCliStatus.data });
  }

  try {
    const data = await detectAllCli();
    cachedCliStatus = { data, loadedAt: Date.now() };
    res.json({ providers: data });
  } catch (err) {
    res.status(500).json({ error: "cli_detection_failed", message: String(err) });
  }
});

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------
app.get("/api/settings", (_req, res) => {
  const rows = db.prepare("SELECT key, value FROM settings").all() as { key: string; value: string }[];
  const settings: Record<string, unknown> = {};
  for (const row of rows) {
    try {
      settings[row.key] = JSON.parse(row.value);
    } catch {
      settings[row.key] = row.value;
    }
  }
  res.json({ settings });
});

app.put("/api/settings", (req, res) => {
  const body = req.body ?? {};

  const upsert = db.prepare(
    "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
  );

  for (const [key, value] of Object.entries(body)) {
    upsert.run(key, typeof value === "string" ? value : JSON.stringify(value));
  }

  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// Stats / Dashboard
// ---------------------------------------------------------------------------
app.get("/api/stats", (_req, res) => {
  const totalTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks").get() as { cnt: number }).cnt;
  const doneTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'done'").get() as { cnt: number }).cnt;
  const inProgressTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'in_progress'").get() as { cnt: number }).cnt;
  const inboxTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'inbox'").get() as { cnt: number }).cnt;
  const plannedTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'planned'").get() as { cnt: number }).cnt;
  const reviewTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'review'").get() as { cnt: number }).cnt;
  const cancelledTasks = (db.prepare("SELECT COUNT(*) as cnt FROM tasks WHERE status = 'cancelled'").get() as { cnt: number }).cnt;

  const totalAgents = (db.prepare("SELECT COUNT(*) as cnt FROM agents").get() as { cnt: number }).cnt;
  const workingAgents = (db.prepare("SELECT COUNT(*) as cnt FROM agents WHERE status = 'working'").get() as { cnt: number }).cnt;
  const idleAgents = (db.prepare("SELECT COUNT(*) as cnt FROM agents WHERE status = 'idle'").get() as { cnt: number }).cnt;

  const completionRate = totalTasks > 0 ? Math.round((doneTasks / totalTasks) * 100) : 0;

  // Top agents by XP
  const topAgents = db.prepare(
    "SELECT id, name, avatar_emoji, stats_tasks_done, stats_xp FROM agents ORDER BY stats_xp DESC LIMIT 5"
  ).all();

  // Tasks per department
  const tasksByDept = db.prepare(`
    SELECT d.id, d.name, d.icon, d.color,
      COUNT(t.id) AS total_tasks,
      SUM(CASE WHEN t.status = 'done' THEN 1 ELSE 0 END) AS done_tasks
    FROM departments d
    LEFT JOIN tasks t ON t.department_id = d.id
    GROUP BY d.id
    ORDER BY d.name
  `).all();

  // Recent activity (last 20 task logs)
  const recentActivity = db.prepare(`
    SELECT tl.*, t.title AS task_title
    FROM task_logs tl
    LEFT JOIN tasks t ON tl.task_id = t.id
    ORDER BY tl.created_at DESC
    LIMIT 20
  `).all();

  res.json({
    stats: {
      tasks: {
        total: totalTasks,
        done: doneTasks,
        in_progress: inProgressTasks,
        inbox: inboxTasks,
        planned: plannedTasks,
        review: reviewTasks,
        cancelled: cancelledTasks,
        completion_rate: completionRate,
      },
      agents: {
        total: totalAgents,
        working: workingAgents,
        idle: idleAgents,
      },
      top_agents: topAgents,
      tasks_by_department: tasksByDept,
      recent_activity: recentActivity,
    },
  });
});

// ---------------------------------------------------------------------------
// prettyStreamJson: parse stream-JSON from Claude/Codex/Gemini into readable text
// (ported from claw-kanban)
// ---------------------------------------------------------------------------
function prettyStreamJson(raw: string): string {
  const chunks: string[] = [];
  const meta: string[] = [];

  for (const line of raw.split(/\r?\n/)) {
    const t = line.trim();
    if (!t) continue;
    if (!t.startsWith("{")) continue;

    try {
      const j: any = JSON.parse(t);

      // Claude: system init
      if (j.type === "system" && j.subtype === "init") {
        meta.push(`[init] cwd=${j.cwd} model=${j.model}`);
        if (Array.isArray(j.mcp_servers)) {
          const failed = j.mcp_servers.filter((s: any) => s.status && s.status !== "ok");
          if (failed.length) meta.push(`[mcp] ${failed.map((s: any) => `${s.name}:${s.status}`).join(", ")}`);
        }
        continue;
      }

      // Gemini: init
      if (j.type === "init" && j.session_id) {
        meta.push(`[init] session=${j.session_id} model=${j.model}`);
        continue;
      }

      // Claude: skip noise types
      if (j.type === "user" || j.type === "rate_limit_event") continue;

      // Claude: stream_event
      if (j.type === "stream_event") {
        const ev = j.event;
        if (ev?.type === "content_block_delta" && ev?.delta?.type === "text_delta") {
          chunks.push(ev.delta.text);
          continue;
        }
        if (ev?.type === "content_block_start" && ev?.content_block?.type === "text" && ev?.content_block?.text) {
          chunks.push(ev.content_block.text);
          continue;
        }
        if (ev?.type === "content_block_start" && ev?.content_block?.type === "tool_use") {
          chunks.push(`\n[tool: ${ev.content_block.name}]\n`);
          continue;
        }
        continue;
      }

      // Claude: assistant message (from --print mode)
      if (j.type === "assistant" && j.message?.content) {
        for (const block of j.message.content) {
          if (block.type === "text" && block.text) {
            chunks.push(block.text);
          }
          if (block.type === "tool_use" && block.name) {
            const inp = block.input || {};
            const key = inp.file_path || inp.command || inp.pattern || inp.description || inp.prompt || "";
            const short = String(key).split("\n")[0].slice(0, 120);
            chunks.push(`\n[tool: ${block.name}] ${short}\n`);
          }
          if (block.type === "thinking" && block.thinking) {
            chunks.push(`\n[thinking] ${block.thinking}\n`);
          }
        }
        continue;
      }

      // Claude: result (final output from --print mode)
      if (j.type === "result" && j.result) {
        chunks.push(j.result);
        continue;
      }

      // Gemini: message with content
      if (j.type === "message" && j.role === "assistant" && j.content) {
        chunks.push(j.content);
        continue;
      }

      // Gemini: tool_use
      if (j.type === "tool_use" && j.tool_name) {
        const params = j.parameters?.file_path || j.parameters?.command || "";
        chunks.push(`\n[tool: ${j.tool_name}] ${params}\n`);
        continue;
      }

      // Gemini: tool_result
      if (j.type === "tool_result" && j.status) {
        if (j.status !== "success") {
          chunks.push(`[result: ${j.status}]\n`);
        }
        continue;
      }

      // Codex: thread.started
      if (j.type === "thread.started" && j.thread_id) {
        meta.push(`[thread] ${j.thread_id}`);
        continue;
      }

      // Codex: item.completed (reasoning, agent_message, or collab)
      if (j.type === "item.completed" && j.item) {
        const item = j.item;
        if (item.type === "agent_message" && item.text) {
          chunks.push(item.text);
        } else if (item.type === "reasoning" && item.text) {
          chunks.push(`\n[reasoning] ${item.text}\n`);
        } else if (item.type === "tool_call" && item.name) {
          const args = item.arguments ? JSON.stringify(item.arguments).slice(0, 100) : "";
          chunks.push(`\n[tool: ${item.name}] ${args}\n`);
        } else if (item.type === "tool_output" && item.output) {
          const out = String(item.output);
          if (out.includes("error") || out.length < 200) {
            chunks.push(`[output] ${out.slice(0, 200)}\n`);
          }
        } else if (item.type === "collab_tool_call") {
          if (item.tool === "spawn_agent" && item.prompt) {
            chunks.push(`\n[spawn_agent] ${String(item.prompt).split("\n")[0].slice(0, 80)}\n`);
          } else if (item.tool === "close_agent") {
            for (const [, st] of Object.entries(item.agents_states || {})) {
              const state = st as Record<string, unknown>;
              if (state.message) chunks.push(`[agent_done] ${String(state.message).slice(0, 100)}\n`);
            }
          }
          // "wait" tool: silent
        }
        continue;
      }

      // Codex: item.started (collab_tool_call display)
      if (j.type === "item.started" && j.item) {
        const item = j.item;
        if (item.type === "collab_tool_call" && item.tool === "spawn_agent" && item.prompt) {
          chunks.push(`\n[spawn_agent] ${String(item.prompt).split("\n")[0].slice(0, 80)}\n`);
        }
        continue;
      }

      // Codex: turn.completed (usage stats)
      if (j.type === "turn.completed" && j.usage) {
        const u = j.usage;
        meta.push(`[usage] in=${u.input_tokens} out=${u.output_tokens} cached=${u.cached_input_tokens || 0}`);
        continue;
      }
    } catch {
      // ignore
    }
  }

  // Fallback: if no JSON was parsed, return raw text (e.g. plain-text logs)
  if (chunks.length === 0 && meta.length === 0) {
    return raw.trim();
  }

  const stitched = chunks.join("");
  const PARA = "\u0000";
  const withPara = stitched.replace(/\n{2,}/g, PARA);
  const singleLine = withPara.replace(/\n/g, " ");
  const normalized = singleLine
    .replace(/\s+/g, " ")
    .replace(new RegExp(PARA, "g"), "\n\n")
    .trim();

  const head = meta.length ? meta.join("\n") + "\n\n" : "";
  return head + normalized;
}

// ---------------------------------------------------------------------------
// Task terminal log viewer (ported from claw-kanban)
// ---------------------------------------------------------------------------
app.get("/api/tasks/:id/terminal", (req, res) => {
  const id = String(req.params.id);
  const lines = Math.min(Math.max(Number(req.query.lines ?? 200), 20), 4000);
  const pretty = String(req.query.pretty ?? "0") === "1";
  const filePath = path.join(logsDir, `${id}.log`);

  if (!fs.existsSync(filePath)) {
    return res.json({ ok: true, exists: false, path: filePath, text: "" });
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const parts = raw.split(/\r?\n/);
  const tail = parts.slice(Math.max(0, parts.length - lines)).join("\n");
  let text = tail;
  if (pretty) {
    const parsed = prettyStreamJson(tail);
    // If pretty parsing produced empty/whitespace but raw has content, fall back to raw
    text = parsed.trim() ? parsed : tail;
  }

  // Also return task_logs (system events) for interleaved display
  const taskLogs = db.prepare(
    "SELECT id, kind, message, created_at FROM task_logs WHERE task_id = ? ORDER BY created_at ASC"
  ).all(id) as Array<{ id: number; kind: string; message: string; created_at: number }>;

  res.json({ ok: true, exists: true, path: filePath, text, task_logs: taskLogs });
});

// ---------------------------------------------------------------------------
// OAuth web-auth helper functions
// ---------------------------------------------------------------------------
function consumeOAuthState(stateId: string, provider: string): { verifier_enc: string; redirect_to: string | null } | null {
  const row = db.prepare(
    "SELECT provider, verifier_enc, redirect_to, created_at FROM oauth_states WHERE id = ?"
  ).get(stateId) as { provider: string; verifier_enc: string; redirect_to: string | null; created_at: number } | undefined;
  if (!row) return null;
  // Always delete (one-time use)
  db.prepare("DELETE FROM oauth_states WHERE id = ?").run(stateId);
  // Check TTL
  if (Date.now() - row.created_at > OAUTH_STATE_TTL_MS) return null;
  // Check provider match
  if (row.provider !== provider) return null;
  return { verifier_enc: row.verifier_enc, redirect_to: row.redirect_to };
}

function upsertOAuthCredential(input: {
  provider: string;
  source: string;
  email: string | null;
  scope: string | null;
  access_token: string;
  refresh_token: string | null;
  expires_at: number | null;
}): void {
  const now = nowMs();
  const accessEnc = encryptSecret(input.access_token);
  const refreshEnc = input.refresh_token ? encryptSecret(input.refresh_token) : null;
  const encData = encryptSecret(JSON.stringify({ access_token: input.access_token }));

  db.prepare(`
    INSERT INTO oauth_credentials (provider, source, encrypted_data, email, scope, expires_at, created_at, updated_at, access_token_enc, refresh_token_enc)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(provider) DO UPDATE SET
      source = excluded.source,
      encrypted_data = excluded.encrypted_data,
      email = excluded.email,
      scope = excluded.scope,
      expires_at = excluded.expires_at,
      updated_at = excluded.updated_at,
      access_token_enc = excluded.access_token_enc,
      refresh_token_enc = excluded.refresh_token_enc
  `).run(
    input.provider, input.source, encData, input.email, input.scope,
    input.expires_at, now, now, accessEnc, refreshEnc
  );
}

function startGitHubOAuth(redirectTo: string | undefined, callbackPath: string): string {
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID ?? BUILTIN_GITHUB_CLIENT_ID;
  if (!clientId) throw new Error("missing_OAUTH_GITHUB_CLIENT_ID");
  const stateId = randomUUID();
  const safeRedirect = sanitizeOAuthRedirect(redirectTo);
  db.prepare(
    "INSERT INTO oauth_states (id, provider, created_at, verifier_enc, redirect_to) VALUES (?, ?, ?, ?, ?)"
  ).run(stateId, "github", Date.now(), "none", safeRedirect);

  const url = new URL("https://github.com/login/oauth/authorize");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("redirect_uri", `${OAUTH_BASE_URL}${callbackPath}`);
  url.searchParams.set("state", stateId);
  url.searchParams.set("scope", "read:user user:email");
  return url.toString();
}

function startGoogleAntigravityOAuth(redirectTo: string | undefined, callbackPath: string): string {
  const clientId = process.env.OAUTH_GOOGLE_CLIENT_ID ?? BUILTIN_GOOGLE_CLIENT_ID;
  if (!clientId) throw new Error("missing_OAUTH_GOOGLE_CLIENT_ID");
  const stateId = randomUUID();
  const verifier = pkceVerifier();
  const safeRedirect = sanitizeOAuthRedirect(redirectTo);
  const verifierEnc = encryptSecret(verifier);
  db.prepare(
    "INSERT INTO oauth_states (id, provider, created_at, verifier_enc, redirect_to) VALUES (?, ?, ?, ?, ?)"
  ).run(stateId, "google_antigravity", Date.now(), verifierEnc, safeRedirect);

  const challenge = b64url(createHash("sha256").update(verifier, "ascii").digest());

  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", clientId);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("redirect_uri", `${OAUTH_BASE_URL}${callbackPath}`);
  url.searchParams.set("scope", [
    "https://www.googleapis.com/auth/cloud-platform",
    "openid", "email", "profile",
  ].join(" "));
  url.searchParams.set("code_challenge", challenge);
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", stateId);
  url.searchParams.set("access_type", "offline");
  url.searchParams.set("prompt", "consent");
  return url.toString();
}

async function handleGitHubCallback(code: string, stateId: string, callbackPath: string): Promise<{ redirectTo: string }> {
  const stateRow = consumeOAuthState(stateId, "github");
  if (!stateRow) throw new Error("Invalid or expired state");

  const redirectTo = stateRow.redirect_to || "/";
  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID ?? BUILTIN_GITHUB_CLIENT_ID;
  const clientSecret = process.env.OAUTH_GITHUB_CLIENT_SECRET;

  // Exchange code for token (client_secret optional for built-in public app)
  const tokenBody: Record<string, string> = {
    client_id: clientId,
    code,
    redirect_uri: `${OAUTH_BASE_URL}${callbackPath}`,
  };
  if (clientSecret) tokenBody.client_secret = clientSecret;

  const tokenResp = await fetch("https://github.com/login/oauth/access_token", {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(tokenBody),
    signal: AbortSignal.timeout(10000),
  });
  const tokenData = await tokenResp.json() as { access_token?: string; error?: string; scope?: string };
  if (!tokenData.access_token) throw new Error(tokenData.error || "No access token received");

  // Fetch primary email
  let email: string | null = null;
  try {
    const emailResp = await fetch("https://api.github.com/user/emails", {
      headers: { Authorization: `Bearer ${tokenData.access_token}`, "User-Agent": "climpire", Accept: "application/vnd.github+json" },
      signal: AbortSignal.timeout(5000),
    });
    if (emailResp.ok) {
      const emails = await emailResp.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
      const primary = emails.find((e) => e.primary && e.verified);
      if (primary) email = primary.email;
    }
  } catch { /* email fetch is best-effort */ }

  upsertOAuthCredential({
    provider: "github",
    source: "web-oauth",
    email,
    scope: tokenData.scope || "read:user,user:email",
    access_token: tokenData.access_token,
    refresh_token: null,
    expires_at: null,
  });

  return { redirectTo: appendOAuthQuery(redirectTo.startsWith("/") ? `${OAUTH_BASE_URL}${redirectTo}` : redirectTo, "oauth", "github-copilot") };
}

async function handleGoogleAntigravityCallback(code: string, stateId: string, callbackPath: string): Promise<{ redirectTo: string }> {
  const stateRow = consumeOAuthState(stateId, "google_antigravity");
  if (!stateRow) throw new Error("Invalid or expired state");

  const redirectTo = stateRow.redirect_to || "/";
  const clientId = process.env.OAUTH_GOOGLE_CLIENT_ID ?? BUILTIN_GOOGLE_CLIENT_ID;
  const clientSecret = process.env.OAUTH_GOOGLE_CLIENT_SECRET ?? BUILTIN_GOOGLE_CLIENT_SECRET;

  // Decrypt PKCE verifier
  const verifier = decryptSecret(stateRow.verifier_enc);

  // Exchange code for token
  const tokenResp = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: `${OAUTH_BASE_URL}${callbackPath}`,
      grant_type: "authorization_code",
      code_verifier: verifier,
    }),
    signal: AbortSignal.timeout(10000),
  });
  const tokenData = await tokenResp.json() as {
    access_token?: string; refresh_token?: string; expires_in?: number;
    error?: string; scope?: string;
  };
  if (!tokenData.access_token) throw new Error(tokenData.error || "No access token received");

  // Fetch user info
  let email: string | null = null;
  try {
    const userResp = await fetch("https://www.googleapis.com/oauth2/v1/userinfo?alt=json", {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
      signal: AbortSignal.timeout(8000),
    });
    if (userResp.ok) {
      const ui = await userResp.json() as { email?: string };
      if (ui?.email) email = ui.email;
    }
  } catch { /* userinfo best-effort */ }

  const expiresAt = tokenData.expires_in ? Date.now() + tokenData.expires_in * 1000 : null;

  upsertOAuthCredential({
    provider: "google_antigravity",
    source: "web-oauth",
    email,
    scope: tokenData.scope || "openid email profile",
    access_token: tokenData.access_token,
    refresh_token: tokenData.refresh_token || null,
    expires_at: expiresAt,
  });

  return { redirectTo: appendOAuthQuery(redirectTo.startsWith("/") ? `${OAUTH_BASE_URL}${redirectTo}` : redirectTo, "oauth", "antigravity") };
}

// ---------------------------------------------------------------------------
// OAuth credentials (simplified for CLImpire)
// ---------------------------------------------------------------------------
// Helper: build OAuth status with 2 connect providers (github-copilot, antigravity)
function buildOAuthStatus() {
  const home = os.homedir();

  // DB-stored credentials
  type CredRow = { provider: string; email: string | null; scope: string | null; expires_at: number | null; created_at: number; updated_at: number; access_token_enc: string | null; refresh_token_enc: string | null };
  const rows = db.prepare(
    "SELECT provider, email, scope, expires_at, created_at, updated_at, access_token_enc, refresh_token_enc FROM oauth_credentials"
  ).all() as CredRow[];

  const dbCreds: Record<string, CredRow> = {};
  for (const row of rows) dbCreds[row.provider] = row;

  // GitHub credential: DB "github" or file-detected from gh CLI
  const ghDb = dbCreds.github;
  let ghConnected = Boolean(ghDb);
  let ghSource: string | null = ghDb ? "web-oauth" : null;
  let ghEmail: string | null = ghDb?.email ?? null;
  let ghScope: string | null = ghDb?.scope ?? null;
  let ghCreatedAt = ghDb?.created_at ?? 0;
  let ghUpdatedAt = ghDb?.updated_at ?? 0;

  // Also detect Copilot file-based credentials
  if (!ghConnected) {
    // gh CLI hosts
    try {
      const hostsPath = path.join(home, ".config", "gh", "hosts.yml");
      const raw = fs.readFileSync(hostsPath, "utf8");
      const userMatch = raw.match(/user:\s*(\S+)/);
      if (userMatch) {
        const stat = fs.statSync(hostsPath);
        ghConnected = true;
        ghSource = "file-detected";
        ghEmail = userMatch[1];
        ghScope = "github.com";
        ghCreatedAt = stat.birthtimeMs;
        ghUpdatedAt = stat.mtimeMs;
      }
    } catch {}
  }
  if (!ghConnected) {
    // GitHub Copilot hosts/apps
    const copilotPaths = [
      path.join(home, ".config", "github-copilot", "hosts.json"),
      path.join(home, ".config", "github-copilot", "apps.json"),
    ];
    for (const cp of copilotPaths) {
      try {
        const raw = JSON.parse(fs.readFileSync(cp, "utf8"));
        if (raw && typeof raw === "object" && Object.keys(raw).length > 0) {
          const stat = fs.statSync(cp);
          const firstKey = Object.keys(raw)[0];
          ghConnected = true;
          ghSource = "file-detected";
          ghEmail = raw[firstKey]?.user ?? null;
          ghScope = "copilot";
          ghCreatedAt = stat.birthtimeMs;
          ghUpdatedAt = stat.mtimeMs;
          break;
        }
      } catch {}
    }
  }

  // Antigravity credential: DB "google_antigravity" or file-detected
  const agDb = dbCreds.google_antigravity;
  let agConnected = Boolean(agDb);
  let agSource: string | null = agDb ? "web-oauth" : null;
  let agEmail: string | null = agDb?.email ?? null;
  let agScope: string | null = agDb?.scope ?? null;
  let agExpiresAt: number | null = agDb?.expires_at ?? null;
  let agCreatedAt = agDb?.created_at ?? 0;
  let agUpdatedAt = agDb?.updated_at ?? 0;
  const agHasRefresh = Boolean(agDb?.refresh_token_enc);

  if (!agConnected) {
    const agPaths = [
      path.join(home, ".antigravity", "auth.json"),
      path.join(home, ".config", "antigravity", "auth.json"),
      path.join(home, ".config", "antigravity", "credentials.json"),
    ];
    for (const ap of agPaths) {
      try {
        const raw = JSON.parse(fs.readFileSync(ap, "utf8"));
        if (raw && typeof raw === "object") {
          const stat = fs.statSync(ap);
          agConnected = true;
          agSource = "file-detected";
          agEmail = raw.email ?? raw.user ?? null;
          agScope = raw.scope ?? null;
          agExpiresAt = raw.expires_at ?? null;
          agCreatedAt = stat.birthtimeMs;
          agUpdatedAt = stat.mtimeMs;
          break;
        }
      } catch {}
    }
  }

  return {
    "github-copilot": {
      connected: ghConnected,
      source: ghSource,
      email: ghEmail,
      scope: ghScope,
      expires_at: null as number | null,
      created_at: ghCreatedAt,
      updated_at: ghUpdatedAt,
      webConnectable: true,  // always connectable — built-in client ID
    },
    antigravity: {
      connected: agConnected,
      source: agSource,
      email: agEmail,
      scope: agScope,
      expires_at: agExpiresAt,
      created_at: agCreatedAt,
      updated_at: agUpdatedAt,
      webConnectable: true,  // always connectable — built-in client ID
      hasRefreshToken: agHasRefresh,
    },
  };
}

app.get("/api/oauth/status", (_req, res) => {
  res.json({
    storageReady: Boolean(OAUTH_ENCRYPTION_SECRET),
    providers: buildOAuthStatus(),
  });
});

// GET /api/oauth/start — Begin OAuth flow
app.get("/api/oauth/start", (req, res) => {
  const provider = firstQueryValue(req.query.provider);
  const redirectTo = sanitizeOAuthRedirect(firstQueryValue(req.query.redirect_to));

  try {
    let authorizeUrl: string;
    if (provider === "github-copilot") {
      authorizeUrl = startGitHubOAuth(redirectTo, "/api/oauth/callback/github-copilot");
    } else if (provider === "antigravity") {
      authorizeUrl = startGoogleAntigravityOAuth(redirectTo, "/api/oauth/callback/antigravity");
    } else {
      return res.status(400).json({ error: `Unsupported provider: ${provider}` });
    }
    res.redirect(302, authorizeUrl);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.status(500).json({ error: msg });
  }
});

// GET /api/oauth/callback/github-copilot — GitHub OAuth callback (for Copilot)
app.get("/api/oauth/callback/github-copilot", async (req, res) => {
  const code = firstQueryValue(req.query.code);
  const state = firstQueryValue(req.query.state);
  const error = firstQueryValue(req.query.error);

  if (error || !code || !state) {
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", error || "missing_code");
    return res.redirect(redirectUrl.toString());
  }

  try {
    const result = await handleGitHubCallback(code, state, "/api/oauth/callback/github-copilot");
    res.redirect(result.redirectTo);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[OAuth] GitHub/Copilot callback error:", msg);
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", msg);
    res.redirect(redirectUrl.toString());
  }
});

// GET /api/oauth/callback/antigravity — Google/Antigravity OAuth callback
app.get("/api/oauth/callback/antigravity", async (req, res) => {
  const code = firstQueryValue(req.query.code);
  const state = firstQueryValue(req.query.state);
  const error = firstQueryValue(req.query.error);

  if (error || !code || !state) {
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", error || "missing_code");
    return res.redirect(redirectUrl.toString());
  }

  try {
    const result = await handleGoogleAntigravityCallback(code, state, "/api/oauth/callback/antigravity");
    res.redirect(result.redirectTo);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error("[OAuth] Antigravity callback error:", msg);
    const redirectUrl = new URL("/", OAUTH_BASE_URL);
    redirectUrl.searchParams.set("oauth_error", msg);
    res.redirect(redirectUrl.toString());
  }
});

// --- GitHub Device Code Flow (no redirect URI needed) ---
app.post("/api/oauth/github-copilot/device-start", async (_req, res) => {
  if (!OAUTH_ENCRYPTION_SECRET) {
    return res.status(400).json({ error: "missing_OAUTH_ENCRYPTION_SECRET" });
  }

  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID ?? BUILTIN_GITHUB_CLIENT_ID;
  try {
    const resp = await fetch("https://github.com/login/device/code", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ client_id: clientId, scope: "read:user user:email" }),
      signal: AbortSignal.timeout(10000),
    });
    if (!resp.ok) {
      return res.status(502).json({ error: "github_device_code_failed", status: resp.status });
    }

    const json = await resp.json() as {
      device_code: string; user_code: string; verification_uri: string;
      expires_in: number; interval: number;
    };
    if (!json.device_code || !json.user_code) {
      return res.status(502).json({ error: "github_device_code_invalid" });
    }

    // Encrypt device_code server-side
    const stateId = randomUUID();
    db.prepare(
      "INSERT INTO oauth_states (id, provider, created_at, verifier_enc, redirect_to) VALUES (?, ?, ?, ?, ?)"
    ).run(stateId, "github", nowMs(), encryptSecret(json.device_code), null);

    res.json({
      stateId,
      userCode: json.user_code,
      verificationUri: json.verification_uri,
      expiresIn: json.expires_in,
      interval: json.interval,
    });
  } catch (err) {
    res.status(500).json({ error: "github_device_start_failed", message: String(err) });
  }
});

app.post("/api/oauth/github-copilot/device-poll", async (req, res) => {
  const stateId = (req.body as { stateId?: string })?.stateId;
  if (!stateId || typeof stateId !== "string") {
    return res.status(400).json({ error: "stateId is required" });
  }

  const row = db.prepare(
    "SELECT provider, verifier_enc, redirect_to, created_at FROM oauth_states WHERE id = ? AND provider = ?"
  ).get(stateId, "github") as { provider: string; verifier_enc: string; redirect_to: string | null; created_at: number } | undefined;
  if (!row) {
    return res.status(400).json({ error: "invalid_state", status: "expired" });
  }
  if (nowMs() - row.created_at > OAUTH_STATE_TTL_MS) {
    db.prepare("DELETE FROM oauth_states WHERE id = ?").run(stateId);
    return res.json({ status: "expired" });
  }

  let deviceCode: string;
  try {
    deviceCode = decryptSecret(row.verifier_enc);
  } catch {
    return res.status(500).json({ error: "decrypt_failed" });
  }

  const clientId = process.env.OAUTH_GITHUB_CLIENT_ID ?? BUILTIN_GITHUB_CLIENT_ID;
  try {
    const resp = await fetch("https://github.com/login/oauth/access_token", {
      method: "POST",
      headers: { Accept: "application/json", "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: clientId,
        device_code: deviceCode,
        grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      }),
      signal: AbortSignal.timeout(10000),
    });

    if (!resp.ok) {
      return res.status(502).json({ error: "github_poll_failed", status: "error" });
    }

    const json = await resp.json() as Record<string, unknown>;

    if ("access_token" in json && typeof json.access_token === "string") {
      db.prepare("DELETE FROM oauth_states WHERE id = ?").run(stateId);
      const accessToken = json.access_token;

      // Fetch user email
      let email: string | null = null;
      try {
        const emailsResp = await fetch("https://api.github.com/user/emails", {
          headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "climpire", Accept: "application/vnd.github+json" },
          signal: AbortSignal.timeout(5000),
        });
        if (emailsResp.ok) {
          const emails = await emailsResp.json() as Array<{ email: string; primary: boolean; verified: boolean }>;
          const primary = emails.find((e) => e.primary && e.verified);
          if (primary) email = primary.email;
        }
      } catch { /* best-effort */ }

      upsertOAuthCredential({
        provider: "github",
        source: "web-oauth",
        email,
        scope: typeof json.scope === "string" ? json.scope : null,
        access_token: accessToken,
        refresh_token: null,
        expires_at: null,
      });

      return res.json({ status: "complete", email });
    }

    const error = typeof json.error === "string" ? json.error : "unknown";
    if (error === "authorization_pending") return res.json({ status: "pending" });
    if (error === "slow_down") return res.json({ status: "slow_down" });
    if (error === "expired_token") {
      db.prepare("DELETE FROM oauth_states WHERE id = ?").run(stateId);
      return res.json({ status: "expired" });
    }
    if (error === "access_denied") {
      db.prepare("DELETE FROM oauth_states WHERE id = ?").run(stateId);
      return res.json({ status: "denied" });
    }
    return res.json({ status: "error", error });
  } catch (err) {
    return res.status(500).json({ error: "github_poll_error", message: String(err) });
  }
});

// POST /api/oauth/disconnect — Disconnect a provider
app.post("/api/oauth/disconnect", (req, res) => {
  const provider = (req.body as { provider?: string })?.provider;
  if (provider === "github-copilot") {
    db.prepare("DELETE FROM oauth_credentials WHERE provider = ?").run("github");
  } else if (provider === "antigravity") {
    db.prepare("DELETE FROM oauth_credentials WHERE provider = ?").run("google_antigravity");
  } else {
    return res.status(400).json({ error: `Invalid provider: ${provider}` });
  }
  res.json({ ok: true });
});

// ---------------------------------------------------------------------------
// OAuth Provider Model Listing
// ---------------------------------------------------------------------------
async function fetchOpenCodeModels(): Promise<Record<string, string[]>> {
  const grouped: Record<string, string[]> = {};
  try {
    const output = await execWithTimeout("opencode", ["models"], 10_000);
    for (const line of output.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || !trimmed.includes("/")) continue;
      const slashIdx = trimmed.indexOf("/");
      const provider = trimmed.slice(0, slashIdx);
      if (provider === "github-copilot") {
        if (!grouped.copilot) grouped.copilot = [];
        grouped.copilot.push(trimmed);
      }
      if (provider === "google" && trimmed.includes("antigravity")) {
        if (!grouped.antigravity) grouped.antigravity = [];
        grouped.antigravity.push(trimmed);
      }
    }
  } catch {
    // opencode not available
  }
  return grouped;
}

// ---------------------------------------------------------------------------
// CLI Models — dynamic model lists for CLI providers
// ---------------------------------------------------------------------------
interface CliModelInfoServer {
  slug: string;
  displayName?: string;
  description?: string;
  reasoningLevels?: Array<{ effort: string; description: string }>;
  defaultReasoningLevel?: string;
}

let cachedCliModels: { data: Record<string, CliModelInfoServer[]>; loadedAt: number } | null = null;

/**
 * Read Codex models from ~/.codex/models_cache.json
 * Returns CliModelInfoServer[] with reasoning levels from the cache
 */
function readCodexModelsCache(): CliModelInfoServer[] {
  try {
    const cachePath = path.join(os.homedir(), ".codex", "models_cache.json");
    if (!fs.existsSync(cachePath)) return [];
    const raw = JSON.parse(fs.readFileSync(cachePath, "utf8"));
    const modelsArr: Array<{
      slug?: string;
      display_name?: string;
      description?: string;
      visibility?: string;
      priority?: number;
      supported_reasoning_levels?: Array<{ effort: string; description: string }>;
      default_reasoning_level?: string;
    }> = Array.isArray(raw) ? raw : (raw.models || raw.data || []);

    const listModels = modelsArr
      .filter((m) => m.visibility === "list" && m.slug)
      .sort((a, b) => (a.priority ?? 999) - (b.priority ?? 999));

    return listModels.map((m) => ({
      slug: m.slug!,
      displayName: m.display_name || m.slug!,
      description: m.description,
      reasoningLevels: m.supported_reasoning_levels && m.supported_reasoning_levels.length > 0
        ? m.supported_reasoning_levels
        : undefined,
      defaultReasoningLevel: m.default_reasoning_level || undefined,
    }));
  } catch {
    return [];
  }
}

/**
 * Read Gemini CLI models from defaultModelConfigs.js in the Gemini CLI installation.
 * Falls back to a hardcoded list of known models.
 */
function fetchGeminiModels(): CliModelInfoServer[] {
  const FALLBACK: CliModelInfoServer[] = [
    { slug: "gemini-3-pro-preview", displayName: "Gemini 3 Pro Preview" },
    { slug: "gemini-3-flash-preview", displayName: "Gemini 3 Flash Preview" },
    { slug: "gemini-2.5-pro", displayName: "Gemini 2.5 Pro" },
    { slug: "gemini-2.5-flash", displayName: "Gemini 2.5 Flash" },
    { slug: "gemini-2.5-flash-lite", displayName: "Gemini 2.5 Flash Lite" },
  ];

  try {
    // 1. Find gemini binary
    const geminiPath = execFileSync("which", ["gemini"], {
      stdio: "pipe", timeout: 5000, encoding: "utf8",
    }).trim();
    if (!geminiPath) return FALLBACK;

    // 2. Resolve symlinks to real installation path
    const realPath = fs.realpathSync(geminiPath);

    // 3. Walk up from resolved binary to find gemini-cli-core config
    let dir = path.dirname(realPath);
    let configPath = "";
    for (let i = 0; i < 10; i++) {
      const candidate = path.join(
        dir, "node_modules", "@google", "gemini-cli-core",
        "dist", "src", "config", "defaultModelConfigs.js",
      );
      if (fs.existsSync(candidate)) {
        configPath = candidate;
        break;
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;
      dir = parent;
    }

    if (!configPath) return FALLBACK;

    // 4. Parse the config file for user-facing models (those extending chat-base-*)
    const content = fs.readFileSync(configPath, "utf8");

    // Match config entries: "model-slug": { ... extends: "chat-base-..." ... }
    // We use a broad regex that captures the key and content within braces
    const models: CliModelInfoServer[] = [];
    const entryRegex = /["']([a-z][a-z0-9._-]+)["']\s*:\s*\{([^}]*extends\s*:\s*["']chat-base[^"']*["'][^}]*)\}/g;
    let match;
    while ((match = entryRegex.exec(content)) !== null) {
      const slug = match[1];
      if (slug.startsWith("chat-base")) continue;
      models.push({ slug, displayName: slug });
    }

    return models.length > 0 ? models : FALLBACK;
  } catch {
    return FALLBACK;
  }
}

/** Convert a plain string to CliModelInfoServer */
function toModelInfo(slug: string): CliModelInfoServer {
  return { slug, displayName: slug };
}

app.get("/api/cli-models", async (_req, res) => {
  const now = Date.now();
  if (cachedCliModels && now - cachedCliModels.loadedAt < MODELS_CACHE_TTL) {
    return res.json({ models: cachedCliModels.data });
  }

  const models: Record<string, CliModelInfoServer[]> = {
    claude: [
      "opus", "sonnet", "haiku",
      "claude-opus-4-6", "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-haiku-4-5",
    ].map(toModelInfo),
    gemini: fetchGeminiModels(),
    opencode: [],
  };

  // Codex: dynamic from ~/.codex/models_cache.json
  const codexModels = readCodexModelsCache();
  models.codex = codexModels.length > 0
    ? codexModels
    : ["gpt-5.3-codex", "gpt-5.2-codex", "gpt-5.1-codex-max", "gpt-5.2", "gpt-5.1-codex-mini"].map(toModelInfo);

  // OpenCode: dynamic from `opencode models` CLI
  try {
    const ocModels = await fetchOpenCodeModels();
    const ocList: string[] = [];
    for (const [, modelList] of Object.entries(ocModels)) {
      for (const m of modelList) {
        if (!ocList.includes(m)) ocList.push(m);
      }
    }
    if (ocList.length > 0) models.opencode = ocList.map(toModelInfo);
  } catch {
    // opencode not available — keep empty
  }

  cachedCliModels = { data: models, loadedAt: Date.now() };
  res.json({ models });
});

app.get("/api/oauth/models", async (_req, res) => {
  const now = Date.now();
  if (cachedModels && now - cachedModels.loadedAt < MODELS_CACHE_TTL) {
    return res.json({ models: cachedModels.data });
  }

  try {
    const ocModels = await fetchOpenCodeModels();

    // Merge with fallback antigravity models if empty
    const merged: Record<string, string[]> = { ...ocModels };
    if (!merged.antigravity || merged.antigravity.length === 0) {
      merged.antigravity = [
        "google/antigravity-gemini-3-pro",
        "google/antigravity-gemini-3-flash",
        "google/antigravity-claude-sonnet-4-5",
        "google/antigravity-claude-sonnet-4-5-thinking",
        "google/antigravity-claude-opus-4-5-thinking",
        "google/antigravity-claude-opus-4-6-thinking",
      ];
    }

    cachedModels = { data: merged, loadedAt: Date.now() };
    res.json({ models: merged });
  } catch (err) {
    res.status(500).json({ error: "model_fetch_failed", message: String(err) });
  }
});

// ---------------------------------------------------------------------------
// Skills (skills.sh) cached proxy
// ---------------------------------------------------------------------------

interface SkillEntry {
  rank: number;
  name: string;
  repo: string;
  installs: number;
}

let cachedSkills: { data: SkillEntry[]; loadedAt: number } | null = null;
const SKILLS_CACHE_TTL = 3600_000; // 1 hour

async function fetchSkillsFromSite(): Promise<SkillEntry[]> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);
    const resp = await fetch("https://skills.sh", { signal: controller.signal });
    clearTimeout(timeout);
    if (!resp.ok) return [];
    const html = await resp.text();

    // Next.js RSC payload embeds the data with escaped quotes: initialSkills\":[{\"source\":...}]
    // Find the start of the array after "initialSkills"
    const anchor = html.indexOf("initialSkills");
    if (anchor === -1) return [];
    const bracketStart = html.indexOf(":[", anchor);
    if (bracketStart === -1) return [];
    const arrStart = bracketStart + 1; // position of '['

    // Walk to find the matching ']'
    let depth = 0;
    let arrEnd = arrStart;
    for (let i = arrStart; i < html.length; i++) {
      if (html[i] === "[") depth++;
      else if (html[i] === "]") depth--;
      if (depth === 0) { arrEnd = i + 1; break; }
    }

    // Unescape RSC-style escaped quotes: \\" → "
    const raw = html.slice(arrStart, arrEnd).replace(/\\"/g, '"');
    const items: Array<{ source?: string; skillId?: string; name?: string; installs?: number }> = JSON.parse(raw);

    return items.map((obj, i) => ({
      rank: i + 1,
      name: obj.name ?? obj.skillId ?? "",
      repo: obj.source ?? "",
      installs: typeof obj.installs === "number" ? obj.installs : 0,
    }));
  } catch {
    return [];
  }
}

app.get("/api/skills", async (_req, res) => {
  if (cachedSkills && Date.now() - cachedSkills.loadedAt < SKILLS_CACHE_TTL) {
    return res.json({ skills: cachedSkills.data });
  }
  const skills = await fetchSkillsFromSite();
  if (skills.length > 0) {
    cachedSkills = { data: skills, loadedAt: Date.now() };
  }
  res.json({ skills });
});

// ---------------------------------------------------------------------------
// Git Worktree management endpoints
// ---------------------------------------------------------------------------

// GET /api/tasks/:id/diff — Get diff for review in UI
app.get("/api/tasks/:id/diff", (req, res) => {
  const id = String(req.params.id);
  const wtInfo = taskWorktrees.get(id);
  if (!wtInfo) {
    return res.json({ ok: true, hasWorktree: false, diff: "", stat: "" });
  }

  try {
    const currentBranch = execFileSync("git", ["rev-parse", "--abbrev-ref", "HEAD"], {
      cwd: wtInfo.projectPath, stdio: "pipe", timeout: 5000,
    }).toString().trim();

    const stat = execFileSync("git", ["diff", `${currentBranch}...${wtInfo.branchName}`, "--stat"], {
      cwd: wtInfo.projectPath, stdio: "pipe", timeout: 10000,
    }).toString().trim();

    const diff = execFileSync("git", ["diff", `${currentBranch}...${wtInfo.branchName}`], {
      cwd: wtInfo.projectPath, stdio: "pipe", timeout: 15000,
    }).toString();

    res.json({
      ok: true,
      hasWorktree: true,
      branchName: wtInfo.branchName,
      stat,
      diff: diff.length > 50000 ? diff.slice(0, 50000) + "\n... (truncated)" : diff,
    });
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    res.json({ ok: false, error: msg });
  }
});

// POST /api/tasks/:id/merge — Manually trigger merge
app.post("/api/tasks/:id/merge", (req, res) => {
  const id = String(req.params.id);
  const wtInfo = taskWorktrees.get(id);
  if (!wtInfo) {
    return res.status(404).json({ error: "no_worktree", message: "No worktree found for this task" });
  }

  const result = mergeWorktree(wtInfo.projectPath, id);

  if (result.success) {
    cleanupWorktree(wtInfo.projectPath, id);
    appendTaskLog(id, "system", `Manual merge 완료: ${result.message}`);
    notifyCeo(`수동 병합 완료: ${result.message}`, id);
  } else {
    appendTaskLog(id, "system", `Manual merge 실패: ${result.message}`);
  }

  res.json({ ok: result.success, message: result.message, conflicts: result.conflicts });
});

// POST /api/tasks/:id/discard — Discard worktree changes (abandon branch)
app.post("/api/tasks/:id/discard", (req, res) => {
  const id = String(req.params.id);
  const wtInfo = taskWorktrees.get(id);
  if (!wtInfo) {
    return res.status(404).json({ error: "no_worktree", message: "No worktree found for this task" });
  }

  cleanupWorktree(wtInfo.projectPath, id);
  appendTaskLog(id, "system", "Worktree discarded (changes abandoned)");
  notifyCeo(`작업 브랜치가 폐기되었습니다: climpire/${id.slice(0, 8)}`, id);

  res.json({ ok: true, message: "Worktree discarded" });
});

// GET /api/worktrees — List all active worktrees
app.get("/api/worktrees", (_req, res) => {
  const entries: Array<{ taskId: string; branchName: string; worktreePath: string; projectPath: string }> = [];
  for (const [taskId, info] of taskWorktrees) {
    entries.push({ taskId, ...info });
  }
  res.json({ ok: true, worktrees: entries });
});

// ---------------------------------------------------------------------------
// CLI Usage stats (real provider API usage, persisted in SQLite)
// ---------------------------------------------------------------------------

// Read cached usage from SQLite
function readCliUsageFromDb(): Record<string, CliUsageEntry> {
  const rows = db.prepare("SELECT provider, data_json FROM cli_usage_cache").all() as Array<{ provider: string; data_json: string }>;
  const usage: Record<string, CliUsageEntry> = {};
  for (const row of rows) {
    try { usage[row.provider] = JSON.parse(row.data_json); } catch { /* skip corrupt */ }
  }
  return usage;
}

// Fetch real usage from provider APIs and persist to SQLite
async function refreshCliUsageData(): Promise<Record<string, CliUsageEntry>> {
  const providers = ["claude", "codex", "gemini", "copilot", "antigravity"];
  const usage: Record<string, CliUsageEntry> = {};

  const fetchMap: Record<string, () => Promise<CliUsageEntry>> = {
    claude: fetchClaudeUsage,
    codex: fetchCodexUsage,
    gemini: fetchGeminiUsage,
  };

  const fetches = providers.map(async (p) => {
    const tool = CLI_TOOLS.find((t) => t.name === p);
    if (!tool) {
      usage[p] = { windows: [], error: "not_implemented" };
      return;
    }
    if (!tool.checkAuth()) {
      usage[p] = { windows: [], error: "unauthenticated" };
      return;
    }
    const fetcher = fetchMap[p];
    if (fetcher) {
      usage[p] = await fetcher();
    } else {
      usage[p] = { windows: [], error: "not_implemented" };
    }
  });

  await Promise.all(fetches);

  // Persist to SQLite
  const upsert = db.prepare(
    "INSERT INTO cli_usage_cache (provider, data_json, updated_at) VALUES (?, ?, ?) ON CONFLICT(provider) DO UPDATE SET data_json = excluded.data_json, updated_at = excluded.updated_at"
  );
  const now = nowMs();
  for (const [p, entry] of Object.entries(usage)) {
    upsert.run(p, JSON.stringify(entry), now);
  }

  return usage;
}

// GET: read from SQLite cache; if empty, fetch and populate first
app.get("/api/cli-usage", async (_req, res) => {
  let usage = readCliUsageFromDb();
  if (Object.keys(usage).length === 0) {
    usage = await refreshCliUsageData();
  }
  res.json({ ok: true, usage });
});

// POST: trigger real API fetches, update SQLite, broadcast to all clients
app.post("/api/cli-usage/refresh", async (_req, res) => {
  try {
    const usage = await refreshCliUsageData();
    broadcast("cli_usage_update", usage);
    res.json({ ok: true, usage });
  } catch (e) {
    res.status(500).json({ ok: false, error: String(e) });
  }
});

// ---------------------------------------------------------------------------
// Production: serve React UI from dist/
// ---------------------------------------------------------------------------
if (isProduction) {
  app.use(express.static(distDir));
  // SPA fallback: serve index.html for non-API routes (Express 5 named wildcard)
  app.get("/{*splat}", (req, res) => {
    if (req.path.startsWith("/api/") || req.path === "/health" || req.path === "/healthz") {
      return res.status(404).json({ error: "not_found" });
    }
    res.sendFile(path.join(distDir, "index.html"));
  });
}

// ---------------------------------------------------------------------------
// Auto break rotation: idle ↔ break every 60s
// ---------------------------------------------------------------------------
function rotateBreaks(): void {
  // Rule: max 1 agent per department on break at a time
  const allAgents = db.prepare(
    "SELECT id, department_id, status FROM agents WHERE status IN ('idle','break')"
  ).all() as { id: string; department_id: string; status: string }[];

  if (allAgents.length === 0) return;

  // Meeting/CEO-office summoned agents should stay in office, not break room.
  for (const a of allAgents) {
    if (a.status === "break" && isAgentInMeeting(a.id)) {
      db.prepare("UPDATE agents SET status = 'idle' WHERE id = ?").run(a.id);
      broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(a.id));
    }
  }

  const candidates = allAgents.filter((a) => !isAgentInMeeting(a.id));
  if (candidates.length === 0) return;

  // Group by department
  const byDept = new Map<string, typeof candidates>();
  for (const a of candidates) {
    const list = byDept.get(a.department_id) || [];
    list.push(a);
    byDept.set(a.department_id, list);
  }

  for (const [, members] of byDept) {
    const onBreak = members.filter(a => a.status === 'break');
    const idle = members.filter(a => a.status === 'idle');

    if (onBreak.length > 1) {
      // Too many on break from same dept — return extras to idle
      const extras = onBreak.slice(1);
      for (const a of extras) {
        db.prepare("UPDATE agents SET status = 'idle' WHERE id = ?").run(a.id);
        broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(a.id));
      }
    } else if (onBreak.length === 1) {
      // 40% chance to return from break (avg ~2.5 min break)
      if (Math.random() < 0.4) {
        db.prepare("UPDATE agents SET status = 'idle' WHERE id = ?").run(onBreak[0].id);
        broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(onBreak[0].id));
      }
    } else if (onBreak.length === 0 && idle.length > 0) {
      // 50% chance to send one idle agent on break
      if (Math.random() < 0.5) {
        const pick = idle[Math.floor(Math.random() * idle.length)];
        db.prepare("UPDATE agents SET status = 'break' WHERE id = ?").run(pick.id);
        broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(pick.id));
      }
    }
  }
}

// Run rotation every 60 seconds, and once on startup after 5s
setTimeout(rotateBreaks, 5_000);
setInterval(rotateBreaks, 60_000);

// ---------------------------------------------------------------------------
// Start HTTP server + WebSocket
// ---------------------------------------------------------------------------
const server = app.listen(PORT, HOST, () => {
  console.log(`[CLImpire] v${PKG_VERSION} listening on http://${HOST}:${PORT} (db: ${dbPath})`);
  if (isProduction) {
    console.log(`[CLImpire] mode: production (serving UI from ${distDir})`);
  } else {
    console.log(`[CLImpire] mode: development (UI served by Vite on separate port)`);
  }
});

// WebSocket server on same HTTP server
const wss = new WebSocketServer({ server });

wss.on("connection", (ws: WebSocket, _req: IncomingMessage) => {
  wsClients.add(ws);
  console.log(`[CLImpire] WebSocket client connected (total: ${wsClients.size})`);

  // Send initial state to the newly connected client
  ws.send(JSON.stringify({
    type: "connected",
    payload: {
      version: PKG_VERSION,
      app: "CLImpire",
    },
    ts: nowMs(),
  }));

  ws.on("close", () => {
    wsClients.delete(ws);
    console.log(`[CLImpire] WebSocket client disconnected (total: ${wsClients.size})`);
  });

  ws.on("error", () => {
    wsClients.delete(ws);
  });
});

// ---------------------------------------------------------------------------
// Graceful shutdown
// ---------------------------------------------------------------------------
function gracefulShutdown(signal: string): void {
  console.log(`\n[CLImpire] ${signal} received. Shutting down gracefully...`);

  // Stop all active CLI processes
  for (const [taskId, child] of activeProcesses) {
    console.log(`[CLImpire] Stopping process for task ${taskId} (pid: ${child.pid})`);
    stopRequestedTasks.add(taskId);
    if (child.pid) {
      killPidTree(child.pid);
    }
    activeProcesses.delete(taskId);

    // Roll back in-flight task code on shutdown.
    rollbackTaskWorktree(taskId, "server_shutdown");

    // Reset agent status for running tasks
    const task = db.prepare("SELECT assigned_agent_id FROM tasks WHERE id = ?").get(taskId) as {
      assigned_agent_id: string | null;
    } | undefined;
    if (task?.assigned_agent_id) {
      db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?")
        .run(task.assigned_agent_id);
    }
    db.prepare("UPDATE tasks SET status = 'cancelled', updated_at = ? WHERE id = ? AND status = 'in_progress'")
      .run(nowMs(), taskId);
  }

  // Close all WebSocket connections
  for (const ws of wsClients) {
    ws.close(1001, "Server shutting down");
  }
  wsClients.clear();

  // Close WebSocket server
  wss.close(() => {
    // Close HTTP server
    server.close(() => {
      // Close database
      try {
        db.close();
      } catch { /* ignore */ }
      console.log("[CLImpire] Shutdown complete.");
      process.exit(0);
    });
  });

  // Force exit after 5 seconds if graceful shutdown hangs
  setTimeout(() => {
    console.error("[CLImpire] Forced exit after timeout.");
    process.exit(1);
  }, 5000).unref();
}

process.on("SIGINT", () => gracefulShutdown("SIGINT"));
process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));

// nodemon sends SIGUSR2 on restart — close DB cleanly before it kills us
process.once("SIGUSR2", () => {
  try { db.close(); } catch { /* ignore */ }
  process.kill(process.pid, "SIGUSR2");
});
