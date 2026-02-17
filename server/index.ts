import express from "express";
import cors from "cors";
import path from "path";
import fs from "node:fs";
import os from "node:os";
import { randomUUID, createHash, randomBytes, createCipheriv, createDecipheriv } from "node:crypto";
import { spawn, execFile, type ChildProcess } from "node:child_process";
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
// Production static file serving
// ---------------------------------------------------------------------------
const distDir = path.resolve(__server_dirname, "..", "dist");
const isProduction = !process.env.VITE_DEV && fs.existsSync(path.join(distDir, "index.html"));

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------
const dbPath = process.env.DB_PATH ?? path.join(process.cwd(), "climpire.sqlite");
const db = new DatabaseSync(dbPath);

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

CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_tasks_agent ON tasks(assigned_agent_id);
CREATE INDEX IF NOT EXISTS idx_tasks_dept ON tasks(department_id);
CREATE INDEX IF NOT EXISTS idx_task_logs_task ON task_logs(task_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_type, receiver_id, created_at DESC);
`);

// ---------------------------------------------------------------------------
// Seed default data
// ---------------------------------------------------------------------------
const deptCount = (db.prepare("SELECT COUNT(*) as cnt FROM departments").get() as { cnt: number }).cnt;

if (deptCount === 0) {
  const insertDept = db.prepare(
    "INSERT INTO departments (id, name, name_ko, icon, color) VALUES (?, ?, ?, ?, ?)"
  );
  insertDept.run("dev", "Development", "개발팀", "💻", "#3b82f6");
  insertDept.run("design", "Design", "디자인팀", "🎨", "#8b5cf6");
  insertDept.run("planning", "Planning", "기획팀", "📊", "#f59e0b");
  insertDept.run("operations", "Operations", "운영팀", "⚙️", "#10b981");
  console.log("[CLImpire] Seeded default departments");
}

const agentCount = (db.prepare("SELECT COUNT(*) as cnt FROM agents").get() as { cnt: number }).cnt;

if (agentCount === 0) {
  const insertAgent = db.prepare(
    `INSERT INTO agents (id, name, name_ko, department_id, role, cli_provider, avatar_emoji, personality)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  );
  insertAgent.run(randomUUID(), "Aria",  "아리아", "dev",        "team_leader", "claude",   "👩‍💻", "꼼꼼한 시니어 개발자");
  insertAgent.run(randomUUID(), "Bolt",  "볼트",   "dev",        "senior",      "codex",    "⚡",   "빠른 코딩 전문가");
  insertAgent.run(randomUUID(), "Nova",  "노바",   "dev",        "junior",      "gemini",   "🌟",   "창의적인 주니어");
  insertAgent.run(randomUUID(), "Pixel", "픽셀",   "design",     "team_leader", "claude",   "🎨",   "디자인 리더");
  insertAgent.run(randomUUID(), "Sage",  "세이지", "planning",   "team_leader", "opencode", "🧠",   "전략 분석가");
  insertAgent.run(randomUUID(), "Atlas", "아틀라스","operations", "team_leader", "claude",   "🗺️",  "운영의 달인");
  console.log("[CLImpire] Seeded default agents");
}

// ---------------------------------------------------------------------------
// Track active child processes
// ---------------------------------------------------------------------------
const activeProcesses = new Map<string, ChildProcess>();

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
function buildAgentArgs(provider: string): string[] {
  switch (provider) {
    case "codex":
      return ["codex", "--yolo", "exec", "--json"];
    case "claude":
      return [
        "claude",
        "--dangerously-skip-permissions",
        "--print",
        "--verbose",
        "--output-format=stream-json",
        "--include-partial-messages",
      ];
    case "gemini":
      return ["gemini", "--yolo", "--output-format=stream-json"];
    case "opencode":
      return ["opencode", "run", "--format", "json"];
    case "copilot":
    case "antigravity":
      throw new Error(`${provider} uses HTTP agent (not CLI spawn)`);
    default:
      throw new Error(`unsupported CLI provider: ${provider}`);
  }
}

function spawnCliAgent(
  taskId: string,
  provider: string,
  prompt: string,
  projectPath: string,
  logPath: string,
): ChildProcess {
  // Save prompt for debugging
  const promptPath = path.join(logsDir, `${taskId}.prompt.txt`);
  fs.writeFileSync(promptPath, prompt, "utf8");

  const args = buildAgentArgs(provider);
  const logStream = fs.createWriteStream(logPath, { flags: "w" });

  const child = spawn(args[0], args.slice(1), {
    cwd: projectPath,
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
    broadcast("cli_output", { task_id: taskId, stream: "stdout", data: chunk.toString("utf8") });
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

function killPidTree(pid: number): void {
  if (process.platform === "win32") {
    try {
      execFile("taskkill", ["/pid", String(pid), "/T", "/F"], { timeout: 5000 }, () => {});
    } catch { /* ignore */ }
  } else {
    try { process.kill(-pid, "SIGTERM"); } catch { /* ignore */ }
    try { process.kill(pid, "SIGTERM"); } catch { /* ignore */ }
  }
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
      if (jsonHasKey(path.join(os.homedir(), ".gemini", "oauth_creds.json"), "access_token")) return true;
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
// Run completion handler
// ---------------------------------------------------------------------------
function handleTaskRunComplete(taskId: string, exitCode: number): void {
  activeProcesses.delete(taskId);

  const t = nowMs();
  const status = exitCode === 0 ? "done" : "inbox";
  const logKind = exitCode === 0 ? "completed" : "failed";

  appendTaskLog(taskId, "system", `RUN ${logKind} (exit code: ${exitCode})`);

  // Update task
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId) as {
    assigned_agent_id: string | null;
    title: string;
  } | undefined;

  db.prepare(
    "UPDATE tasks SET status = ?, updated_at = ?, completed_at = ? WHERE id = ?"
  ).run(status, t, exitCode === 0 ? t : null, taskId);

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

  // Read log file for result
  const logPath = path.join(logsDir, `${taskId}.log`);
  let result: string | null = null;
  try {
    if (fs.existsSync(logPath)) {
      const raw = fs.readFileSync(logPath, "utf8");
      result = raw.slice(-2000); // last 2000 chars as result summary
    }
  } catch { /* ignore */ }

  if (result) {
    db.prepare("UPDATE tasks SET result = ? WHERE id = ?").run(result, taskId);
  }

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId);
  broadcast("task_update", updatedTask);

  // Create system message about completion
  if (task) {
    const msgId = randomUUID();
    db.prepare(
      `INSERT INTO messages (id, sender_type, sender_id, receiver_type, receiver_id, content, message_type, task_id, created_at)
       VALUES (?, 'system', NULL, 'all', NULL, ?, 'status_update', ?, ?)`
    ).run(
      msgId,
      exitCode === 0
        ? `Task "${task.title}" completed successfully.`
        : `Task "${task.title}" failed (exit code: ${exitCode}).`,
      taskId,
      t,
    );
    broadcast("new_message", {
      id: msgId,
      sender_type: "system",
      content: exitCode === 0
        ? `Task "${task.title}" completed successfully.`
        : `Task "${task.title}" failed (exit code: ${exitCode}).`,
      message_type: "status_update",
      task_id: taskId,
      created_at: t,
    });
  }
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
    ORDER BY d.created_at ASC
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
  if (!["claude", "codex", "gemini", "opencode"].includes(provider)) {
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

  const child = spawnCliAgent(taskId, provider, prompt, projectPath, logPath);

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
      d.icon AS department_icon
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

  res.json({ task, logs });
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
    killPidTree(activeChild.pid);
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
  if (!["claude", "codex", "gemini", "opencode"].includes(provider)) {
    return res.status(400).json({ error: "unsupported_provider", provider });
  }

  const projectPath = task.project_path || (req.body?.project_path as string | undefined) || process.cwd();
  const logPath = path.join(logsDir, `${id}.log`);

  // Build rich prompt with agent context
  const roleLabel = { team_leader: "Team Leader", senior: "Senior", junior: "Junior", intern: "Intern" }[agent.role] || agent.role;
  const prompt = [
    `[Task] ${task.title}`,
    task.description ? `\n${task.description}` : "",
    `\n---`,
    `Agent: ${agent.name} (${roleLabel}, ${agent.department_name || "Unassigned"})`,
    agent.personality ? `Personality: ${agent.personality}` : "",
    `Please complete the task above thoroughly.`,
  ].filter(Boolean).join("\n");

  appendTaskLog(id, "system", `RUN start (agent=${agent.name}, provider=${provider})`);

  const child = spawnCliAgent(id, provider, prompt, projectPath, logPath);

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

  res.json({ ok: true, pid: child.pid ?? null, logPath, cwd: projectPath });
});

app.post("/api/tasks/:id/stop", (req, res) => {
  const id = String(req.params.id);
  const task = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as {
    id: string;
    assigned_agent_id: string | null;
  } | undefined;
  if (!task) return res.status(404).json({ error: "not_found" });

  const activeChild = activeProcesses.get(id);
  if (!activeChild?.pid) {
    // No active process; just update status
    db.prepare("UPDATE tasks SET status = 'cancelled', updated_at = ? WHERE id = ?").run(nowMs(), id);
    if (task.assigned_agent_id) {
      db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?").run(task.assigned_agent_id);
    }
    return res.json({ ok: true, stopped: false, message: "No active process found." });
  }

  killPidTree(activeChild.pid);
  activeProcesses.delete(id);

  appendTaskLog(id, "system", `STOP sent to pid ${activeChild.pid}`);

  const t = nowMs();
  db.prepare("UPDATE tasks SET status = 'cancelled', updated_at = ? WHERE id = ?").run(t, id);

  if (task.assigned_agent_id) {
    db.prepare("UPDATE agents SET status = 'idle', current_task_id = NULL WHERE id = ?").run(task.assigned_agent_id);
    const updatedAgent = db.prepare("SELECT * FROM agents WHERE id = ?").get(task.assigned_agent_id);
    broadcast("agent_status", updatedAgent);
  }

  const updatedTask = db.prepare("SELECT * FROM tasks WHERE id = ?").get(id);
  broadcast("task_update", updatedTask);

  res.json({ ok: true, stopped: true, pid: activeChild.pid });
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
  dev:        ["개발", "코딩", "프론트", "백엔드", "API", "서버", "코드", "버그", "배포", "테스트", "프로그램", "앱", "웹"],
  design:     ["디자인", "UI", "UX", "목업", "피그마", "아이콘", "로고", "배너", "레이아웃", "시안"],
  planning:   ["기획", "전략", "분석", "리서치", "보고서", "PPT", "발표", "시장", "조사", "제안"],
  operations: ["운영", "배포", "인프라", "모니터링", "서버관리", "CI", "CD", "DevOps", "장애"],
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

function generateChatReply(agent: AgentRow, ceoMessage: string): string {
  const isGreeting = /안녕|하이|hello|hi|반가|좋은\s*(아침|오후|저녁)/i.test(ceoMessage);
  const isQuestion = /\?|어때|뭐해|어디|언제|왜|어떻게|무엇|있어|됐어|가능|할 수/i.test(ceoMessage);
  const isReport = /보고|현황|상태|진행|어디까지/i.test(ceoMessage);
  const isPraise = /잘했|수고|고마|감사|좋아|훌륭|대단/i.test(ceoMessage);
  const role = ROLE_LABEL[agent.role] || agent.role;
  const dept = agent.department_id ? getDeptName(agent.department_id) : "";
  const nameTag = dept ? `${dept} ${role} ${agent.name_ko || agent.name}` : `${role} ${agent.name_ko || agent.name}`;

  if (agent.status === "working") {
    if (isGreeting) return pickRandom([
      `네, 대표님! ${nameTag}입니다. 현재 작업 중이지만 말씀하세요 😊`,
      `안녕하세요 대표님! ${nameTag}입니다. 지금 업무 진행 중인데, 무엇을 도와드릴까요?`,
    ]);
    if (isReport) return pickRandom([
      `현재 할당된 업무를 진행 중입니다. 순조롭게 진행되고 있어요! 📊`,
      `네! 지금 집중해서 작업하고 있습니다. 완료되면 바로 보고 드리겠습니다.`,
    ]);
    return pickRandom([
      `현재 진행 중인 작업이 있습니다. 메모해두고 현 작업 완료 후 처리하겠습니다! 📝`,
      `알겠습니다, 대표님. 현재 업무 완료 후 바로 확인하겠습니다!`,
    ]);
  }
  if (agent.status === "break") return pickRandom([
    `잠시 휴식 중이었습니다! 바로 복귀하겠습니다 ☕`, `네, 대표님! 휴식 중이었는데 말씀하세요~`,
  ]);
  if (agent.status === "offline") return `[자동응답] 현재 오프라인 상태입니다. 복귀 후 확인하겠습니다.`;
  if (isPraise) return pickRandom([
    `감사합니다, 대표님! 더 열심히 하겠습니다! 💪`, `대표님 덕분에 힘이 납니다! 😊`,
  ]);
  if (isGreeting) return pickRandom([
    `안녕하세요, 대표님! ${nameTag}입니다. 오늘도 좋은 하루 되세요 😊`,
    `안녕하세요! ${nameTag}입니다. 말씀하세요!`,
    `네, 대표님! ${nameTag}입니다. 오늘도 화이팅입니다! 🔥`,
  ]);
  if (isReport) return pickRandom([
    `현재 대기 중이며, 새로운 업무 할당을 기다리고 있습니다 📋`,
    `특별히 진행 중인 업무는 없습니다. 새로운 작업이 있으시면 말씀해주세요!`,
  ]);
  if (isQuestion) return pickRandom([
    `네, 말씀하신 부분 확인해보겠습니다! 잠시만 기다려주세요.`,
    `확인해보겠습니다. 조금만 기다려주세요! 🔍`,
  ]);
  return pickRandom([
    `네, 확인했습니다! 추가 지시사항이 있으시면 말씀해주세요.`,
    `네! 말씀 잘 들었습니다 😊`,
    `네, 대표님. 말씀하신 내용 메모해두었습니다! 📝`,
  ]);
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

function findBestSubordinate(deptId: string, excludeId: string): AgentRow | null {
  // Find subordinates in department, prefer: idle > break, higher role first
  const agents = db.prepare(
    `SELECT * FROM agents WHERE department_id = ? AND id != ? AND role != 'team_leader' ORDER BY
       CASE status WHEN 'idle' THEN 0 WHEN 'break' THEN 1 WHEN 'working' THEN 2 ELSE 3 END,
       CASE role WHEN 'senior' THEN 0 WHEN 'junior' THEN 1 WHEN 'intern' THEN 2 ELSE 3 END`
  ).all(deptId, excludeId) as AgentRow[];
  return agents[0] ?? null;
}

function findTeamLeader(deptId: string): AgentRow | null {
  return (db.prepare(
    "SELECT * FROM agents WHERE department_id = ? AND role = 'team_leader' LIMIT 1"
  ).get(deptId) as AgentRow | undefined) ?? null;
}

function getDeptName(deptId: string): string {
  const d = db.prepare("SELECT name_ko FROM departments WHERE id = ?").get(deptId) as { name_ko: string } | undefined;
  return d?.name_ko ?? deptId;
}

function handleTaskDelegation(
  teamLeader: AgentRow,
  ceoMessage: string,
  ceoMsgId: string,
): void {
  const leaderName = teamLeader.name_ko || teamLeader.name;
  const leaderDeptId = teamLeader.department_id!;
  const leaderDeptName = getDeptName(leaderDeptId);

  // --- Step 1: Team leader acknowledges (1~2 sec) ---
  const ackDelay = 1000 + Math.random() * 1000;
  setTimeout(() => {
    // Find best subordinate
    const subordinate = findBestSubordinate(leaderDeptId, teamLeader.id);

    // Create task
    const taskId = randomUUID();
    const t = nowMs();
    const taskTitle = ceoMessage.length > 60 ? ceoMessage.slice(0, 57) + "..." : ceoMessage;
    db.prepare(`
      INSERT INTO tasks (id, title, description, department_id, status, priority, task_type, created_at, updated_at)
      VALUES (?, ?, ?, ?, 'planned', 1, 'general', ?, ?)
    `).run(taskId, taskTitle, `[CEO 지시] ${ceoMessage}`, leaderDeptId, t, t);
    appendTaskLog(taskId, "system", `CEO가 ${leaderName}에게 업무 지시: ${ceoMessage}`);

    broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));

    // Detect cross-department needs
    const mentionedDepts = detectTargetDepartments(ceoMessage).filter((d) => d !== leaderDeptId);

    // Acknowledgment message from team leader
    if (subordinate) {
      const subName = subordinate.name_ko || subordinate.name;
      const subRole = ROLE_LABEL[subordinate.role] || subordinate.role;

      let ackMsg: string;
      if (mentionedDepts.length > 0) {
        const crossDeptNames = mentionedDepts.map(getDeptName).join(", ");
        ackMsg = pickRandom([
          `네, 대표님! 확인했습니다. ${subRole} ${subName}에게 할당하고, ${crossDeptNames}에도 협조 요청하겠습니다! 📋`,
          `알겠습니다! ${subName}가 메인으로 진행하고, ${crossDeptNames}과 협업 조율하겠습니다 🤝`,
        ]);
      } else {
        ackMsg = pickRandom([
          `네, 대표님! 확인했습니다. ${subRole} ${subName}에게 바로 할당하겠습니다! 📋`,
          `알겠습니다! 우리 팀 ${subName}가 적임자입니다. 바로 지시하겠습니다 🚀`,
          `확인했습니다, 대표님! ${subName}에게 전달하고 진행 관리하겠습니다.`,
        ]);
      }
      sendAgentMessage(teamLeader, ackMsg, "chat", "agent", null, taskId);

      // --- Step 2: Team leader delegates to subordinate (2~3 sec after ack) ---
      const delegateDelay = 2000 + Math.random() * 1000;
      setTimeout(() => {
        // Assign task to subordinate
        const t2 = nowMs();
        db.prepare(
          "UPDATE tasks SET assigned_agent_id = ?, status = 'planned', updated_at = ? WHERE id = ?"
        ).run(subordinate.id, t2, taskId);
        db.prepare("UPDATE agents SET current_task_id = ? WHERE id = ?").run(taskId, subordinate.id);
        appendTaskLog(taskId, "system", `${leaderName}이(가) ${subName}에게 할당`);

        broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
        broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(subordinate.id));

        // Team leader → subordinate delegation message
        const delegateMsg = pickRandom([
          `${subName}, 대표님 지시사항이야. "${ceoMessage}" — 확인하고 진행해줘!`,
          `${subName}! 긴급 업무야. "${ceoMessage}" — 우선순위 높게 처리 부탁해.`,
          `${subName}, 새 업무 할당이야: "${ceoMessage}" — 진행 상황 수시로 공유해줘 👍`,
        ]);
        sendAgentMessage(teamLeader, delegateMsg, "task_assign", "agent", subordinate.id, taskId);

        // --- Step 3: Subordinate acknowledges & starts working (1~2 sec after delegation) ---
        const subAckDelay = 1000 + Math.random() * 1000;
        setTimeout(() => {
          const subAckMsg = pickRandom([
            `네, ${ROLE_LABEL[teamLeader.role]} ${leaderName}님! 확인했습니다. 바로 착수하겠습니다! 💪`,
            `알겠습니다! 바로 시작하겠습니다. 진행 상황 공유 드리겠습니다.`,
            `확인했습니다, ${leaderName}님! 최선을 다해 처리하겠습니다 🔥`,
          ]);
          sendAgentMessage(subordinate, subAckMsg, "chat", "agent", null, taskId);

          // Move task to in_progress and agent to working
          const t3 = nowMs();
          db.prepare(
            "UPDATE tasks SET status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
          ).run(t3, t3, taskId);
          db.prepare(
            "UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?"
          ).run(taskId, subordinate.id);
          appendTaskLog(taskId, "system", `${subName}이(가) 작업 시작`);

          broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
          broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(subordinate.id));
        }, subAckDelay);

        // --- Step 4: Cross-department cooperation (3~4 sec after ack) ---
        if (mentionedDepts.length > 0) {
          const crossDelay = 3000 + Math.random() * 1000;
          setTimeout(() => {
            for (const crossDeptId of mentionedDepts) {
              const crossLeader = findTeamLeader(crossDeptId);
              if (!crossLeader) continue;
              const crossDeptName = getDeptName(crossDeptId);
              const crossLeaderName = crossLeader.name_ko || crossLeader.name;

              // Team leader sends cooperation request
              const coopReq = pickRandom([
                `${crossLeaderName}님, 안녕하세요! 대표님 지시로 "${taskTitle}" 업무 진행 중인데, ${crossDeptName} 협조가 필요합니다. 도움 부탁드려요! 🤝`,
                `${crossLeaderName}님! "${taskTitle}" 건으로 ${crossDeptName} 지원이 필요합니다. 시간 되시면 협의 부탁드립니다.`,
              ]);
              sendAgentMessage(teamLeader, coopReq, "chat", "agent", crossLeader.id, taskId);

              // Cross-dept team leader acknowledges (1~2 sec later)
              const crossAckDelay = 1000 + Math.random() * 1000;
              setTimeout(() => {
                const crossAckMsg = pickRandom([
                  `네, ${leaderName}님! 확인했습니다. ${crossDeptName}에서 지원 가능한 부분 확인해보겠습니다 👍`,
                  `알겠습니다! 우리 팀에서 관련 작업 서포트하겠습니다. 상세 내용 공유 부탁드려요.`,
                  `확인했습니다, ${leaderName}님! ${crossDeptName} 리소스 확인 후 회신 드리겠습니다.`,
                ]);
                sendAgentMessage(crossLeader, crossAckMsg, "chat", "agent", null, taskId);
              }, crossAckDelay);
            }
          }, crossDelay);
        }
      }, delegateDelay);
    } else {
      // No subordinate available — team leader handles it themselves
      const selfMsg = pickRandom([
        `네, 대표님! 확인했습니다. 현재 팀원들이 모두 업무 중이라 제가 직접 처리하겠습니다! 💪`,
        `알겠습니다! 팀 내 여유 인력이 없어서 제가 직접 진행하겠습니다.`,
      ]);
      sendAgentMessage(teamLeader, selfMsg, "chat", "agent", null, taskId);

      // Assign to self and start immediately
      const t2 = nowMs();
      db.prepare(
        "UPDATE tasks SET assigned_agent_id = ?, status = 'in_progress', started_at = ?, updated_at = ? WHERE id = ?"
      ).run(teamLeader.id, t2, t2, taskId);
      db.prepare("UPDATE agents SET status = 'working', current_task_id = ? WHERE id = ?").run(taskId, teamLeader.id);
      appendTaskLog(taskId, "system", `${leaderName}이(가) 직접 작업 시작`);

      broadcast("task_update", db.prepare("SELECT * FROM tasks WHERE id = ?").get(taskId));
      broadcast("agent_status", db.prepare("SELECT * FROM agents WHERE id = ?").get(teamLeader.id));
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

  // Regular chat reply
  const delay = 1000 + Math.random() * 2000;
  setTimeout(() => {
    const reply = generateChatReply(agent, ceoMessage);
    sendAgentMessage(agent, reply);
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
  res.json({ ok: true, message: msg });
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
// Task terminal log viewer (ported from claw-kanban)
// ---------------------------------------------------------------------------
app.get("/api/tasks/:id/terminal", (req, res) => {
  const id = String(req.params.id);
  const lines = Math.min(Math.max(Number(req.query.lines ?? 200), 20), 4000);
  const filePath = path.join(logsDir, `${id}.log`);

  if (!fs.existsSync(filePath)) {
    return res.json({ ok: true, exists: false, path: filePath, text: "" });
  }

  const raw = fs.readFileSync(filePath, "utf8");
  const parts = raw.split(/\r?\n/);
  const tail = parts.slice(Math.max(0, parts.length - lines)).join("\n");
  res.json({ ok: true, exists: true, path: filePath, text: tail });
});

// ---------------------------------------------------------------------------
// OAuth credentials (simplified for CLImpire)
// ---------------------------------------------------------------------------
app.get("/api/oauth/status", (_req, res) => {
  const rows = db.prepare(
    "SELECT provider, source, email, scope, expires_at, created_at, updated_at FROM oauth_credentials"
  ).all() as Array<{
    provider: string;
    source: string | null;
    email: string | null;
    scope: string | null;
    expires_at: number | null;
    created_at: number;
    updated_at: number;
  }>;

  const providers: Record<string, unknown> = {};
  for (const row of rows) {
    providers[row.provider] = {
      connected: true,
      source: row.source,
      email: row.email,
      scope: row.scope,
      expires_at: row.expires_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
    };
  }

  res.json({
    storageReady: Boolean(OAUTH_ENCRYPTION_SECRET),
    providers,
  });
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
    if (child.pid) {
      killPidTree(child.pid);
    }
    activeProcesses.delete(taskId);

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
