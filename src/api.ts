import type {
  Department, Agent, Task, TaskLog, Message,
  CliStatusMap, CompanyStats, CompanySettings,
  TaskStatus, TaskType, CliProvider, AgentRole,
  MessageType, ReceiverType, SubTask, MeetingMinute,
  CliModelInfo
} from './types';

const base = '';

async function request<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${base}${url}`, init);
  if (!r.ok) {
    const body = await r.json().catch(() => null);
    throw new Error(body?.error ?? body?.message ?? `Request failed: ${r.status}`);
  }
  return r.json();
}

function post(url: string, body?: unknown) {
  return request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
}

function patch(url: string, body: unknown) {
  return request(url, {
    method: 'PATCH',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function put(url: string, body: unknown) {
  return request(url, {
    method: 'PUT',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

function del(url: string) {
  return request(url, { method: 'DELETE' });
}

// Departments
export async function getDepartments(): Promise<Department[]> {
  const j = await request<{ departments: Department[] }>('/api/departments');
  return j.departments;
}

export async function getDepartment(id: string): Promise<{ department: Department; agents: Agent[] }> {
  return request(`/api/departments/${id}`);
}

// Agents
export async function getAgents(): Promise<Agent[]> {
  const j = await request<{ agents: Agent[] }>('/api/agents');
  return j.agents;
}

export async function getAgent(id: string): Promise<Agent> {
  const j = await request<{ agent: Agent }>(`/api/agents/${id}`);
  return j.agent;
}

export async function updateAgent(id: string, data: Partial<Pick<Agent, 'status' | 'current_task_id' | 'department_id' | 'role' | 'cli_provider' | 'personality'>>): Promise<void> {
  await patch(`/api/agents/${id}`, data);
}

// Tasks
export async function getTasks(filters?: { status?: TaskStatus; department_id?: string; agent_id?: string }): Promise<Task[]> {
  const params = new URLSearchParams();
  if (filters?.status) params.set('status', filters.status);
  if (filters?.department_id) params.set('department_id', filters.department_id);
  if (filters?.agent_id) params.set('agent_id', filters.agent_id);
  const q = params.toString();
  const j = await request<{ tasks: Task[] }>(`/api/tasks${q ? '?' + q : ''}`);
  return j.tasks;
}

export async function getTask(id: string): Promise<{ task: Task; logs: TaskLog[]; subtasks: SubTask[] }> {
  return request(`/api/tasks/${id}`);
}

export async function createTask(input: {
  title: string;
  description?: string;
  department_id?: string;
  task_type?: TaskType;
  priority?: number;
  project_path?: string;
}): Promise<string> {
  const j = await post('/api/tasks', input) as { id: string };
  return j.id;
}

export async function updateTask(id: string, data: Partial<Pick<Task, 'title' | 'description' | 'status' | 'priority' | 'task_type' | 'department_id' | 'project_path'>>): Promise<void> {
  await patch(`/api/tasks/${id}`, data);
}

export async function deleteTask(id: string): Promise<void> {
  await del(`/api/tasks/${id}`);
}

export async function assignTask(id: string, agentId: string): Promise<void> {
  await post(`/api/tasks/${id}/assign`, { agent_id: agentId });
}

export async function runTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/run`);
}

export async function stopTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/stop`, { mode: 'cancel' });
}

export async function pauseTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/stop`, { mode: 'pause' });
}

export async function resumeTask(id: string): Promise<void> {
  await post(`/api/tasks/${id}/resume`);
}

// Messages
export async function getMessages(params: { receiver_type?: ReceiverType; receiver_id?: string; limit?: number }): Promise<Message[]> {
  const sp = new URLSearchParams();
  if (params.receiver_type) sp.set('receiver_type', params.receiver_type);
  if (params.receiver_id) sp.set('receiver_id', params.receiver_id);
  if (params.limit) sp.set('limit', String(params.limit));
  const q = sp.toString();
  const j = await request<{ messages: Message[] }>(`/api/messages${q ? '?' + q : ''}`);
  return j.messages;
}

export async function sendMessage(input: {
  receiver_type: ReceiverType;
  receiver_id?: string;
  content: string;
  message_type?: MessageType;
  task_id?: string;
}): Promise<string> {
  const j = await post('/api/messages', { sender_type: 'ceo', ...input }) as { id: string };
  return j.id;
}

export async function sendAnnouncement(content: string): Promise<string> {
  const j = await post('/api/announcements', { content }) as { id: string };
  return j.id;
}

export async function clearMessages(agentId?: string): Promise<void> {
  const params = new URLSearchParams();
  if (agentId) {
    params.set('agent_id', agentId);
  } else {
    params.set('scope', 'announcements');
  }
  await del(`/api/messages?${params.toString()}`);
}

// Terminal
export async function getTerminal(id: string, lines?: number, pretty?: boolean): Promise<{
  ok: boolean;
  exists: boolean;
  path: string;
  text: string;
  task_logs?: Array<{ id: number; kind: string; message: string; created_at: number }>;
}> {
  const params = new URLSearchParams();
  if (lines) params.set('lines', String(lines));
  if (pretty) params.set('pretty', '1');
  const q = params.toString();
  return request(`/api/tasks/${id}/terminal${q ? '?' + q : ''}`);
}

export async function getTaskMeetingMinutes(id: string): Promise<MeetingMinute[]> {
  const j = await request<{ meetings: MeetingMinute[] }>(`/api/tasks/${id}/meeting-minutes`);
  return j.meetings;
}

// CLI Status
export async function getCliStatus(refresh?: boolean): Promise<CliStatusMap> {
  const q = refresh ? '?refresh=1' : '';
  const j = await request<{ providers: CliStatusMap }>(`/api/cli-status${q}`);
  return j.providers;
}

// Stats
export async function getStats(): Promise<CompanyStats> {
  const j = await request<{ stats: CompanyStats }>('/api/stats');
  return j.stats;
}

// Settings
export async function getSettings(): Promise<CompanySettings> {
  const j = await request<{ settings: CompanySettings }>('/api/settings');
  return j.settings;
}

export async function saveSettings(settings: CompanySettings): Promise<void> {
  await put('/api/settings', settings);
}

// OAuth
export interface OAuthProviderStatus {
  connected: boolean;
  source: string | null;
  email: string | null;
  scope: string | null;
  expires_at: number | null;
  created_at: number;
  updated_at: number;
  webConnectable: boolean;
}

export type OAuthConnectProvider = "github-copilot" | "antigravity";

export interface OAuthStatus {
  storageReady: boolean;
  providers: Record<string, OAuthProviderStatus>;
}

export async function getOAuthStatus(): Promise<OAuthStatus> {
  return request<OAuthStatus>('/api/oauth/status');
}

export function getOAuthStartUrl(provider: OAuthConnectProvider, redirectTo: string): string {
  const params = new URLSearchParams({ provider, redirect_to: redirectTo });
  return `/api/oauth/start?${params.toString()}`;
}

export async function disconnectOAuth(provider: OAuthConnectProvider): Promise<void> {
  await post('/api/oauth/disconnect', { provider });
}

// GitHub Device Code Flow
export interface DeviceCodeStart {
  stateId: string;
  userCode: string;
  verificationUri: string;
  expiresIn: number;
  interval: number;
}

export interface DevicePollResult {
  status: "pending" | "complete" | "slow_down" | "expired" | "denied" | "error";
  email?: string | null;
  error?: string;
}

export async function startGitHubDeviceFlow(): Promise<DeviceCodeStart> {
  return post('/api/oauth/github-copilot/device-start') as Promise<DeviceCodeStart>;
}

export async function pollGitHubDevice(stateId: string): Promise<DevicePollResult> {
  return post('/api/oauth/github-copilot/device-poll', { stateId }) as Promise<DevicePollResult>;
}

// OAuth Models
export async function getOAuthModels(): Promise<Record<string, string[]>> {
  const j = await request<{ models: Record<string, string[]> }>('/api/oauth/models');
  return j.models;
}

// CLI Models (for CLI provider model selection)
export async function getCliModels(): Promise<Record<string, CliModelInfo[]>> {
  const j = await request<{ models: Record<string, CliModelInfo[]> }>('/api/cli-models');
  return j.models;
}

// Git Worktree management
export interface TaskDiffResult {
  ok: boolean;
  hasWorktree?: boolean;
  branchName?: string;
  stat?: string;
  diff?: string;
  error?: string;
}

export interface MergeResult {
  ok: boolean;
  message: string;
  conflicts?: string[];
}

export interface WorktreeEntry {
  taskId: string;
  branchName: string;
  worktreePath: string;
  projectPath: string;
}

export async function getTaskDiff(id: string): Promise<TaskDiffResult> {
  return request<TaskDiffResult>(`/api/tasks/${id}/diff`);
}

export async function mergeTask(id: string): Promise<MergeResult> {
  return post(`/api/tasks/${id}/merge`) as Promise<MergeResult>;
}

export async function discardTask(id: string): Promise<{ ok: boolean; message: string }> {
  return post(`/api/tasks/${id}/discard`) as Promise<{ ok: boolean; message: string }>;
}

export async function getWorktrees(): Promise<{ ok: boolean; worktrees: WorktreeEntry[] }> {
  return request<{ ok: boolean; worktrees: WorktreeEntry[] }>('/api/worktrees');
}

// CLI Usage
export interface CliUsageWindow {
  label: string;           // "5-hour", "7-day", "Primary", "2.5 Pro", etc.
  utilization: number;     // 0.0 – 1.0
  resetsAt: string | null; // ISO 8601
}

export interface CliUsageEntry {
  windows: CliUsageWindow[];
  error: string | null;    // "unauthenticated" | "unavailable" | "not_implemented" | null
}

export async function getCliUsage(): Promise<{ ok: boolean; usage: Record<string, CliUsageEntry> }> {
  return request<{ ok: boolean; usage: Record<string, CliUsageEntry> }>('/api/cli-usage');
}

export async function refreshCliUsage(): Promise<{ ok: boolean; usage: Record<string, CliUsageEntry> }> {
  return post('/api/cli-usage/refresh') as Promise<{ ok: boolean; usage: Record<string, CliUsageEntry> }>;
}

// Skills
export interface SkillEntry {
  rank: number;
  name: string;
  repo: string;
  installs: number;
}

export async function getSkills(): Promise<SkillEntry[]> {
  const j = await request<{ skills: SkillEntry[] }>('/api/skills');
  return j.skills;
}

// SubTasks
export async function getActiveSubtasks(): Promise<SubTask[]> {
  const j = await request<{ subtasks: SubTask[] }>('/api/subtasks?active=1');
  return j.subtasks;
}

export async function createSubtask(taskId: string, input: {
  title: string;
  description?: string;
  assigned_agent_id?: string;
}): Promise<SubTask> {
  return post(`/api/tasks/${taskId}/subtasks`, input) as Promise<SubTask>;
}

export async function updateSubtask(id: string, data: Partial<Pick<SubTask, 'title' | 'description' | 'status' | 'assigned_agent_id' | 'blocked_reason'>>): Promise<SubTask> {
  return patch(`/api/subtasks/${id}`, data) as Promise<SubTask>;
}
