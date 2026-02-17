// Department
export interface Department {
  id: string;
  name: string;
  name_ko: string;
  icon: string;
  color: string;
  description: string | null;
  sort_order: number;
  created_at: number;
  agent_count?: number;
}

// Agent roles
export type AgentRole = 'team_leader' | 'senior' | 'junior' | 'intern';
export type AgentStatus = 'idle' | 'working' | 'break' | 'offline';
export type CliProvider = 'claude' | 'codex' | 'gemini' | 'opencode' | 'copilot' | 'antigravity';

export interface Agent {
  id: string;
  name: string;
  name_ko: string;
  department_id: string;
  department?: Department;
  role: AgentRole;
  cli_provider: CliProvider;
  avatar_emoji: string;
  personality: string | null;
  status: AgentStatus;
  current_task_id: string | null;
  stats_tasks_done: number;
  stats_xp: number;
  created_at: number;
}

// Task
export type TaskStatus = 'inbox' | 'planned' | 'in_progress' | 'review' | 'done' | 'cancelled';
export type TaskType = 'general' | 'development' | 'design' | 'analysis' | 'presentation' | 'documentation';

export interface Task {
  id: string;
  title: string;
  description: string | null;
  department_id: string | null;
  assigned_agent_id: string | null;
  assigned_agent?: Agent;
  status: TaskStatus;
  priority: number;
  task_type: TaskType;
  project_path: string | null;
  result: string | null;
  started_at: number | null;
  completed_at: number | null;
  created_at: number;
  updated_at: number;
}

export interface TaskLog {
  id: number;
  task_id: string;
  kind: string;
  message: string;
  created_at: number;
}

// Messages
export type SenderType = 'ceo' | 'agent' | 'system';
export type ReceiverType = 'agent' | 'department' | 'all';
export type MessageType = 'chat' | 'task_assign' | 'announcement' | 'report' | 'status_update';

export interface Message {
  id: string;
  sender_type: SenderType;
  sender_id: string | null;
  sender_agent?: Agent;
  receiver_type: ReceiverType;
  receiver_id: string | null;
  content: string;
  message_type: MessageType;
  task_id: string | null;
  created_at: number;
}

// CLI Status
export interface CliToolStatus {
  installed: boolean;
  version: string | null;
  authenticated: boolean;
  authHint: string;
}

export type CliStatusMap = Record<CliProvider, CliToolStatus>;

// Company Stats (matches server GET /api/stats response)
export interface CompanyStats {
  tasks: {
    total: number;
    done: number;
    in_progress: number;
    inbox: number;
    planned: number;
    review: number;
    cancelled: number;
    completion_rate: number;
  };
  agents: {
    total: number;
    working: number;
    idle: number;
  };
  top_agents: Array<{
    id: string;
    name: string;
    avatar_emoji: string;
    stats_tasks_done: number;
    stats_xp: number;
  }>;
  tasks_by_department: Array<{
    id: string;
    name: string;
    icon: string;
    color: string;
    total_tasks: number;
    done_tasks: number;
  }>;
  recent_activity: Array<Record<string, unknown>>;
}

// WebSocket Events
export type WSEventType =
  | 'task_update'
  | 'agent_status'
  | 'new_message'
  | 'announcement'
  | 'cli_output'
  | 'connected';

export interface WSEvent {
  type: WSEventType;
  payload: unknown;
}

// Settings
export interface CompanySettings {
  companyName: string;
  ceoName: string;
  autoAssign: boolean;
  theme: 'dark' | 'light';
  language: 'ko' | 'en';
  defaultProvider: CliProvider;
}

export const DEFAULT_SETTINGS: CompanySettings = {
  companyName: 'CLImpire Corp.',
  ceoName: 'CEO',
  autoAssign: true,
  theme: 'dark',
  language: 'ko',
  defaultProvider: 'claude',
};
