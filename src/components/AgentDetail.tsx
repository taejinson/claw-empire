import { useState, useMemo, useEffect, useCallback } from "react";
import type { Agent, Task, Department, SubTask } from "../types";
import * as api from "../api";
import type { OAuthStatus, OAuthAccountInfo } from "../api";
import AgentAvatar from "./AgentAvatar";

interface SubAgent {
  id: string;
  parentAgentId: string;
  task: string;
  status: "working" | "done";
}

interface AgentDetailProps {
  agent: Agent;
  agents: Agent[];
  department: Department | undefined;
  departments: Department[];
  tasks: Task[];
  subAgents: SubAgent[];
  subtasks: SubTask[];
  onClose: () => void;
  onChat: (agent: Agent) => void;
  onAssignTask: (agentId: string) => void;
  onOpenTerminal?: (taskId: string) => void;
  onAgentUpdated?: () => void;
}

type Locale = "ko" | "en" | "ja" | "zh";
type TFunction = (messages: Record<Locale, string>) => string;

const LANGUAGE_STORAGE_KEY = "climpire.language";
const LOCALE_TAGS: Record<Locale, string> = {
  ko: "ko-KR",
  en: "en-US",
  ja: "ja-JP",
  zh: "zh-CN",
};

function normalizeLocale(value: string | null | undefined): Locale | null {
  const code = (value ?? "").toLowerCase();
  if (code.startsWith("ko")) return "ko";
  if (code.startsWith("en")) return "en";
  if (code.startsWith("ja")) return "ja";
  if (code.startsWith("zh")) return "zh";
  return null;
}

function detectLocale(): Locale {
  if (typeof window === "undefined") return "en";
  return (
    normalizeLocale(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)) ??
    normalizeLocale(window.navigator.language) ??
    "en"
  );
}

function useI18n(preferredLocale?: string) {
  const [locale, setLocale] = useState<Locale>(
    () => normalizeLocale(preferredLocale) ?? detectLocale()
  );

  useEffect(() => {
    const preferred = normalizeLocale(preferredLocale);
    if (preferred) setLocale(preferred);
  }, [preferredLocale]);

  useEffect(() => {
    if (typeof window === "undefined") return;
    const sync = () => {
      setLocale(normalizeLocale(preferredLocale) ?? detectLocale());
    };
    window.addEventListener("storage", sync);
    window.addEventListener("climpire-language-change", sync as EventListener);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener(
        "climpire-language-change",
        sync as EventListener
      );
    };
  }, [preferredLocale]);

  const t = useCallback(
    (messages: Record<Locale, string>) => messages[locale] ?? messages.en,
    [locale]
  );

  return { locale, localeTag: LOCALE_TAGS[locale], t };
}

function roleLabel(role: string, t: TFunction) {
  switch (role) {
    case "team_leader":
      return t({ ko: "팀장", en: "Team Leader", ja: "チームリーダー", zh: "组长" });
    case "senior":
      return t({ ko: "시니어", en: "Senior", ja: "シニア", zh: "高级" });
    case "junior":
      return t({ ko: "주니어", en: "Junior", ja: "ジュニア", zh: "初级" });
    case "intern":
      return t({ ko: "인턴", en: "Intern", ja: "インターン", zh: "实习生" });
    default:
      return role;
  }
}

const STATUS_CONFIG: Record<
  string,
  { label: string; color: string; bg: string }
> = {
  idle: { label: "idle", color: "text-green-400", bg: "bg-green-500/20" },
  working: { label: "working", color: "text-blue-400", bg: "bg-blue-500/20" },
  break: { label: "break", color: "text-yellow-400", bg: "bg-yellow-500/20" },
  offline: {
    label: "offline",
    color: "text-slate-400",
    bg: "bg-slate-500/20",
  },
};

const CLI_LABELS: Record<string, string> = {
  claude: "Claude Code",
  codex: "Codex CLI",
  gemini: "Gemini CLI",
  opencode: "OpenCode",
  copilot: "GitHub Copilot",
  antigravity: "Antigravity",
};

const SUBTASK_STATUS_ICON: Record<string, string> = {
  pending: '\u23F3',
  in_progress: '\uD83D\uDD28',
  done: '\u2705',
  blocked: '\uD83D\uDEAB',
};

function oauthAccountLabel(account: OAuthAccountInfo): string {
  return account.label || account.email || account.id.slice(0, 8);
}

function statusLabel(status: string, t: TFunction) {
  switch (status) {
    case "idle":
      return t({ ko: "대기중", en: "Idle", ja: "待機中", zh: "空闲" });
    case "working":
      return t({ ko: "근무중", en: "Working", ja: "作業中", zh: "工作中" });
    case "break":
      return t({ ko: "휴식중", en: "Break", ja: "休憩中", zh: "休息中" });
    case "offline":
      return t({ ko: "오프라인", en: "Offline", ja: "オフライン", zh: "离线" });
    default:
      return status;
  }
}

function taskStatusLabel(status: string, t: TFunction) {
  switch (status) {
    case "inbox":
      return t({ ko: "수신함", en: "Inbox", ja: "受信箱", zh: "收件箱" });
    case "planned":
      return t({ ko: "계획됨", en: "Planned", ja: "計画済み", zh: "已计划" });
    case "in_progress":
      return t({ ko: "진행 중", en: "In Progress", ja: "進行中", zh: "进行中" });
    case "review":
      return t({ ko: "검토", en: "Review", ja: "レビュー", zh: "审核" });
    case "done":
      return t({ ko: "완료", en: "Done", ja: "完了", zh: "完成" });
    case "pending":
      return t({ ko: "보류", en: "Pending", ja: "保留", zh: "待处理" });
    case "cancelled":
      return t({ ko: "취소", en: "Cancelled", ja: "キャンセル", zh: "已取消" });
    default:
      return status;
  }
}

function taskTypeLabel(type: string, t: TFunction) {
  switch (type) {
    case "general":
      return t({ ko: "일반", en: "General", ja: "一般", zh: "通用" });
    case "development":
      return t({ ko: "개발", en: "Development", ja: "開発", zh: "开发" });
    case "design":
      return t({ ko: "디자인", en: "Design", ja: "デザイン", zh: "设计" });
    case "analysis":
      return t({ ko: "분석", en: "Analysis", ja: "分析", zh: "分析" });
    case "presentation":
      return t({ ko: "발표", en: "Presentation", ja: "プレゼン", zh: "演示" });
    case "documentation":
      return t({ ko: "문서화", en: "Documentation", ja: "ドキュメント", zh: "文档" });
    default:
      return type;
  }
}

export default function AgentDetail({
  agent,
  agents,
  department,
  departments,
  tasks,
  subAgents,
  subtasks,
  onClose,
  onChat,
  onAssignTask,
  onOpenTerminal,
  onAgentUpdated,
}: AgentDetailProps) {
  const { t, locale } = useI18n();
  const [tab, setTab] = useState<"info" | "tasks" | "alba">("info");
  const [editingCli, setEditingCli] = useState(false);
  const [selectedCli, setSelectedCli] = useState(agent.cli_provider);
  const [selectedOAuthAccountId, setSelectedOAuthAccountId] = useState(agent.oauth_account_id ?? "");
  const [savingCli, setSavingCli] = useState(false);
  const [oauthStatus, setOauthStatus] = useState<OAuthStatus | null>(null);
  const [oauthLoading, setOauthLoading] = useState(false);
  const [expandedTaskId, setExpandedTaskId] = useState<string | null>(null);
  const agentTasks = tasks.filter((t) => t.assigned_agent_id === agent.id);

  const subtasksByTask = useMemo(() => {
    const map: Record<string, SubTask[]> = {};
    for (const st of subtasks) {
      if (!map[st.task_id]) map[st.task_id] = [];
      map[st.task_id].push(st);
    }
    return map;
  }, [subtasks]);
  const agentSubAgents = subAgents.filter(
    (s) => s.parentAgentId === agent.id
  );
  const statusCfg = STATUS_CONFIG[agent.status] ?? STATUS_CONFIG.idle;
  const doneTasks = agentTasks.filter((t) => t.status === "done").length;
  const oauthProviderKey =
    selectedCli === "copilot" ? "github-copilot" : selectedCli === "antigravity" ? "antigravity" : null;
  const activeOAuthAccounts = useMemo(() => {
    if (!oauthProviderKey || !oauthStatus) return [];
    return (oauthStatus.providers[oauthProviderKey]?.accounts ?? []).filter(
      (a) => a.active && a.status === "active",
    );
  }, [oauthProviderKey, oauthStatus]);
  const requiresOAuthAccount = selectedCli === "copilot" || selectedCli === "antigravity";
  const canSaveCli = !requiresOAuthAccount || Boolean(selectedOAuthAccountId);

  const xpLevel = Math.floor(agent.stats_xp / 100) + 1;
  const xpProgress = agent.stats_xp % 100;

  useEffect(() => {
    setSelectedCli(agent.cli_provider);
    setSelectedOAuthAccountId(agent.oauth_account_id ?? "");
  }, [agent.id, agent.cli_provider, agent.oauth_account_id]);

  useEffect(() => {
    if (!editingCli || !requiresOAuthAccount) return;
    setOauthLoading(true);
    api.getOAuthStatus()
      .then(setOauthStatus)
      .catch((err) => console.error("Failed to load OAuth status:", err))
      .finally(() => setOauthLoading(false));
  }, [editingCli, requiresOAuthAccount]);

  useEffect(() => {
    if (!requiresOAuthAccount) {
      if (selectedOAuthAccountId) setSelectedOAuthAccountId("");
      return;
    }
    if (activeOAuthAccounts.length === 0) return;
    if (!selectedOAuthAccountId || !activeOAuthAccounts.some((a) => a.id === selectedOAuthAccountId)) {
      setSelectedOAuthAccountId(activeOAuthAccounts[0].id);
    }
  }, [requiresOAuthAccount, activeOAuthAccounts, selectedOAuthAccountId]);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm">
      <div className="w-[calc(100vw-1.5rem)] max-w-[480px] max-h-[85vh] overflow-hidden rounded-2xl border border-slate-700 bg-slate-800 shadow-2xl">
        {/* Header */}
        <div
          className="relative px-6 py-5 border-b border-slate-700"
          style={{
            background: department
              ? `linear-gradient(135deg, ${department.color}22, transparent)`
              : undefined,
          }}
        >
          <button
            onClick={onClose}
            className="absolute top-3 right-3 w-8 h-8 rounded-full bg-slate-700/50 hover:bg-slate-600 flex items-center justify-center text-slate-400 hover:text-white transition-colors"
          >
            ✕
          </button>

          <div className="flex items-center gap-4">
            {/* Avatar */}
            <div className="relative">
              <AgentAvatar
                agent={agent}
                agents={agents}
                size={64}
                rounded="2xl"
                className={agent.status === "working" ? "animate-agent-work" : ""}
              />
              <div
                className={`absolute -bottom-1 -right-1 w-4 h-4 rounded-full border-2 border-slate-800 ${
                  agent.status === "working"
                    ? "bg-blue-500"
                    : agent.status === "idle"
                    ? "bg-green-500"
                    : agent.status === "break"
                    ? "bg-yellow-500"
                    : "bg-slate-500"
                }`}
              />
            </div>

            <div className="flex-1">
              <div className="flex items-center gap-2">
                <h2 className="text-lg font-bold text-white">
                  {locale === "ko" ? agent.name_ko ?? agent.name : agent.name ?? agent.name_ko}
                </h2>
                <span className={`text-xs px-1.5 py-0.5 rounded ${statusCfg.bg} ${statusCfg.color}`}>
                  {statusLabel(statusCfg.label, t)}
                </span>
              </div>
              <div className="text-sm text-slate-400 mt-0.5">
                {department?.icon} {department ? (locale === "ko" ? department.name_ko : department.name) : ""} ·{" "}
                {roleLabel(agent.role, t)}
              </div>
              <div className="text-xs text-slate-500 mt-0.5 flex items-center gap-1">
                {editingCli ? (
                  <>
                    <span>🔧</span>
                    <select
                      value={selectedCli}
                      onChange={(e) => setSelectedCli(e.target.value as Agent["cli_provider"])}
                      className="bg-slate-700 text-slate-200 text-xs rounded px-1.5 py-0.5 border border-slate-600 focus:outline-none focus:border-blue-500"
                    >
                      {Object.entries(CLI_LABELS).map(([key, label]) => (
                        <option key={key} value={key}>{label}</option>
                      ))}
                    </select>
                    {requiresOAuthAccount && (
                      oauthLoading ? (
                        <span className="text-[10px] text-slate-400">
                          {t({ ko: "계정 로딩...", en: "Loading accounts...", ja: "アカウント読み込み中...", zh: "正在加载账号..." })}
                        </span>
                      ) : activeOAuthAccounts.length > 0 ? (
                        <select
                          value={selectedOAuthAccountId}
                          onChange={(e) => setSelectedOAuthAccountId(e.target.value)}
                          className="bg-slate-700 text-slate-200 text-xs rounded px-1.5 py-0.5 border border-slate-600 focus:outline-none focus:border-blue-500 max-w-[170px]"
                        >
                          {activeOAuthAccounts.map((acc) => (
                            <option key={acc.id} value={acc.id}>
                              {oauthAccountLabel(acc)}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="text-[10px] text-amber-300">
                          {t({
                            ko: "활성 OAuth 계정 없음",
                            en: "No active OAuth account",
                            ja: "有効な OAuth アカウントなし",
                            zh: "没有可用的 OAuth 账号",
                          })}
                        </span>
                      )
                    )}
                    <button
                      disabled={savingCli || !canSaveCli}
                      onClick={async () => {
                        setSavingCli(true);
                        try {
                          await api.updateAgent(agent.id, {
                            cli_provider: selectedCli,
                            oauth_account_id: requiresOAuthAccount ? (selectedOAuthAccountId || null) : null,
                          });
                          onAgentUpdated?.();
                          setEditingCli(false);
                        } catch (e) {
                          console.error("Failed to update CLI:", e);
                        } finally {
                          setSavingCli(false);
                        }
                      }}
                      className="text-[10px] px-1.5 py-0.5 bg-blue-600 hover:bg-blue-500 text-white rounded transition-colors disabled:opacity-50"
                    >
                      {savingCli ? "..." : t({ ko: "저장", en: "Save", ja: "保存", zh: "保存" })}
                    </button>
                    <button
                      onClick={() => {
                        setEditingCli(false);
                        setSelectedCli(agent.cli_provider);
                        setSelectedOAuthAccountId(agent.oauth_account_id ?? "");
                      }}
                      className="text-[10px] px-1.5 py-0.5 bg-slate-600 hover:bg-slate-500 text-slate-300 rounded transition-colors"
                    >
                      {t({ ko: "취소", en: "Cancel", ja: "キャンセル", zh: "取消" })}
                    </button>
                  </>
                ) : (
                  <button
                    onClick={() => setEditingCli(true)}
                    className="flex items-center gap-1 hover:text-slate-300 transition-colors"
                    title={t({ ko: "클릭하여 CLI 변경", en: "Click to change CLI", ja: "クリックして CLI を変更", zh: "点击更改 CLI" })}
                  >
                    🔧 {CLI_LABELS[agent.cli_provider] ?? agent.cli_provider}
                    <span className="text-[9px] text-slate-600 ml-0.5">✏️</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {/* Level bar */}
          <div className="mt-3 flex items-center gap-2">
            <span className="text-xs text-yellow-400 font-bold">
              Lv.{xpLevel}
            </span>
            <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-yellow-500 to-amber-400 rounded-full transition-all"
                style={{ width: `${xpProgress}%` }}
              />
            </div>
            <span className="text-[10px] text-slate-500">
              {agent.stats_xp} XP
            </span>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-slate-700">
          {[
            { key: "info", label: t({ ko: "정보", en: "Info", ja: "情報", zh: "信息" }) },
            {
              key: "tasks",
              label: `${t({ ko: "업무", en: "Tasks", ja: "タスク", zh: "任务" })} (${agentTasks.length})`,
            },
            {
              key: "alba",
              label: `${t({ ko: "알바생", en: "Sub-agents", ja: "サブエージェント", zh: "子代理" })} (${agentSubAgents.length})`,
            },
          ].map((tabItem) => (
            <button
              key={tabItem.key}
              onClick={() => setTab(tabItem.key as typeof tab)}
              className={`flex-1 py-2.5 text-sm font-medium transition-colors ${
                tab === tabItem.key
                  ? "text-blue-400 border-b-2 border-blue-400"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              {tabItem.label}
            </button>
          ))}
        </div>

        {/* Content */}
        <div className="p-4 overflow-y-auto max-h-[40vh]">
          {tab === "info" && (
            <div className="space-y-3">
              <div className="bg-slate-700/30 rounded-lg p-3">
                <div className="text-xs text-slate-500 mb-1">
                  {t({ ko: "성격", en: "Personality", ja: "性格", zh: "性格" })}
                </div>
                <div className="text-sm text-slate-300">
                  {agent.personality ??
                    t({ ko: "설정 없음", en: "Not set", ja: "未設定", zh: "未设置" })}
                </div>
              </div>

              <div className="grid grid-cols-3 gap-2">
                <div className="bg-slate-700/30 rounded-lg p-3 text-center">
                  <div className="text-lg font-bold text-white">
                    {agent.stats_tasks_done}
                  </div>
                  <div className="text-[10px] text-slate-500">
                    {t({ ko: "완료 업무", en: "Completed", ja: "完了タスク", zh: "已完成任务" })}
                  </div>
                </div>
                <div className="bg-slate-700/30 rounded-lg p-3 text-center">
                  <div className="text-lg font-bold text-white">{xpLevel}</div>
                  <div className="text-[10px] text-slate-500">{t({ ko: "레벨", en: "Level", ja: "レベル", zh: "等级" })}</div>
                </div>
                <div className="bg-slate-700/30 rounded-lg p-3 text-center">
                  <div className="text-lg font-bold text-white">
                    {agentSubAgents.filter((s) => s.status === "working").length}
                  </div>
                  <div className="text-[10px] text-slate-500">
                    {t({ ko: "알바생", en: "Sub-agents", ja: "サブエージェント", zh: "子代理" })}
                  </div>
                </div>
              </div>

              <div className="flex gap-2 pt-2">
                <button
                  onClick={() => onChat(agent)}
                  className="flex-1 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
                >
                  💬 {t({ ko: "대화하기", en: "Chat", ja: "チャット", zh: "对话" })}
                </button>
                <button
                  onClick={() => onAssignTask(agent.id)}
                  className="flex-1 py-2 rounded-lg bg-purple-600 hover:bg-purple-500 text-white text-sm font-medium transition-colors"
                >
                  📋 {t({ ko: "업무 배정", en: "Assign Task", ja: "タスク割り当て", zh: "分配任务" })}
                </button>
              </div>
              {agent.status === "working" && agent.current_task_id && onOpenTerminal && (
                <button
                  onClick={() => onOpenTerminal(agent.current_task_id!)}
                  className="w-full mt-2 py-2 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-200 text-sm font-medium transition-colors flex items-center justify-center gap-1.5"
                >
                  &#128421; {t({ ko: "터미널 보기", en: "View Terminal", ja: "ターミナル表示", zh: "查看终端" })}
                </button>
              )}
            </div>
          )}

          {tab === "tasks" && (
            <div className="space-y-2">
              {agentTasks.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-sm">
                  {t({ ko: "배정된 업무가 없습니다", en: "No assigned tasks", ja: "割り当てられたタスクはありません", zh: "暂无已分配任务" })}
                </div>
              ) : (
                agentTasks.map((taskItem) => {
                  const tSubs = subtasksByTask[taskItem.id] ?? [];
                  const isExpanded = expandedTaskId === taskItem.id;
                  const subTotal = taskItem.subtask_total ?? tSubs.length;
                  const subDone = taskItem.subtask_done ?? tSubs.filter((s) => s.status === "done").length;
                  return (
                    <div key={taskItem.id} className="bg-slate-700/30 rounded-lg p-3">
                      <button
                        onClick={() => setExpandedTaskId(isExpanded ? null : taskItem.id)}
                        className="flex items-start gap-3 w-full text-left"
                      >
                        <div
                          className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
                            taskItem.status === "done"
                              ? "bg-green-500"
                              : taskItem.status === "in_progress"
                              ? "bg-blue-500"
                              : "bg-slate-500"
                          }`}
                        />
                        <div className="flex-1 min-w-0">
                          <div className="text-sm text-white truncate">
                            {taskItem.title}
                          </div>
                          <div className="text-xs text-slate-500 mt-0.5">
                            {taskStatusLabel(taskItem.status, t)} · {taskTypeLabel(taskItem.task_type, t)}
                          </div>
                          {subTotal > 0 && (
                            <div className="flex items-center gap-2 mt-1.5">
                              <div className="flex-1 h-1 bg-slate-600 rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-gradient-to-r from-green-500 to-emerald-400 rounded-full transition-all"
                                  style={{ width: `${Math.round((subDone / subTotal) * 100)}%` }}
                                />
                              </div>
                              <span className="text-[10px] text-slate-400 whitespace-nowrap">
                                {subDone}/{subTotal}
                              </span>
                            </div>
                          )}
                        </div>
                      </button>
                      {isExpanded && tSubs.length > 0 && (
                        <div className="mt-2 ml-5 space-y-1 border-l border-slate-600 pl-2">
                          {tSubs.map((st) => {
                            const targetDept = st.target_department_id
                              ? departments.find(d => d.id === st.target_department_id)
                              : null;
                            return (
                              <div key={st.id} className="flex items-center gap-1.5 text-xs">
                                <span>{SUBTASK_STATUS_ICON[st.status] || '\u23F3'}</span>
                                <span className={`flex-1 truncate ${st.status === 'done' ? 'line-through text-slate-500' : 'text-slate-300'}`}>
                                  {st.title}
                                </span>
                                {targetDept && (
                                  <span
                                    className="shrink-0 rounded px-1 py-0.5 text-[10px] font-medium"
                                    style={{ backgroundColor: targetDept.color + '30', color: targetDept.color }}
                                  >
                                    {targetDept.icon} {locale === "ko" ? targetDept.name_ko : targetDept.name}
                                  </span>
                                )}
                                {st.delegated_task_id && st.status !== 'done' && (
                                  <span
                                    className="text-blue-400 shrink-0"
                                    title={t({ ko: "위임됨", en: "Delegated", ja: "委任済み", zh: "已委派" })}
                                  >
                                    🔗
                                  </span>
                                )}
                                {st.status === 'blocked' && st.blocked_reason && (
                                  <span className="text-red-400 text-[10px] truncate max-w-[80px]" title={st.blocked_reason}>
                                    {st.blocked_reason}
                                  </span>
                                )}
                              </div>
                            );
                          })}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
            </div>
          )}

          {tab === "alba" && (
            <div className="space-y-2">
              {agentSubAgents.length === 0 ? (
                <div className="text-center py-8 text-slate-500 text-sm">
                  <div className="text-3xl mb-2">🧑‍💼</div>
                  {t({ ko: "현재 알바생이 없습니다", en: "No sub-agents currently", ja: "現在サブエージェントはいません", zh: "当前没有子代理" })}
                  <div className="text-xs mt-1 text-slate-600">
                    {t({
                      ko: "병렬 처리 시 자동으로 알바생이 소환됩니다",
                      en: "Sub-agents are spawned automatically during parallel work.",
                      ja: "並列処理時にサブエージェントが自動で生成されます。",
                      zh: "并行处理时会自动生成子代理。",
                    })}
                  </div>
                </div>
              ) : (
                agentSubAgents.map((s) => (
                  <div
                    key={s.id}
                    className={`bg-slate-700/30 rounded-lg p-3 flex items-center gap-3 ${
                      s.status === "working" ? "animate-alba-spawn" : ""
                    }`}
                  >
                    <div className="w-8 h-8 rounded-full bg-amber-500/20 flex items-center justify-center text-sm">
                      🧑‍💼
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="text-sm text-white truncate flex items-center gap-1.5">
                        <span className="text-[10px] px-1 py-0.5 rounded bg-amber-500/20 text-amber-400">
                          {t({ ko: "알바", en: "Sub", ja: "サブ", zh: "子任务" })}
                        </span>
                        {s.task}
                      </div>
                      <div className="text-xs text-slate-500 mt-0.5">
                        {s.status === "working"
                          ? `🔨 ${t({ ko: "작업중...", en: "Working...", ja: "作業中...", zh: "工作中..." })}`
                          : `✅ ${t({ ko: "완료", en: "Done", ja: "完了", zh: "完成" })}`}
                      </div>
                    </div>
                    {s.status === "working" && (
                      <div className="w-4 h-4 border-2 border-blue-400 border-t-transparent rounded-full animate-spin" />
                    )}
                  </div>
                ))
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
