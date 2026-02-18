import { useEffect, useState, useCallback, useRef } from "react";
import Sidebar from "./components/Sidebar";
import OfficeView from "./components/OfficeView";
import { ChatPanel } from "./components/ChatPanel";
import Dashboard from "./components/Dashboard";
import TaskBoard from "./components/TaskBoard";
import AgentDetail from "./components/AgentDetail";
import SettingsPanel from "./components/SettingsPanel";
import TerminalPanel from "./components/TerminalPanel";
import SkillsLibrary from "./components/SkillsLibrary";
import { useWebSocket } from "./hooks/useWebSocket";
import type {
  Department,
  Agent,
  Task,
  Message,
  CompanyStats,
  CompanySettings,
  CliStatusMap,
  SubTask,
} from "./types";
import { DEFAULT_SETTINGS } from "./types";
import {
  detectBrowserLanguage,
  I18nProvider,
  LANGUAGE_STORAGE_KEY,
  LANGUAGE_USER_SET_STORAGE_KEY,
  normalizeLanguage,
  pickLang,
} from "./i18n";
import * as api from "./api";

interface SubAgent {
  id: string;
  parentAgentId: string;
  task: string;
  status: "working" | "done";
}

export interface CrossDeptDelivery {
  id: string;
  fromAgentId: string;
  toAgentId: string;
}

export interface CeoOfficeCall {
  id: string;
  fromAgentId: string;
  seatIndex: number;
  phase: "kickoff" | "review";
  action?: "arrive" | "speak";
  line?: string;
}

type View = "office" | "dashboard" | "tasks" | "skills" | "settings";
type TaskPanelTab = "terminal" | "minutes";

export interface OAuthCallbackResult {
  provider: string | null;
  error: string | null;
}

function mergeSettingsWithDefaults(
  settings?: Partial<CompanySettings> | null
): CompanySettings {
  return {
    ...DEFAULT_SETTINGS,
    ...(settings ?? {}),
    language: normalizeLanguage(settings?.language ?? DEFAULT_SETTINGS.language),
    providerModelConfig: {
      ...(DEFAULT_SETTINGS.providerModelConfig ?? {}),
      ...(settings?.providerModelConfig ?? {}),
    },
  };
}

function isUserLanguagePinned(): boolean {
  if (typeof window === "undefined") return false;
  return window.localStorage.getItem(LANGUAGE_USER_SET_STORAGE_KEY) === "1";
}

function syncClientLanguage(language: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(LANGUAGE_STORAGE_KEY, normalizeLanguage(language));
  window.dispatchEvent(new Event("climpire-language-change"));
}

export default function App() {
  // Core state
  const [view, setView] = useState<View>("office");
  const [departments, setDepartments] = useState<Department[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [stats, setStats] = useState<CompanyStats | null>(null);
  const [settings, setSettings] = useState<CompanySettings>(() =>
    mergeSettingsWithDefaults({ language: detectBrowserLanguage() })
  );
  const [cliStatus, setCliStatus] = useState<CliStatusMap | null>(null);
  const [subAgents, setSubAgents] = useState<SubAgent[]>([]);
  const [subtasks, setSubtasks] = useState<SubTask[]>([]);

  // UI state
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [chatAgent, setChatAgent] = useState<Agent | null>(null);
  const [showChat, setShowChat] = useState(false);
  const [taskPanel, setTaskPanel] = useState<{ taskId: string; tab: TaskPanelTab } | null>(null);
  const [loading, setLoading] = useState(true);
  const [unreadAgentIds, setUnreadAgentIds] = useState<Set<string>>(new Set());
  const [crossDeptDeliveries, setCrossDeptDeliveries] = useState<CrossDeptDelivery[]>([]);
  const [ceoOfficeCalls, setCeoOfficeCalls] = useState<CeoOfficeCall[]>([]);
  const [oauthResult, setOauthResult] = useState<OAuthCallbackResult | null>(null);

  // Ref to track currently open chat (avoids stale closures in WebSocket handlers)
  const activeChatRef = useRef<{ showChat: boolean; agentId: string | null }>({ showChat: false, agentId: null });
  activeChatRef.current = { showChat, agentId: chatAgent?.id ?? null };

  // OAuth callback detection
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const oauthProvider = params.get("oauth");
    const oauthError = params.get("oauth_error");
    if (oauthProvider || oauthError) {
      setOauthResult({
        provider: oauthProvider,
        error: oauthError,
      });
      // Clean URL
      const clean = new URL(window.location.href);
      clean.searchParams.delete("oauth");
      clean.searchParams.delete("oauth_error");
      window.history.replaceState({}, "", clean.pathname + clean.search);
      // Switch to settings view
      setView("settings");
    }
  }, []);

  // WebSocket
  const { connected, on } = useWebSocket();

  // Initial data fetch
  const fetchAll = useCallback(async () => {
    try {
      const [depts, ags, tks, sts, sett, subs] = await Promise.all([
        api.getDepartments(),
        api.getAgents(),
        api.getTasks(),
        api.getStats(),
        api.getSettings(),
        api.getActiveSubtasks(),
      ]);
      setDepartments(depts);
      setAgents(ags);
      setTasks(tks);
      setStats(sts);
      const mergedSettings = mergeSettingsWithDefaults(sett);
      const autoDetectedLanguage = detectBrowserLanguage();
      const shouldAutoAssignLanguage = !isUserLanguagePinned();
      const nextSettings = shouldAutoAssignLanguage
        ? { ...mergedSettings, language: autoDetectedLanguage }
        : mergedSettings;

      setSettings(nextSettings);
      syncClientLanguage(nextSettings.language);

      if (
        shouldAutoAssignLanguage &&
        mergedSettings.language !== autoDetectedLanguage
      ) {
        api.saveSettings(nextSettings).catch((error) => {
          console.error("Auto language sync failed:", error);
        });
      }
      setSubtasks(subs);
    } catch (e) {
      console.error("Failed to fetch data:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
  }, [fetchAll]);

  // Fetch CLI status on settings view
  useEffect(() => {
    if (view === "settings" && !cliStatus) {
      api.getCliStatus(true).then(setCliStatus).catch(console.error);
    }
  }, [view, cliStatus]);

  // WebSocket event handlers
  useEffect(() => {
    const unsubs = [
      on("task_update", () => {
        api.getTasks().then(setTasks).catch(console.error);
        api.getAgents().then(setAgents).catch(console.error);
        api.getStats().then(setStats).catch(console.error);
      }),
      on("agent_status", (payload: unknown) => {
        const p = payload as Agent & { subAgents?: SubAgent[] };
        setAgents((prev) =>
          prev.map((a) =>
            a.id === p.id ? { ...a, ...p } : a
          )
        );
        if (p.subAgents) {
          setSubAgents((prev) => {
            const others = prev.filter((s) => s.parentAgentId !== p.id);
            return [...others, ...p.subAgents!];
          });
        }
      }),
      on("new_message", (payload: unknown) => {
        const msg = payload as Message;
        setMessages((prev) =>
          prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]
        );
        // Track unread: if an agent sent a message, mark as unread
        // BUT skip if the chat panel is currently open for this agent
        if (msg.sender_type === 'agent' && msg.sender_id) {
          const { showChat: chatOpen, agentId: activeId } = activeChatRef.current;
          if (chatOpen && activeId === msg.sender_id) return; // already reading
          setUnreadAgentIds((prev) => {
            if (prev.has(msg.sender_id!)) return prev;
            const next = new Set(prev);
            next.add(msg.sender_id!);
            return next;
          });
        }
      }),
      on("announcement", (payload: unknown) => {
        const msg = payload as Message;
        setMessages((prev) =>
          prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]
        );
        if (msg.sender_type === 'agent' && msg.sender_id) {
          const { showChat: chatOpen, agentId: activeId } = activeChatRef.current;
          if (chatOpen && activeId === msg.sender_id) return; // already reading
          setUnreadAgentIds((prev) => {
            if (prev.has(msg.sender_id!)) return prev;
            const next = new Set(prev);
            next.add(msg.sender_id!);
            return next;
          });
        }
      }),
      on("cross_dept_delivery", (payload: unknown) => {
        const p = payload as { from_agent_id: string; to_agent_id: string };
        setCrossDeptDeliveries((prev) => [
          ...prev,
          { id: `cd-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`, fromAgentId: p.from_agent_id, toAgentId: p.to_agent_id },
        ]);
      }),
      on("ceo_office_call", (payload: unknown) => {
        const p = payload as {
          from_agent_id: string;
          seat_index?: number;
          phase?: "kickoff" | "review";
          action?: "arrive" | "speak";
          line?: string;
        };
        if (!p.from_agent_id) return;
        setCeoOfficeCalls((prev) => [
          ...prev,
          {
            id: `ceo-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
            fromAgentId: p.from_agent_id,
            seatIndex: p.seat_index ?? 0,
            phase: p.phase ?? "kickoff",
            action: p.action ?? "arrive",
            line: p.line,
          },
        ]);
      }),
      on("subtask_update", (payload: unknown) => {
        const st = payload as SubTask;
        setSubtasks((prev) => {
          const idx = prev.findIndex((s) => s.id === st.id);
          if (idx >= 0) {
            const next = [...prev];
            next[idx] = st;
            return next;
          }
          return [...prev, st];
        });
        // Also refresh tasks to update subtask_total/subtask_done counts
        api.getTasks().then(setTasks).catch(console.error);
      }),
      on("cli_output", (payload: unknown) => {
        const p = payload as { task_id: string; stream: string; data: string };
        // Parse stream-json for sub-agent (Task tool) spawns from Claude Code
        try {
          const lines = p.data.split("\n").filter(Boolean);
          for (const line of lines) {
            const json = JSON.parse(line);
            // Detect Claude Code sub-agent spawn events
            if (json.type === "tool_use" && json.tool === "Task") {
              const parentAgent = agents.find(
                (a) => a.current_task_id === p.task_id
              );
              if (parentAgent) {
                const subId = json.id || `sub-${Date.now()}`;
                setSubAgents((prev) => {
                  if (prev.some((s) => s.id === subId)) return prev;
                  return [
                    ...prev,
                    {
                      id: subId,
                      parentAgentId: parentAgent.id,
                      task: json.input?.prompt?.slice(0, 100) || "Sub-task",
                      status: "working" as const,
                    },
                  ];
                });
              }
            }
            // Detect sub-agent completion
            if (json.type === "tool_result" && json.tool === "Task") {
              setSubAgents((prev) =>
                prev.map((s) =>
                  s.id === json.id ? { ...s, status: "done" as const } : s
                )
              );
            }
          }
        } catch {
          // Not JSON or not parseable - ignore
        }
      }),
    ];
    return () => unsubs.forEach((fn) => fn());
  }, [on]);

  // Polling for fresh data every 5 seconds
  useEffect(() => {
    const timer = setInterval(() => {
      api.getAgents().then(setAgents).catch(console.error);
      api.getTasks().then(setTasks).catch(console.error);
    }, 5000);
    return () => clearInterval(timer);
  }, []);

  // Handlers
  async function handleSendMessage(
    content: string,
    receiverType: "agent" | "department" | "all",
    receiverId?: string,
    messageType?: string
  ) {
    try {
      await api.sendMessage({
        receiver_type: receiverType,
        receiver_id: receiverId,
        content,
        message_type: (messageType as "chat" | "task_assign" | "report") || "chat",
      });
      // Refresh messages
      const msgs = await api.getMessages({
        receiver_type: receiverType,
        receiver_id: receiverId,
        limit: 50,
      });
      setMessages(msgs);
    } catch (e) {
      console.error("Send message failed:", e);
    }
  }

  async function handleSendAnnouncement(content: string) {
    try {
      await api.sendAnnouncement(content);
    } catch (e) {
      console.error("Announcement failed:", e);
    }
  }

  async function handleCreateTask(input: {
    title: string;
    description?: string;
    department_id?: string;
    task_type?: string;
    priority?: number;
  }) {
    try {
      await api.createTask(input as Parameters<typeof api.createTask>[0]);
      const tks = await api.getTasks();
      setTasks(tks);
      const sts = await api.getStats();
      setStats(sts);
    } catch (e) {
      console.error("Create task failed:", e);
    }
  }

  async function handleUpdateTask(id: string, data: Partial<Task>) {
    try {
      await api.updateTask(id, data);
      const tks = await api.getTasks();
      setTasks(tks);
    } catch (e) {
      console.error("Update task failed:", e);
    }
  }

  async function handleDeleteTask(id: string) {
    try {
      await api.deleteTask(id);
      setTasks((prev) => prev.filter((t) => t.id !== id));
    } catch (e) {
      console.error("Delete task failed:", e);
    }
  }

  async function handleAssignTask(taskId: string, agentId: string) {
    try {
      await api.assignTask(taskId, agentId);
      const [tks, ags] = await Promise.all([api.getTasks(), api.getAgents()]);
      setTasks(tks);
      setAgents(ags);
    } catch (e) {
      console.error("Assign task failed:", e);
    }
  }

  async function handleRunTask(id: string) {
    try {
      await api.runTask(id);
      const [tks, ags] = await Promise.all([api.getTasks(), api.getAgents()]);
      setTasks(tks);
      setAgents(ags);
    } catch (e) {
      console.error("Run task failed:", e);
    }
  }

  async function handleStopTask(id: string) {
    try {
      await api.stopTask(id);
      const [tks, ags] = await Promise.all([api.getTasks(), api.getAgents()]);
      setTasks(tks);
      setAgents(ags);
    } catch (e) {
      console.error("Stop task failed:", e);
    }
  }

  async function handlePauseTask(id: string) {
    try {
      await api.pauseTask(id);
      const [tks, ags] = await Promise.all([api.getTasks(), api.getAgents()]);
      setTasks(tks);
      setAgents(ags);
    } catch (e) {
      console.error("Pause task failed:", e);
    }
  }

  async function handleResumeTask(id: string) {
    try {
      await api.resumeTask(id);
      const [tks, ags] = await Promise.all([api.getTasks(), api.getAgents()]);
      setTasks(tks);
      setAgents(ags);
    } catch (e) {
      console.error("Resume task failed:", e);
    }
  }

  async function handleSaveSettings(s: CompanySettings) {
    try {
      const nextSettings = mergeSettingsWithDefaults(s);
      await api.saveSettings(nextSettings);
      setSettings(nextSettings);
      if (typeof window !== "undefined") {
        window.localStorage.setItem(LANGUAGE_USER_SET_STORAGE_KEY, "1");
      }
      syncClientLanguage(nextSettings.language);
    } catch (e) {
      console.error("Save settings failed:", e);
    }
  }

  function handleOpenChat(agent: Agent) {
    setChatAgent(agent);
    setShowChat(true);
    // Clear unread for this agent
    setUnreadAgentIds((prev) => {
      if (!prev.has(agent.id)) return prev;
      const next = new Set(prev);
      next.delete(agent.id);
      return next;
    });
    // Fetch messages for this agent
    api
      .getMessages({ receiver_type: "agent", receiver_id: agent.id, limit: 50 })
      .then(setMessages)
      .catch(console.error);
  }

  const uiLanguage = normalizeLanguage(settings.language);
  const loadingTitle = pickLang(uiLanguage, {
    ko: "CLImpire 로딩 중...",
    en: "Loading CLImpire...",
    ja: "CLImpireを読み込み中...",
    zh: "CLImpire 加载中...",
  });
  const loadingSubtitle = pickLang(uiLanguage, {
    ko: "AI 에이전트 제국을 준비하고 있습니다",
    en: "Preparing your AI agent empire",
    ja: "AIエージェント帝国を準備しています",
    zh: "正在准备你的 AI 代理帝国",
  });
  const viewTitle = (() => {
    switch (view) {
      case "office":
        return `🏢 ${pickLang(uiLanguage, {
          ko: "오피스",
          en: "Office",
          ja: "オフィス",
          zh: "办公室",
        })}`;
      case "dashboard":
        return `📊 ${pickLang(uiLanguage, {
          ko: "대시보드",
          en: "Dashboard",
          ja: "ダッシュボード",
          zh: "仪表盘",
        })}`;
      case "tasks":
        return `📋 ${pickLang(uiLanguage, {
          ko: "업무 관리",
          en: "Tasks",
          ja: "タスク管理",
          zh: "任务管理",
        })}`;
      case "skills":
        return `📚 ${pickLang(uiLanguage, {
          ko: "문서고",
          en: "Skills",
          ja: "スキル資料室",
          zh: "技能库",
        })}`;
      case "settings":
        return `⚙️ ${pickLang(uiLanguage, {
          ko: "설정",
          en: "Settings",
          ja: "設定",
          zh: "设置",
        })}`;
      default:
        return "";
    }
  })();
  const announcementLabel = `📢 ${pickLang(uiLanguage, {
    ko: "전사 공지",
    en: "Announcement",
    ja: "全社告知",
    zh: "全员公告",
  })}`;

  if (loading) {
    return (
      <I18nProvider language={uiLanguage}>
        <div className="h-screen flex items-center justify-center bg-slate-900">
          <div className="text-center">
            <div className="text-5xl mb-4 animate-agent-bounce">🏢</div>
            <div className="text-lg text-slate-400 font-medium">
              {loadingTitle}
            </div>
            <div className="text-sm text-slate-500 mt-1">
              {loadingSubtitle}
            </div>
          </div>
        </div>
      </I18nProvider>
    );
  }

  return (
    <I18nProvider language={uiLanguage}>
      <div className="h-screen flex overflow-hidden bg-slate-900">
        {/* Sidebar */}
        <Sidebar
          currentView={view}
          onChangeView={setView}
          departments={departments}
          agents={agents}
          settings={settings}
          connected={connected}
        />

        {/* Main Content */}
        <main className="flex-1 overflow-y-auto overflow-x-hidden min-w-0">
          {/* Top Bar */}
          <header className="sticky top-0 z-30 bg-slate-900/80 backdrop-blur-sm border-b border-slate-700/50 px-6 py-3 flex items-center justify-between">
            <div>
              <h1 className="text-lg font-bold text-white">{viewTitle}</h1>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => {
                  setChatAgent(null);
                  setShowChat(true);
                  api
                    .getMessages({ receiver_type: "all", limit: 50 })
                    .then(setMessages)
                    .catch(console.error);
                }}
                className="px-3 py-1.5 text-sm bg-amber-600/20 text-amber-400 border border-amber-500/30 rounded-lg hover:bg-amber-600/30 transition-colors"
              >
                {announcementLabel}
              </button>
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <div
                  className={`w-2 h-2 rounded-full ${
                    connected ? "bg-green-500" : "bg-red-500"
                  }`}
                />
                {connected ? "Live" : "Offline"}
              </div>
            </div>
          </header>

          {/* Views */}
          <div className="p-6">
            {view === "office" && (
              <OfficeView
                departments={departments}
                agents={agents}
                tasks={tasks}
                subAgents={subAgents}
                unreadAgentIds={unreadAgentIds}
                crossDeptDeliveries={crossDeptDeliveries}
                onCrossDeptDeliveryProcessed={(id) =>
                  setCrossDeptDeliveries((prev) => prev.filter((d) => d.id !== id))
                }
                ceoOfficeCalls={ceoOfficeCalls}
                onCeoOfficeCallProcessed={(id) =>
                  setCeoOfficeCalls((prev) => prev.filter((d) => d.id !== id))
                }
                onSelectAgent={(a) => setSelectedAgent(a)}
                onSelectDepartment={(dept) => {
                  const leader = agents.find(
                    (a) => a.department_id === dept.id && a.role === "team_leader"
                  );
                  if (leader) {
                    handleOpenChat(leader);
                  }
                }}
              />
            )}

            {view === "dashboard" && (
              <Dashboard
                stats={stats}
                agents={agents}
                tasks={tasks}
                companyName={settings.companyName}
              />
            )}

            {view === "tasks" && (
              <TaskBoard
                tasks={tasks}
                agents={agents}
                departments={departments}
                subtasks={subtasks}
                onCreateTask={handleCreateTask}
                onUpdateTask={handleUpdateTask}
                onDeleteTask={handleDeleteTask}
                onAssignTask={handleAssignTask}
                onRunTask={handleRunTask}
                onStopTask={handleStopTask}
                onPauseTask={handlePauseTask}
                onResumeTask={handleResumeTask}
                onOpenTerminal={(id) => setTaskPanel({ taskId: id, tab: "terminal" })}
                onOpenMeetingMinutes={(id) => setTaskPanel({ taskId: id, tab: "minutes" })}
              />
            )}

            {view === "skills" && <SkillsLibrary />}

            {view === "settings" && (
              <SettingsPanel
                settings={settings}
                cliStatus={cliStatus}
                onSave={handleSaveSettings}
                onRefreshCli={() =>
                  api.getCliStatus(true).then(setCliStatus).catch(console.error)
                }
                oauthResult={oauthResult}
                onOauthResultClear={() => setOauthResult(null)}
              />
            )}
          </div>
        </main>

        {/* Chat Panel (slide-in) */}
        {showChat && (
          <ChatPanel
            selectedAgent={chatAgent}
            messages={messages}
            agents={agents}
            onSendMessage={handleSendMessage}
            onSendAnnouncement={handleSendAnnouncement}
            onClearMessages={async (agentId) => {
              try {
                await api.clearMessages(agentId);
                setMessages([]);
              } catch (e) {
                console.error("Clear messages failed:", e);
              }
            }}
            onClose={() => setShowChat(false)}
          />
        )}

        {/* Agent Detail Modal */}
        {selectedAgent && (
          <AgentDetail
            agent={selectedAgent}
            agents={agents}
            department={departments.find(
              (d) => d.id === selectedAgent.department_id
            )}
            departments={departments}
            tasks={tasks}
            subAgents={subAgents}
            subtasks={subtasks}
            onClose={() => setSelectedAgent(null)}
            onChat={(a) => {
              setSelectedAgent(null);
              handleOpenChat(a);
            }}
            onAssignTask={() => {
              setSelectedAgent(null);
              setView("tasks");
            }}
            onOpenTerminal={(id) => {
              setSelectedAgent(null);
              setTaskPanel({ taskId: id, tab: "terminal" });
            }}
            onAgentUpdated={() => {
              api.getAgents().then((ags) => {
                setAgents(ags);
                // Refresh selected agent with updated data
                if (selectedAgent) {
                  const updated = ags.find(a => a.id === selectedAgent.id);
                  if (updated) setSelectedAgent(updated);
                }
              }).catch(console.error);
            }}
          />
        )}

        {/* Terminal Panel (slide-in from right) */}
        {taskPanel && (
          <TerminalPanel
            taskId={taskPanel.taskId}
            initialTab={taskPanel.tab}
            task={tasks.find((t) => t.id === taskPanel.taskId)}
            agent={agents.find(
              (a) =>
                a.current_task_id === taskPanel.taskId ||
                tasks.find((t) => t.id === taskPanel.taskId)?.assigned_agent_id === a.id
            )}
            agents={agents}
            onClose={() => setTaskPanel(null)}
          />
        )}
      </div>
    </I18nProvider>
  );
}
