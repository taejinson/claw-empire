import { useEffect, useState, useCallback } from "react";
import Sidebar from "./components/Sidebar";
import OfficeView from "./components/OfficeView";
import { ChatPanel } from "./components/ChatPanel";
import Dashboard from "./components/Dashboard";
import TaskBoard from "./components/TaskBoard";
import AgentDetail from "./components/AgentDetail";
import SettingsPanel from "./components/SettingsPanel";
import { useWebSocket } from "./hooks/useWebSocket";
import type {
  Department,
  Agent,
  Task,
  Message,
  CompanyStats,
  CompanySettings,
  CliStatusMap,
} from "./types";
import { DEFAULT_SETTINGS } from "./types";
import * as api from "./api";

interface SubAgent {
  id: string;
  parentAgentId: string;
  task: string;
  status: "working" | "done";
}

type View = "office" | "dashboard" | "tasks" | "settings";

export default function App() {
  // Core state
  const [view, setView] = useState<View>("office");
  const [departments, setDepartments] = useState<Department[]>([]);
  const [agents, setAgents] = useState<Agent[]>([]);
  const [tasks, setTasks] = useState<Task[]>([]);
  const [messages, setMessages] = useState<Message[]>([]);
  const [stats, setStats] = useState<CompanyStats | null>(null);
  const [settings, setSettings] = useState<CompanySettings>(DEFAULT_SETTINGS);
  const [cliStatus, setCliStatus] = useState<CliStatusMap | null>(null);
  const [subAgents, setSubAgents] = useState<SubAgent[]>([]);

  // UI state
  const [selectedAgent, setSelectedAgent] = useState<Agent | null>(null);
  const [chatAgent, setChatAgent] = useState<Agent | null>(null);
  const [showChat, setShowChat] = useState(false);
  const [loading, setLoading] = useState(true);

  // WebSocket
  const { connected, on } = useWebSocket();

  // Initial data fetch
  const fetchAll = useCallback(async () => {
    try {
      const [depts, ags, tks, sts, sett] = await Promise.all([
        api.getDepartments(),
        api.getAgents(),
        api.getTasks(),
        api.getStats(),
        api.getSettings(),
      ]);
      setDepartments(depts);
      setAgents(ags);
      setTasks(tks);
      setStats(sts);
      setSettings(sett);
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
      }),
      on("announcement", (payload: unknown) => {
        const msg = payload as Message;
        setMessages((prev) =>
          prev.some((m) => m.id === msg.id) ? prev : [...prev, msg]
        );
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

  async function handleSaveSettings(s: CompanySettings) {
    try {
      await api.saveSettings(s);
      setSettings(s);
    } catch (e) {
      console.error("Save settings failed:", e);
    }
  }

  function handleOpenChat(agent: Agent) {
    setChatAgent(agent);
    setShowChat(true);
    // Fetch messages for this agent
    api
      .getMessages({ receiver_type: "agent", receiver_id: agent.id, limit: 50 })
      .then(setMessages)
      .catch(console.error);
  }

  if (loading) {
    return (
      <div className="h-screen flex items-center justify-center bg-slate-900">
        <div className="text-center">
          <div className="text-5xl mb-4 animate-agent-bounce">🏢</div>
          <div className="text-lg text-slate-400 font-medium">
            CLImpire 로딩 중...
          </div>
          <div className="text-sm text-slate-500 mt-1">
            AI 에이전트 제국을 준비하고 있습니다
          </div>
        </div>
      </div>
    );
  }

  return (
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
      <main className="flex-1 overflow-y-auto">
        {/* Top Bar */}
        <header className="sticky top-0 z-30 bg-slate-900/80 backdrop-blur-sm border-b border-slate-700/50 px-6 py-3 flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-white">
              {view === "office" && "🏢 오피스"}
              {view === "dashboard" && "📊 대시보드"}
              {view === "tasks" && "📋 업무 관리"}
              {view === "settings" && "⚙️ 설정"}
            </h1>
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
              📢 전사 공지
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
              onCreateTask={handleCreateTask}
              onUpdateTask={handleUpdateTask}
              onDeleteTask={handleDeleteTask}
              onAssignTask={handleAssignTask}
              onRunTask={handleRunTask}
              onStopTask={handleStopTask}
            />
          )}

          {view === "settings" && (
            <SettingsPanel
              settings={settings}
              cliStatus={cliStatus}
              onSave={handleSaveSettings}
              onRefreshCli={() =>
                api.getCliStatus(true).then(setCliStatus).catch(console.error)
              }
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
          onClose={() => setShowChat(false)}
        />
      )}

      {/* Agent Detail Modal */}
      {selectedAgent && (
        <AgentDetail
          agent={selectedAgent}
          department={departments.find(
            (d) => d.id === selectedAgent.department_id
          )}
          tasks={tasks}
          subAgents={subAgents}
          onClose={() => setSelectedAgent(null)}
          onChat={(a) => {
            setSelectedAgent(null);
            handleOpenChat(a);
          }}
          onAssignTask={() => {
            setSelectedAgent(null);
            setView("tasks");
          }}
        />
      )}
    </div>
  );
}
