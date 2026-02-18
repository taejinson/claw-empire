import { useState } from "react";
import type { Department, Agent, CompanySettings } from "../types";
import { useI18n } from "../i18n";

type View = "office" | "dashboard" | "tasks" | "skills" | "settings";

interface SidebarProps {
  currentView: View;
  onChangeView: (v: View) => void;
  departments: Department[];
  agents: Agent[];
  settings: CompanySettings;
  connected: boolean;
}

const NAV_ITEMS: { view: View; icon: string }[] = [
  { view: "office", icon: "🏢" },
  { view: "skills", icon: "📚" },
  { view: "dashboard", icon: "📊" },
  { view: "tasks", icon: "📋" },
  { view: "settings", icon: "⚙️" },
];

export default function Sidebar({
  currentView,
  onChangeView,
  departments,
  agents,
  settings,
  connected,
}: SidebarProps) {
  const [collapsed, setCollapsed] = useState(false);
  const { t, locale } = useI18n();
  const workingCount = agents.filter((a) => a.status === "working").length;
  const totalAgents = agents.length;
  const isKorean = locale.startsWith("ko");

  const tr = (ko: string, en: string, ja = en, zh = en) =>
    t({ ko, en, ja, zh });

  const navLabels: Record<View, string> = {
    office: tr("오피스", "Office", "オフィス", "办公室"),
    skills: tr("문서고", "Library", "ライブラリ", "文档库"),
    dashboard: tr("대시보드", "Dashboard", "ダッシュボード", "仪表盘"),
    tasks: tr("업무 관리", "Tasks", "タスク管理", "任务管理"),
    settings: tr("설정", "Settings", "設定", "设置"),
  };

  return (
    <aside
      className={`flex flex-col bg-slate-800/80 backdrop-blur-sm border-r border-slate-700/50 transition-all duration-300 ${
        collapsed ? "w-16" : "w-48"
      }`}
    >
      {/* Logo */}
      <div className="flex items-center gap-2 px-3 py-4 border-b border-slate-700/50">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="flex items-center gap-2 hover:opacity-80 transition-opacity"
        >
          <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 relative overflow-visible">
            <img
              src="/sprites/ceo-lobster.png"
              alt={tr("CEO", "CEO")}
              className="w-8 h-8 object-contain"
              style={{ imageRendering: 'pixelated' }}
            />
            <span className="absolute -top-0.5 left-1/2 -translate-x-1/2 text-[10px] leading-none drop-shadow">👑</span>
          </div>
          {!collapsed && (
            <div className="overflow-hidden">
              <div className="text-sm font-bold text-white truncate">
                {settings.companyName}
              </div>
              <div className="text-[10px] text-slate-400">
                👑 {settings.ceoName}
              </div>
            </div>
          )}
        </button>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-2 space-y-0.5 px-2">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.view}
            onClick={() => onChangeView(item.view)}
            className={`w-full flex items-center gap-2.5 px-2.5 py-2 rounded-lg text-sm transition-all ${
              currentView === item.view
                ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                : "text-slate-400 hover:bg-slate-700/50 hover:text-slate-200 border border-transparent"
            }`}
          >
            <span className="text-base shrink-0">{item.icon}</span>
            {!collapsed && <span>{navLabels[item.view]}</span>}
          </button>
        ))}
      </nav>

      {/* Department quick stats */}
      {!collapsed && (
        <div className="px-3 py-2 border-t border-slate-700/50">
          <div className="text-[10px] uppercase text-slate-500 font-semibold mb-1.5 tracking-wider">
            {tr("부서 현황", "Department Status", "部門状況", "部门状态")}
          </div>
          {departments.map((d) => {
            const deptAgents = agents.filter(
              (a) => a.department_id === d.id
            );
            const working = deptAgents.filter(
              (a) => a.status === "working"
            ).length;
            return (
              <div
                key={d.id}
                className="flex items-center gap-1.5 py-0.5 text-xs text-slate-400"
              >
                <span>{d.icon}</span>
                <span className="flex-1 truncate">
                  {isKorean ? d.name_ko || d.name : d.name || d.name_ko}
                </span>
                <span
                  className={
                    working > 0 ? "text-blue-400 font-medium" : ""
                  }
                >
                  {working}/{deptAgents.length}
                </span>
              </div>
            );
          })}
        </div>
      )}

      {/* Status bar */}
      <div className="px-3 py-2.5 border-t border-slate-700/50">
        <div className="flex items-center gap-2">
          <div
            className={`w-2 h-2 rounded-full ${
              connected ? "bg-green-500" : "bg-red-500"
            }`}
          />
          {!collapsed && (
            <div className="text-[10px] text-slate-500">
              {connected
                ? tr("연결됨", "Connected", "接続中", "已连接")
                : tr("연결 끊김", "Disconnected", "接続なし", "已断开")}{" "}
              · {workingCount}/{totalAgents}{" "}
              {tr("근무중", "working", "稼働中", "工作中")}
            </div>
          )}
        </div>
      </div>
    </aside>
  );
}
