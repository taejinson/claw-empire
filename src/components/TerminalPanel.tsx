import { useState, useEffect, useRef, useCallback, useMemo } from 'react';
import type { Agent, Task, MeetingMinute } from '../types';
import * as api from '../api';
import AgentAvatar from './AgentAvatar';
import { useI18n } from '../i18n';
import type { LangText } from '../i18n';

interface TerminalPanelProps {
  taskId: string;
  task: Task | undefined;
  agent: Agent | undefined;
  agents: Agent[];
  initialTab?: 'terminal' | 'minutes';
  onClose: () => void;
}

const STATUS_BADGES: Record<string, { label: LangText; color: string }> = {
  in_progress: {
    label: { ko: '진행중', en: 'Running', ja: '実行中', zh: '运行中' },
    color: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
  },
  review: {
    label: { ko: '검토', en: 'Review', ja: 'レビュー', zh: '审核' },
    color: 'bg-purple-500/20 text-purple-400 border-purple-500/40',
  },
  done: {
    label: { ko: '완료', en: 'Done', ja: '完了', zh: '完成' },
    color: 'bg-green-500/20 text-green-400 border-green-500/40',
  },
  inbox: {
    label: { ko: '수신함', en: 'Inbox', ja: '受信箱', zh: '收件箱' },
    color: 'bg-slate-500/20 text-slate-400 border-slate-500/40',
  },
  planned: {
    label: { ko: '예정', en: 'Planned', ja: '予定', zh: '计划' },
    color: 'bg-blue-500/20 text-blue-400 border-blue-500/40',
  },
  cancelled: {
    label: { ko: '취소', en: 'Cancelled', ja: 'キャンセル', zh: '已取消' },
    color: 'bg-red-500/20 text-red-400 border-red-500/40',
  },
};

interface TaskLogEntry {
  id: number;
  kind: string;
  message: string;
  created_at: number;
}

export default function TerminalPanel({ taskId, task, agent, agents, initialTab = 'terminal', onClose }: TerminalPanelProps) {
  const [text, setText] = useState('');
  const [taskLogs, setTaskLogs] = useState<TaskLogEntry[]>([]);
  const [meetingMinutes, setMeetingMinutes] = useState<MeetingMinute[]>([]);
  const [logPath, setLogPath] = useState('');
  const [follow, setFollow] = useState(true);
  const [activeTab, setActiveTab] = useState<'terminal' | 'minutes'>(initialTab);
  const preRef = useRef<HTMLPreElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const { t, locale } = useI18n();

  const tr = (ko: string, en: string, ja = en, zh = en) =>
    t({ ko, en, ja, zh });

  const isKorean = locale.startsWith('ko');
  const agentName = agent
    ? isKorean
      ? agent.name_ko || agent.name
      : agent.name || agent.name_ko
    : null;

  const taskLogTimeFormatter = useMemo(
    () =>
      new Intl.DateTimeFormat(locale, {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      }),
    [locale]
  );

  useEffect(() => {
    setActiveTab(initialTab);
  }, [initialTab, taskId]);

  // Poll terminal endpoint every 1.5s
  const fetchTerminal = useCallback(async () => {
    try {
      const res = await api.getTerminal(taskId, 800, true);
      if (res.ok) {
        setLogPath(res.path);
        if (res.task_logs) setTaskLogs(res.task_logs);
        if (res.exists && res.text) {
          setText(res.text);
        }
      }
    } catch {
      // ignore
    }
  }, [taskId]);

  const fetchMeetingMinutes = useCallback(async () => {
    try {
      const rows = await api.getTaskMeetingMinutes(taskId);
      setMeetingMinutes(rows);
    } catch {
      // ignore
    }
  }, [taskId]);

  useEffect(() => {
    if (activeTab === 'terminal') {
      fetchTerminal();
    } else {
      fetchMeetingMinutes();
    }
    const timer = setInterval(
      activeTab === 'terminal' ? fetchTerminal : fetchMeetingMinutes,
      activeTab === 'terminal' ? 1500 : 2500,
    );
    return () => clearInterval(timer);
  }, [activeTab, fetchTerminal, fetchMeetingMinutes]);

  // Close on Escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Auto-scroll when follow is enabled
  useEffect(() => {
    if (follow && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [text, follow]);

  // Detect if user scrolled away from bottom
  function handleScroll() {
    if (!containerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = containerRef.current;
    const atBottom = scrollHeight - scrollTop - clientHeight < 50;
    if (!atBottom && follow) setFollow(false);
  }

  function scrollToBottom() {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
      setFollow(true);
    }
  }

  const badge = STATUS_BADGES[task?.status ?? ''] ?? STATUS_BADGES.inbox;
  const badgeLabel = t(badge.label);
  const meetingTypeLabel = (type: 'planned' | 'review') =>
    type === 'planned'
      ? tr('Planned 승인', 'Planned Approval', 'Planned 承認', 'Planned 审批')
      : tr('Review 승인', 'Review Approval', 'Review 承認', 'Review 审批');
  const meetingStatusLabel = (status: MeetingMinute['status']) => {
    if (status === 'completed') return tr('완료', 'Completed', '完了', '已完成');
    if (status === 'revision_requested') return tr('보완 요청', 'Revision Requested', '修正要請', '要求修订');
    if (status === 'failed') return tr('실패', 'Failed', '失敗', '失败');
    return tr('진행중', 'In Progress', '進行中', '进行中');
  };

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-[560px] max-w-full flex flex-col bg-[#0d1117] border-l border-slate-700/50 shadow-2xl">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-700/50 bg-[#161b22]">
        <div className="flex items-center gap-2 flex-1 min-w-0">
          {agent && (
            <AgentAvatar agent={agent} agents={agents} size={28} />
          )}
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-bold text-white truncate">
                {task?.title ?? taskId}
              </h3>
              <span className={`text-[10px] px-1.5 py-0.5 rounded border ${badge.color} flex-shrink-0`}>
                {badgeLabel}
              </span>
            </div>
            {logPath && (
              <div className="text-[10px] text-slate-500 truncate font-mono mt-0.5">
                {logPath}
              </div>
            )}
            <div className="mt-1 inline-flex rounded-md border border-slate-700 overflow-hidden w-fit">
              <button
                onClick={() => setActiveTab('terminal')}
                className={`px-2 py-0.5 text-[10px] transition ${
                  activeTab === 'terminal' ? 'bg-cyan-700/30 text-cyan-200' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {tr('터미널', 'Terminal', 'ターミナル', '终端')}
              </button>
              <button
                onClick={() => setActiveTab('minutes')}
                className={`px-2 py-0.5 text-[10px] transition ${
                  activeTab === 'minutes' ? 'bg-cyan-700/30 text-cyan-200' : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {tr('회의록', 'Minutes', '会議録', '会议纪要')}
              </button>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-1.5 flex-shrink-0">
          {/* Follow toggle */}
          <button
            onClick={() => setFollow(f => !f)}
            className={`px-2 py-1 text-[10px] rounded border transition ${
              follow
                ? 'bg-green-500/20 text-green-400 border-green-500/40'
                : 'bg-slate-700/50 text-slate-400 border-slate-600'
            }`}
            title={
              follow
                ? tr('자동 스크롤 ON', 'Auto-scroll ON', '自動スクロール ON', '自动滚动 ON')
                : tr('자동 스크롤 OFF', 'Auto-scroll OFF', '自動スクロール OFF', '自动滚动 OFF')
            }
          >
            {follow
              ? tr('따라가기', 'FOLLOW', '追従中', '跟随中')
              : tr('일시정지', 'PAUSED', '一時停止', '已暂停')}
          </button>
          {/* Scroll to bottom */}
          <button
            onClick={scrollToBottom}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded transition"
            title={tr('맨 아래로', 'Scroll to bottom', '一番下へ', '滚动到底部')}
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M12 5v14M5 12l7 7 7-7" />
            </svg>
          </button>
          {/* Close */}
          <button
            onClick={onClose}
            className="p-1.5 text-slate-400 hover:text-white hover:bg-slate-700 rounded transition"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        </div>
      </div>

      {/* Task log markers (system events) */}
      {activeTab === 'terminal' && taskLogs.length > 0 && (
        <div className="px-4 py-2 border-b border-slate-700/30 bg-[#161b22]/50 space-y-0.5 max-h-24 overflow-y-auto">
          {taskLogs.map(log => {
            const kindColor = log.kind === 'error' ? 'text-red-400' :
              log.kind === 'system' ? 'text-cyan-400' : 'text-slate-500';
            const time = taskLogTimeFormatter.format(new Date(log.created_at));
            return (
              <div key={log.id} className={`text-[10px] font-mono ${kindColor}`}>
                [{time}] {log.message}
              </div>
            );
          })}
        </div>
      )}

      {/* Terminal body */}
      {activeTab === 'terminal' ? (
        <div
          ref={containerRef}
          className="flex-1 overflow-y-auto p-4"
          onScroll={handleScroll}
        >
          {!text ? (
            <div className="flex flex-col items-center justify-center h-full text-slate-500">
              <div className="text-3xl mb-3">
                {task?.status === 'in_progress' ? (
                  <span className="inline-block animate-spin">&#9881;</span>
                ) : (
                  <span>&#128421;</span>
                )}
              </div>
              <div className="text-sm">
                {task?.status === 'in_progress'
                  ? tr('출력을 기다리는 중...', 'Waiting for output...', '出力待機中...', '正在等待输出...')
                  : tr('아직 터미널 출력이 없습니다', 'No terminal output yet', 'まだターミナル出力がありません', '暂无终端输出')}
              </div>
            </div>
          ) : (
            <pre
              ref={preRef}
              className="text-[12px] leading-relaxed text-green-300 font-mono whitespace-pre-wrap break-words selection:bg-green-800/40"
            >
              {text}
            </pre>
          )}
        </div>
      ) : (
        <div className="flex-1 overflow-y-auto p-4 space-y-3">
          {meetingMinutes.length === 0 ? (
            <div className="flex h-full flex-col items-center justify-center text-slate-500">
              <div className="text-3xl mb-3">📝</div>
              <div className="text-sm">
                {tr('회의록이 아직 없습니다', 'No meeting minutes yet', '会議録はまだありません', '暂无会议纪要')}
              </div>
            </div>
          ) : (
            meetingMinutes.map((meeting) => (
              <div key={meeting.id} className="rounded-xl border border-slate-700 bg-slate-900/70 p-3">
                <div className="mb-2 flex flex-wrap items-center gap-2">
                  <span className="rounded bg-cyan-900/50 px-2 py-0.5 text-[10px] text-cyan-200">
                    {meetingTypeLabel(meeting.meeting_type)}
                  </span>
                  <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
                    {tr('라운드', 'Round', 'ラウンド', '轮次')} {meeting.round}
                  </span>
                  <span className="rounded bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
                    {meetingStatusLabel(meeting.status)}
                  </span>
                  <span className="ml-auto text-[10px] text-slate-500">
                    {new Date(meeting.started_at).toLocaleString(locale)}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {meeting.entries.map((entry) => (
                    <div key={entry.id} className="rounded-md border border-slate-800 bg-slate-950/60 px-2 py-1.5">
                      <div className="mb-0.5 flex items-center gap-2 text-[10px] text-slate-400">
                        <span>#{entry.seq}</span>
                        <span className="text-cyan-300">{entry.speaker_name}</span>
                        {entry.department_name && <span>{entry.department_name}</span>}
                        {entry.role_label && <span>· {entry.role_label}</span>}
                      </div>
                      <div className="text-xs leading-relaxed text-slate-200 whitespace-pre-wrap break-words">
                        {entry.content}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      )}

      {/* Bottom status bar */}
      <div className="flex items-center justify-between px-4 py-1.5 border-t border-slate-700/50 bg-[#161b22] text-[10px] text-slate-500">
        <span>
          {agent ? `${agentName}` : tr('담당 에이전트 없음', 'No agent', '担当エージェントなし', '无负责人')}
          {agent?.cli_provider ? ` (${agent.cli_provider})` : ''}
        </span>
        <span>
          {task?.status === 'in_progress' && (
            <span className="inline-flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
              {activeTab === 'terminal'
                ? tr('실시간', 'Live', 'ライブ', '实时')
                : tr('회의록', 'Minutes', '会議録', '会议纪要')}
            </span>
          )}
          {task?.status === 'review' && tr('검토 중', 'Under review', 'レビュー中', '审核中')}
          {task?.status === 'done' && tr('완료됨', 'Completed', '完了', '已完成')}
        </span>
      </div>
    </div>
  );
}
