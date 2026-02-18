import { useState, useEffect, useRef, useMemo } from 'react';
import type { Agent, Message } from '../types';
import MessageContent from './MessageContent';
import AgentAvatar, { buildSpriteMap } from './AgentAvatar';
import { useI18n } from '../i18n';
import type { LangText } from '../i18n';

interface ChatPanelProps {
  selectedAgent: Agent | null;
  messages: Message[];
  agents: Agent[];
  onSendMessage: (content: string, receiverType: 'agent' | 'department' | 'all', receiverId?: string, messageType?: string) => void;
  onSendAnnouncement: (content: string) => void;
  onSendDirective: (content: string) => void;
  onClearMessages?: (agentId?: string) => void;
  onClose: () => void;
}

type ChatMode = 'chat' | 'task' | 'announcement' | 'report';

const STATUS_COLORS: Record<string, string> = {
  idle: 'bg-green-400',
  working: 'bg-blue-400',
  break: 'bg-yellow-400',
  offline: 'bg-gray-500',
};

const STATUS_LABELS: Record<string, LangText> = {
  idle: { ko: '대기중', en: 'Idle', ja: '待機中', zh: '待机中' },
  working: { ko: '작업중', en: 'Working', ja: '作業中', zh: '工作中' },
  break: { ko: '휴식', en: 'Break', ja: '休憩中', zh: '休息中' },
  offline: { ko: '오프라인', en: 'Offline', ja: 'オフライン', zh: '离线' },
};

const ROLE_LABELS: Record<string, LangText> = {
  team_leader: { ko: '팀장', en: 'Team Leader', ja: 'チームリーダー', zh: '组长' },
  senior: { ko: '시니어', en: 'Senior', ja: 'シニア', zh: '高级' },
  junior: { ko: '주니어', en: 'Junior', ja: 'ジュニア', zh: '初级' },
  intern: { ko: '인턴', en: 'Intern', ja: 'インターン', zh: '实习生' },
};

function formatTime(ts: number, locale: string): string {
  return new Intl.DateTimeFormat(locale, {
    hour: '2-digit',
    minute: '2-digit',
  }).format(new Date(ts));
}

function TypingIndicator() {
  return (
    <div className="flex items-center gap-1 px-4 py-2">
      <div className="flex items-center gap-1 bg-gray-700 rounded-2xl rounded-bl-sm px-4 py-2">
        <span
          className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"
          style={{ animationDelay: '0ms' }}
        />
        <span
          className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"
          style={{ animationDelay: '150ms' }}
        />
        <span
          className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"
          style={{ animationDelay: '300ms' }}
        />
      </div>
    </div>
  );
}

export function ChatPanel({
  selectedAgent,
  messages,
  agents,
  onSendMessage,
  onSendAnnouncement,
  onSendDirective,
  onClearMessages,
  onClose,
}: ChatPanelProps) {
  const [input, setInput] = useState('');
  const [mode, setMode] = useState<ChatMode>(selectedAgent ? 'task' : 'announcement');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const spriteMap = useMemo(() => buildSpriteMap(agents), [agents]);
  const { t, locale } = useI18n();
  const isKorean = locale.startsWith('ko');

  const tr = (ko: string, en: string, ja = en, zh = en) =>
    t({ ko, en, ja, zh });

  const getAgentName = (agent: Agent | null | undefined) => {
    if (!agent) return '';
    return isKorean ? agent.name_ko || agent.name : agent.name || agent.name_ko;
  };

  const getRoleLabel = (role: string) => {
    const label = ROLE_LABELS[role];
    return label ? t(label) : role;
  };

  const getStatusLabel = (status: string) => {
    const label = STATUS_LABELS[status];
    return label ? t(label) : status;
  };

  const selectedDeptName = selectedAgent?.department
    ? isKorean
      ? selectedAgent.department.name_ko || selectedAgent.department.name
      : selectedAgent.department.name || selectedAgent.department.name_ko
    : selectedAgent?.department_id;

  // Close on Escape key
  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [onClose]);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Switch mode when agent selection changes
  useEffect(() => {
    if (!selectedAgent) {
      setMode('announcement');
    } else if (mode === 'announcement') {
      setMode('task');
    }
  }, [selectedAgent]);

  const isDirectiveMode = input.trimStart().startsWith('$');

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed) return;

    // $ directive — priority over all modes
    if (trimmed.startsWith('$')) {
      const directiveContent = trimmed.slice(1).trim();
      if (directiveContent) {
        onSendDirective(directiveContent);
        setInput('');
        textareaRef.current?.focus();
        return;
      }
    }

    if (mode === 'announcement') {
      onSendAnnouncement(trimmed);
    } else if (mode === 'task' && selectedAgent) {
      onSendMessage(trimmed, 'agent', selectedAgent.id, 'task_assign');
    } else if (mode === 'report' && selectedAgent) {
      onSendMessage(
        `[${tr('보고 요청', 'Report Request', 'レポート依頼', '报告请求')}] ${trimmed}`,
        'agent',
        selectedAgent.id,
        'report'
      );
    } else if (selectedAgent) {
      onSendMessage(trimmed, 'agent', selectedAgent.id, 'chat');
    } else {
      onSendMessage(trimmed, 'all');
    }

    setInput('');
    textareaRef.current?.focus();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      handleSend();
    }
  };

  const isAnnouncementMode = mode === 'announcement';

  // Filter messages relevant to current view
  const visibleMessages = messages.filter((msg) => {
    if (!selectedAgent) {
      // Show only announcements / all broadcasts when no agent selected
      return msg.receiver_type === 'all' || msg.message_type === 'announcement' || msg.message_type === 'directive';
    }
    // Show messages between CEO and selected agent
    return (
      (msg.sender_type === 'ceo' &&
        msg.receiver_type === 'agent' &&
        msg.receiver_id === selectedAgent.id) ||
      (msg.sender_type === 'agent' &&
        msg.sender_id === selectedAgent.id) ||
      msg.message_type === 'announcement' ||
      msg.message_type === 'directive' ||
      msg.receiver_type === 'all'
    );
  });

  return (
    <div className="flex flex-col w-96 h-full bg-gray-900 border-l border-gray-700 shadow-2xl">
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 bg-gray-800 border-b border-gray-700 flex-shrink-0">
        {selectedAgent ? (
          <>
            {/* Agent avatar */}
            <div className="relative flex-shrink-0">
              <AgentAvatar agent={selectedAgent} spriteMap={spriteMap} size={40} />
              <span
                className={`absolute bottom-0 right-0 w-3 h-3 rounded-full border-2 border-gray-800 ${
                  STATUS_COLORS[selectedAgent.status] ?? 'bg-gray-500'
                }`}
              />
            </div>

            {/* Agent info */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-white text-sm truncate">
                  {getAgentName(selectedAgent)}
                </span>
                <span className="text-xs px-1.5 py-0.5 bg-gray-700 text-gray-300 rounded">
                  {getRoleLabel(selectedAgent.role)}
                </span>
              </div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="text-xs text-gray-400 truncate">
                  {selectedDeptName}
                </span>
                <span className="text-gray-600">·</span>
                <span className="text-xs text-gray-400">
                  {getStatusLabel(selectedAgent.status)}
                </span>
              </div>
            </div>
          </>
        ) : (
          <>
            <div className="w-10 h-10 rounded-full bg-yellow-500/20 flex items-center justify-center text-xl flex-shrink-0">
              📢
            </div>
            <div className="flex-1 min-w-0">
              <div className="font-semibold text-white text-sm">
                {tr('전사 공지', 'Company Announcement', '全体告知', '全员公告')}
              </div>
              <div className="text-xs text-gray-400 mt-0.5">
                {tr('모든 에이전트에게 전달됩니다', 'Sent to all agents', 'すべてのエージェントに送信されます', '将发送给所有代理')}
              </div>
            </div>
          </>
        )}

        <div className="flex items-center gap-1 flex-shrink-0">
          {/* Clear messages */}
          {onClearMessages && visibleMessages.length > 0 && (
            <button
              onClick={() => {
                if (
                  window.confirm(
                    selectedAgent
                      ? tr(
                          `${getAgentName(selectedAgent)}와의 대화를 삭제하시겠습니까?`,
                          `Delete conversation with ${getAgentName(selectedAgent)}?`,
                          `${getAgentName(selectedAgent)}との会話を削除しますか？`,
                          `要删除与 ${getAgentName(selectedAgent)} 的对话吗？`
                        )
                      : tr(
                          '전사 공지 내역을 삭제하시겠습니까?',
                          'Delete announcement history?',
                          '全体告知履歴を削除しますか？',
                          '要删除全员公告记录吗？'
                        )
                  )
                ) {
                  onClearMessages(selectedAgent?.id);
                }
              }}
              className="w-8 h-8 flex items-center justify-center rounded-full text-gray-500 hover:text-red-400 hover:bg-gray-700 transition-colors"
              title={tr('대화 내역 삭제', 'Clear message history', '会話履歴を削除', '清除消息记录')}
            >
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M3 6h18M8 6V4a2 2 0 012-2h4a2 2 0 012 2v2m3 0v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6h14" />
              </svg>
            </button>
          )}
          {/* Close button */}
          <button
            onClick={onClose}
            className="w-8 h-8 flex items-center justify-center rounded-full text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
            aria-label={tr('닫기', 'Close', '閉じる', '关闭')}
          >
            ✕
          </button>
        </div>
      </div>

      {/* Announcement mode banner */}
      {isAnnouncementMode && (
        <div className="flex items-center gap-2 px-4 py-2 bg-yellow-500/10 border-b border-yellow-500/30 flex-shrink-0">
          <span className="text-yellow-400 text-sm font-medium">
            📢 {tr('전사 공지 모드 - 모든 에이전트에게 전달됩니다', 'Announcement mode - sent to all agents', '全体告知モード - すべてのエージェントに送信', '全员公告模式 - 将发送给所有代理')}
          </span>
        </div>
      )}

      {/* Messages area */}
      <div className="flex-1 overflow-y-auto px-4 py-4 space-y-3 min-h-0">
        {visibleMessages.length === 0 ? (
          /* Empty state */
          <div className="flex flex-col items-center justify-center h-full gap-4 text-center">
            <div className="text-6xl">💬</div>
            <div>
              <p className="text-gray-400 font-medium">
                {tr('대화를 시작해보세요! 👋', 'Start a conversation! 👋', '会話を始めましょう! 👋', '开始对话吧! 👋')}
              </p>
              <p className="text-gray-600 text-sm mt-1">
                {selectedAgent
                  ? tr(
                      `${getAgentName(selectedAgent)}에게 메시지를 보내보세요`,
                      `Send a message to ${getAgentName(selectedAgent)}`,
                      `${getAgentName(selectedAgent)}にメッセージを送ってみましょう`,
                      `给 ${getAgentName(selectedAgent)} 发送一条消息吧`
                    )
                  : tr(
                      '전체 에이전트에게 공지를 보내보세요',
                      'Send an announcement to all agents',
                      'すべてのエージェントに告知を送ってみましょう',
                      '给所有代理发送一条公告吧'
                    )}
              </p>
            </div>
          </div>
        ) : (
          <>
            {visibleMessages.map((msg) => {
              const isCeo = msg.sender_type === 'ceo';
              const isDirective = msg.message_type === 'directive';
              const isSystem =
                msg.sender_type === 'system' || msg.message_type === 'announcement' || isDirective;

              // Resolve sender name
              const senderAgent =
                msg.sender_agent ??
                agents.find((a) => a.id === msg.sender_id);
              const senderName = isCeo
                ? tr('CEO', 'CEO')
                : isSystem
                ? tr('시스템', 'System', 'システム', '系统')
                : getAgentName(senderAgent) || tr('알 수 없음', 'Unknown', '不明', '未知');

              // Agent reply to announcements: show as left-aligned agent bubble
              if (msg.sender_type === 'agent' && msg.receiver_type === 'all') {
                return (
                  <div key={msg.id} className="flex items-end gap-2">
                    <AgentAvatar agent={senderAgent} spriteMap={spriteMap} size={28} />
                    <div className="flex flex-col gap-1 max-w-[75%]">
                      <span className="text-xs text-gray-500 px-1">{senderName}</span>
                      <div className="bg-gray-700/70 text-gray-100 text-sm rounded-2xl rounded-bl-sm px-4 py-2.5 shadow-md border border-yellow-500/20">
                        <MessageContent content={msg.content} />
                      </div>
                      <span className="text-xs text-gray-600 px-1">
                        {formatTime(msg.created_at, locale)}
                      </span>
                    </div>
                  </div>
                );
              }

              if (isSystem || msg.receiver_type === 'all') {
                // Center announcement / directive bubble
                return (
                  <div key={msg.id} className="flex flex-col items-center gap-1">
                    {isDirective && (
                      <span className="text-xs font-bold text-red-400 px-2 py-0.5 bg-red-500/10 border border-red-500/30 rounded-full">
                        {tr('업무지시', 'Directive', '業務指示', '业务指示')}
                      </span>
                    )}
                    <div className={`max-w-[85%] text-sm rounded-2xl px-4 py-2.5 text-center shadow-sm ${
                      isDirective
                        ? 'bg-red-500/15 border border-red-500/30 text-red-300'
                        : 'bg-yellow-500/15 border border-yellow-500/30 text-yellow-300'
                    }`}>
                      <MessageContent content={msg.content} />
                    </div>
                    <span className="text-xs text-gray-600">
                      {formatTime(msg.created_at, locale)}
                    </span>
                  </div>
                );
              }

              if (isCeo) {
                // Right-aligned CEO bubble
                return (
                  <div key={msg.id} className="flex flex-col items-end gap-1">
                    <span className="text-xs text-gray-500 px-1">
                      {tr('CEO', 'CEO')}
                    </span>
                    <div className="max-w-[80%] bg-blue-600 text-white text-sm rounded-2xl rounded-br-sm px-4 py-2.5 shadow-md">
                      <MessageContent content={msg.content} />
                    </div>
                    <span className="text-xs text-gray-600 px-1">
                      {formatTime(msg.created_at, locale)}
                    </span>
                  </div>
                );
              }

              // Left-aligned agent bubble
              return (
                <div key={msg.id} className="flex items-end gap-2">
                  <AgentAvatar agent={senderAgent} spriteMap={spriteMap} size={28} />
                  <div className="flex flex-col gap-1 max-w-[75%]">
                    <span className="text-xs text-gray-500 px-1">{senderName}</span>
                    <div className="bg-gray-700 text-gray-100 text-sm rounded-2xl rounded-bl-sm px-4 py-2.5 shadow-md">
                      <MessageContent content={msg.content} />
                    </div>
                    <span className="text-xs text-gray-600 px-1">
                      {formatTime(msg.created_at, locale)}
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Typing indicator when selected agent is working */}
            {selectedAgent && selectedAgent.status === 'working' && (
              <div className="flex items-end gap-2">
                <AgentAvatar agent={selectedAgent} spriteMap={spriteMap} size={28} />
                <TypingIndicator />
              </div>
            )}
          </>
        )}

        {/* Auto-scroll anchor */}
        <div ref={messagesEndRef} />
      </div>

      {/* Quick action buttons */}
      <div className="flex gap-2 px-4 pt-3 pb-1 flex-shrink-0 border-t border-gray-700/50">
        <button
          onClick={() => setMode(mode === 'task' ? 'chat' : 'task')}
          disabled={!selectedAgent}
          className={`flex-1 flex items-center justify-center gap-1 text-xs px-2 py-1.5 rounded-lg transition-colors font-medium ${
            mode === 'task'
              ? 'bg-blue-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-40 disabled:cursor-not-allowed'
          }`}
        >
          <span>📋</span>
          <span>{tr('업무 지시', 'Task', 'タスク指示', '任务指示')}</span>
        </button>

        <button
          onClick={() => setMode(mode === 'announcement' ? 'chat' : 'announcement')}
          className={`flex-1 flex items-center justify-center gap-1 text-xs px-2 py-1.5 rounded-lg transition-colors font-medium ${
            mode === 'announcement'
              ? 'bg-yellow-500 text-gray-900'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
          }`}
        >
          <span>📢</span>
          <span>{tr('전사 공지', 'Announcement', '全体告知', '全员公告')}</span>
        </button>

        <button
          onClick={() => setMode(mode === 'report' ? 'chat' : 'report')}
          disabled={!selectedAgent}
          className={`flex-1 flex items-center justify-center gap-1 text-xs px-2 py-1.5 rounded-lg transition-colors font-medium ${
            mode === 'report'
              ? 'bg-emerald-600 text-white'
              : 'bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-40 disabled:cursor-not-allowed'
          }`}
        >
          <span>📊</span>
          <span>{tr('보고 요청', 'Report', 'レポート依頼', '报告请求')}</span>
        </button>
      </div>

      {/* Mode hint */}
      {(mode !== 'chat' || isDirectiveMode) && (
        <div className="px-4 py-1 flex-shrink-0">
          {isDirectiveMode ? (
            <p className="text-xs text-red-400 font-medium">
              {tr('업무지시 모드 — 기획팀이 자동으로 주관합니다', 'Directive mode - Planning team auto-coordinates', '業務指示モード — 企画チームが自動的に主管します', '业务指示模式 — 企划组自动主管')}
            </p>
          ) : (
            <>
              {mode === 'task' && (
                <p className="text-xs text-blue-400">
                  📋 {tr('업무 지시 모드 — 에이전트에게 작업을 할당합니다', 'Task mode - assign work to the agent', 'タスク指示モード — エージェントに作業を割り当てます', '任务指示模式 — 向代理分配工作')}
                </p>
              )}
              {mode === 'announcement' && (
                <p className="text-xs text-yellow-400">
                  📢 {tr('전사 공지 모드 — 모든 에이전트에게 전달됩니다', 'Announcement mode - sent to all agents', '全体告知モード — すべてのエージェントに送信', '全员公告模式 — 将发送给所有代理')}
                </p>
              )}
              {mode === 'report' && (
                <p className="text-xs text-emerald-400">
                  📊 {tr('보고 요청 모드 — 보고서/발표자료 작성 작업을 요청합니다', 'Report mode - request report/deck authoring', 'レポート依頼モード — レポート/資料作成を依頼します', '报告请求模式 — 请求撰写报告/演示资料')}
                </p>
              )}
            </>
          )}
        </div>
      )}

      {/* Input area */}
      <div className="px-4 pb-4 pt-2 flex-shrink-0">
        <div
          className={`flex items-end gap-2 bg-gray-800 rounded-2xl border transition-colors ${
            isDirectiveMode
              ? 'border-red-500/50 focus-within:border-red-400'
              : isAnnouncementMode
              ? 'border-yellow-500/50 focus-within:border-yellow-400'
              : mode === 'task'
              ? 'border-blue-500/50 focus-within:border-blue-400'
              : mode === 'report'
              ? 'border-emerald-500/50 focus-within:border-emerald-400'
              : 'border-gray-600 focus-within:border-blue-500'
          }`}
        >
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={
              isAnnouncementMode
                ? tr('전사 공지 내용을 입력하세요...', 'Write an announcement...', '全体告知内容を入力してください...', '请输入公告内容...')
                : mode === 'task'
                ? tr('업무 지시 내용을 입력하세요...', 'Write a task instruction...', 'タスク指示内容を入力してください...', '请输入任务指示内容...')
                : mode === 'report'
                ? tr('보고 요청 내용을 입력하세요...', 'Write a report request...', 'レポート依頼内容を入力してください...', '请输入报告请求内容...')
                : selectedAgent
                ? tr(
                    `${getAgentName(selectedAgent)}에게 메시지 보내기...`,
                    `Send a message to ${getAgentName(selectedAgent)}...`,
                    `${getAgentName(selectedAgent)}にメッセージを送る...`,
                    `向 ${getAgentName(selectedAgent)} 发送消息...`
                  )
                : tr('메시지를 입력하세요...', 'Type a message...', 'メッセージを入力してください...', '请输入消息...')
            }
            rows={1}
            className="flex-1 bg-transparent text-gray-100 text-sm placeholder-gray-500 resize-none px-4 py-3 focus:outline-none max-h-32 min-h-[44px] overflow-y-auto leading-relaxed"
            style={{
              scrollbarWidth: 'none',
            }}
            onInput={(e) => {
              const el = e.currentTarget;
              el.style.height = 'auto';
              el.style.height = `${Math.min(el.scrollHeight, 128)}px`;
            }}
          />
          <button
            onClick={handleSend}
            disabled={!input.trim()}
            className={`flex-shrink-0 w-9 h-9 mb-2 mr-2 rounded-xl flex items-center justify-center transition-all ${
              input.trim()
                ? isDirectiveMode
                  ? 'bg-red-600 hover:bg-red-500 text-white'
                  : isAnnouncementMode
                  ? 'bg-yellow-500 hover:bg-yellow-400 text-gray-900'
                  : mode === 'task'
                  ? 'bg-blue-600 hover:bg-blue-500 text-white'
                  : mode === 'report'
                  ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                  : 'bg-blue-600 hover:bg-blue-500 text-white'
                : 'bg-gray-700 text-gray-600 cursor-not-allowed'
            }`}
            aria-label={tr('전송', 'Send', '送信', '发送')}
          >
            <svg
              xmlns="http://www.w3.org/2000/svg"
              viewBox="0 0 24 24"
              fill="currentColor"
              className="w-4 h-4"
            >
              <path d="M3.478 2.405a.75.75 0 00-.926.94l2.432 7.905H13.5a.75.75 0 010 1.5H4.984l-2.432 7.905a.75.75 0 00.926.94 60.519 60.519 0 0018.445-8.986.75.75 0 000-1.218A60.517 60.517 0 003.478 2.405z" />
            </svg>
          </button>
        </div>
        <p className="text-xs text-gray-600 mt-1.5 px-1">
          {tr('Enter로 전송, Shift+Enter로 줄바꿈', 'Press Enter to send, Shift+Enter for a new line', 'Enterで送信、Shift+Enterで改行', '按 Enter 发送，Shift+Enter 换行')}
        </p>
      </div>
    </div>
  );
}
