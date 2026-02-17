import { useState, useEffect, useRef } from 'react';
import type { Agent, Message } from '../types';

interface ChatPanelProps {
  selectedAgent: Agent | null;
  messages: Message[];
  agents: Agent[];
  onSendMessage: (content: string, receiverType: 'agent' | 'department' | 'all', receiverId?: string, messageType?: string) => void;
  onSendAnnouncement: (content: string) => void;
  onClose: () => void;
}

type ChatMode = 'chat' | 'task' | 'announcement' | 'report';

const STATUS_COLORS: Record<string, string> = {
  idle: 'bg-green-400',
  working: 'bg-blue-400',
  break: 'bg-yellow-400',
  offline: 'bg-gray-500',
};

const STATUS_LABELS: Record<string, string> = {
  idle: '대기중',
  working: '작업중',
  break: '휴식',
  offline: '오프라인',
};

const ROLE_LABELS: Record<string, string> = {
  team_leader: '팀장',
  senior: '시니어',
  junior: '주니어',
  intern: '인턴',
};

function formatTime(ts: number): string {
  const d = new Date(ts);
  const h = d.getHours().toString().padStart(2, '0');
  const m = d.getMinutes().toString().padStart(2, '0');
  return `${h}:${m}`;
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
  onClose,
}: ChatPanelProps) {
  const [input, setInput] = useState('');
  const [mode, setMode] = useState<ChatMode>('chat');
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Switch to announcement mode when no agent selected
  useEffect(() => {
    if (!selectedAgent && mode === 'chat') {
      setMode('announcement');
    } else if (selectedAgent && mode === 'announcement') {
      setMode('chat');
    }
  }, [selectedAgent]);

  const handleSend = () => {
    const trimmed = input.trim();
    if (!trimmed) return;

    if (mode === 'announcement') {
      onSendAnnouncement(trimmed);
    } else if (mode === 'task' && selectedAgent) {
      onSendMessage(trimmed, 'agent', selectedAgent.id, 'task_assign');
    } else if (mode === 'report' && selectedAgent) {
      onSendMessage(`[보고 요청] ${trimmed}`, 'agent', selectedAgent.id, 'report');
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
      return msg.receiver_type === 'all' || msg.message_type === 'announcement';
    }
    // Show messages between CEO and selected agent
    return (
      (msg.sender_type === 'ceo' &&
        msg.receiver_type === 'agent' &&
        msg.receiver_id === selectedAgent.id) ||
      (msg.sender_type === 'agent' &&
        msg.sender_id === selectedAgent.id) ||
      msg.message_type === 'announcement' ||
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
              <div className="w-10 h-10 rounded-full bg-gray-700 flex items-center justify-center text-xl">
                {selectedAgent.avatar_emoji}
              </div>
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
                  {selectedAgent.name_ko || selectedAgent.name}
                </span>
                <span className="text-xs px-1.5 py-0.5 bg-gray-700 text-gray-300 rounded">
                  {ROLE_LABELS[selectedAgent.role] ?? selectedAgent.role}
                </span>
              </div>
              <div className="flex items-center gap-1.5 mt-0.5">
                <span className="text-xs text-gray-400 truncate">
                  {selectedAgent.department?.name_ko ?? selectedAgent.department_id}
                </span>
                <span className="text-gray-600">·</span>
                <span className="text-xs text-gray-400">
                  {STATUS_LABELS[selectedAgent.status] ?? selectedAgent.status}
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
              <div className="font-semibold text-white text-sm">전사 공지</div>
              <div className="text-xs text-gray-400 mt-0.5">
                모든 에이전트에게 전달됩니다
              </div>
            </div>
          </>
        )}

        {/* Close button */}
        <button
          onClick={onClose}
          className="flex-shrink-0 w-8 h-8 flex items-center justify-center rounded-full text-gray-400 hover:text-white hover:bg-gray-700 transition-colors"
          aria-label="닫기"
        >
          ✕
        </button>
      </div>

      {/* Announcement mode banner */}
      {isAnnouncementMode && (
        <div className="flex items-center gap-2 px-4 py-2 bg-yellow-500/10 border-b border-yellow-500/30 flex-shrink-0">
          <span className="text-yellow-400 text-sm font-medium">
            📢 전사 공지 모드 - 모든 에이전트에게 전달됩니다
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
              <p className="text-gray-400 font-medium">대화를 시작해보세요! 👋</p>
              <p className="text-gray-600 text-sm mt-1">
                {selectedAgent
                  ? `${selectedAgent.name_ko || selectedAgent.name}에게 메시지를 보내보세요`
                  : '전체 에이전트에게 공지를 보내보세요'}
              </p>
            </div>
          </div>
        ) : (
          <>
            {visibleMessages.map((msg) => {
              const isCeo = msg.sender_type === 'ceo';
              const isSystem =
                msg.sender_type === 'system' || msg.message_type === 'announcement';

              // Resolve sender name
              const senderAgent =
                msg.sender_agent ??
                agents.find((a) => a.id === msg.sender_id);
              const senderName = isCeo
                ? 'CEO'
                : isSystem
                ? '시스템'
                : senderAgent?.name_ko ?? senderAgent?.name ?? '알 수 없음';

              if (isSystem || msg.receiver_type === 'all') {
                // Center announcement bubble
                return (
                  <div key={msg.id} className="flex flex-col items-center gap-1">
                    <div className="max-w-[85%] bg-yellow-500/15 border border-yellow-500/30 text-yellow-300 text-sm rounded-2xl px-4 py-2.5 text-center shadow-sm">
                      {msg.content}
                    </div>
                    <span className="text-xs text-gray-600">{formatTime(msg.created_at)}</span>
                  </div>
                );
              }

              if (isCeo) {
                // Right-aligned CEO bubble
                return (
                  <div key={msg.id} className="flex flex-col items-end gap-1">
                    <span className="text-xs text-gray-500 px-1">CEO</span>
                    <div className="max-w-[80%] bg-blue-600 text-white text-sm rounded-2xl rounded-br-sm px-4 py-2.5 shadow-md">
                      {msg.content}
                    </div>
                    <span className="text-xs text-gray-600 px-1">
                      {formatTime(msg.created_at)}
                    </span>
                  </div>
                );
              }

              // Left-aligned agent bubble
              return (
                <div key={msg.id} className="flex items-end gap-2">
                  <div className="flex-shrink-0 w-7 h-7 rounded-full bg-gray-700 flex items-center justify-center text-base">
                    {senderAgent?.avatar_emoji ?? '🤖'}
                  </div>
                  <div className="flex flex-col gap-1 max-w-[75%]">
                    <span className="text-xs text-gray-500 px-1">{senderName}</span>
                    <div className="bg-gray-700 text-gray-100 text-sm rounded-2xl rounded-bl-sm px-4 py-2.5 shadow-md">
                      {msg.content}
                    </div>
                    <span className="text-xs text-gray-600 px-1">
                      {formatTime(msg.created_at)}
                    </span>
                  </div>
                </div>
              );
            })}

            {/* Typing indicator when selected agent is working */}
            {selectedAgent && selectedAgent.status === 'working' && (
              <div className="flex items-end gap-2">
                <div className="flex-shrink-0 w-7 h-7 rounded-full bg-gray-700 flex items-center justify-center text-base">
                  {selectedAgent.avatar_emoji}
                </div>
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
          <span>업무 지시</span>
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
          <span>전사 공지</span>
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
          <span>보고 요청</span>
        </button>
      </div>

      {/* Mode hint */}
      {mode !== 'chat' && (
        <div className="px-4 py-1 flex-shrink-0">
          {mode === 'task' && (
            <p className="text-xs text-blue-400">
              📋 업무 지시 모드 — 에이전트에게 작업을 할당합니다
            </p>
          )}
          {mode === 'announcement' && (
            <p className="text-xs text-yellow-400">
              📢 전사 공지 모드 — 모든 에이전트에게 전달됩니다
            </p>
          )}
          {mode === 'report' && (
            <p className="text-xs text-emerald-400">
              📊 보고 요청 모드 — 에이전트에게 현황 보고를 요청합니다
            </p>
          )}
        </div>
      )}

      {/* Input area */}
      <div className="px-4 pb-4 pt-2 flex-shrink-0">
        <div
          className={`flex items-end gap-2 bg-gray-800 rounded-2xl border transition-colors ${
            isAnnouncementMode
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
                ? '전사 공지 내용을 입력하세요...'
                : mode === 'task'
                ? '업무 지시 내용을 입력하세요...'
                : mode === 'report'
                ? '보고 요청 내용을 입력하세요...'
                : selectedAgent
                ? `${selectedAgent.name_ko || selectedAgent.name}에게 메시지 보내기...`
                : '메시지를 입력하세요...'
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
                ? isAnnouncementMode
                  ? 'bg-yellow-500 hover:bg-yellow-400 text-gray-900'
                  : mode === 'task'
                  ? 'bg-blue-600 hover:bg-blue-500 text-white'
                  : mode === 'report'
                  ? 'bg-emerald-600 hover:bg-emerald-500 text-white'
                  : 'bg-blue-600 hover:bg-blue-500 text-white'
                : 'bg-gray-700 text-gray-600 cursor-not-allowed'
            }`}
            aria-label="전송"
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
          Enter로 전송, Shift+Enter로 줄바꿈
        </p>
      </div>
    </div>
  );
}
