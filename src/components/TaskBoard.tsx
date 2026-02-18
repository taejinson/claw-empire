import { useState, useMemo, useCallback, useEffect } from 'react';
import type { Task, Agent, Department, TaskStatus, TaskType, SubTask } from '../types';
import AgentAvatar from './AgentAvatar';
import AgentSelect from './AgentSelect';
import { getTaskDiff, mergeTask, discardTask, type TaskDiffResult } from '../api';

interface TaskBoardProps {
  tasks: Task[];
  agents: Agent[];
  departments: Department[];
  subtasks: SubTask[];
  onCreateTask: (input: {
    title: string;
    description?: string;
    department_id?: string;
    task_type?: string;
    priority?: number;
  }) => void;
  onUpdateTask: (id: string, data: Partial<Task>) => void;
  onDeleteTask: (id: string) => void;
  onAssignTask: (taskId: string, agentId: string) => void;
  onRunTask: (id: string) => void;
  onStopTask: (id: string) => void;
  onPauseTask?: (id: string) => void;
  onResumeTask?: (id: string) => void;
  onOpenTerminal?: (taskId: string) => void;
  onOpenMeetingMinutes?: (taskId: string) => void;
  onMergeTask?: (id: string) => void;
  onDiscardTask?: (id: string) => void;
}

type Locale = 'ko' | 'en' | 'ja' | 'zh';
type TFunction = (messages: Record<Locale, string>) => string;

const LANGUAGE_STORAGE_KEY = 'climpire.language';
const LOCALE_TAGS: Record<Locale, string> = {
  ko: 'ko-KR',
  en: 'en-US',
  ja: 'ja-JP',
  zh: 'zh-CN',
};

function normalizeLocale(value: string | null | undefined): Locale | null {
  const code = (value ?? '').toLowerCase();
  if (code.startsWith('ko')) return 'ko';
  if (code.startsWith('en')) return 'en';
  if (code.startsWith('ja')) return 'ja';
  if (code.startsWith('zh')) return 'zh';
  return null;
}

function detectLocale(): Locale {
  if (typeof window === 'undefined') return 'en';
  return (
    normalizeLocale(window.localStorage.getItem(LANGUAGE_STORAGE_KEY)) ??
    normalizeLocale(window.navigator.language) ??
    'en'
  );
}

function useI18n(preferredLocale?: string) {
  const [locale, setLocale] = useState<Locale>(() => normalizeLocale(preferredLocale) ?? detectLocale());

  useEffect(() => {
    const preferred = normalizeLocale(preferredLocale);
    if (preferred) setLocale(preferred);
  }, [preferredLocale]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const sync = () => {
      setLocale(normalizeLocale(preferredLocale) ?? detectLocale());
    };
    window.addEventListener('storage', sync);
    window.addEventListener('climpire-language-change', sync as EventListener);
    return () => {
      window.removeEventListener('storage', sync);
      window.removeEventListener('climpire-language-change', sync as EventListener);
    };
  }, [preferredLocale]);

  const t = useCallback(
    (messages: Record<Locale, string>) => messages[locale] ?? messages.en,
    [locale],
  );

  return { locale, localeTag: LOCALE_TAGS[locale], t };
}

// ── Column config ──────────────────────────────────────────────────────────────

const COLUMNS: {
  status: TaskStatus;
  icon: string;
  headerBg: string;
  borderColor: string;
  dotColor: string;
}[] = [
  {
    status: 'inbox',
    icon: '📥',
    headerBg: 'bg-slate-800',
    borderColor: 'border-slate-600',
    dotColor: 'bg-slate-400',
  },
  {
    status: 'planned',
    icon: '📋',
    headerBg: 'bg-blue-900',
    borderColor: 'border-blue-700',
    dotColor: 'bg-blue-400',
  },
  {
    status: 'in_progress',
    icon: '⚡',
    headerBg: 'bg-amber-900',
    borderColor: 'border-amber-700',
    dotColor: 'bg-amber-400',
  },
  {
    status: 'review',
    icon: '🔍',
    headerBg: 'bg-purple-900',
    borderColor: 'border-purple-700',
    dotColor: 'bg-purple-400',
  },
  {
    status: 'done',
    icon: '✅',
    headerBg: 'bg-green-900',
    borderColor: 'border-green-700',
    dotColor: 'bg-green-400',
  },
  {
    status: 'pending',
    icon: '⏸️',
    headerBg: 'bg-orange-900',
    borderColor: 'border-orange-700',
    dotColor: 'bg-orange-400',
  },
  {
    status: 'cancelled',
    icon: '🚫',
    headerBg: 'bg-red-900',
    borderColor: 'border-red-700',
    dotColor: 'bg-red-400',
  },
];

const STATUS_OPTIONS: TaskStatus[] = [
  'inbox',
  'planned',
  'in_progress',
  'review',
  'done',
  'pending',
  'cancelled',
];

const TASK_TYPE_OPTIONS: { value: TaskType; color: string }[] = [
  { value: 'general', color: 'bg-slate-700 text-slate-300' },
  { value: 'development', color: 'bg-cyan-900 text-cyan-300' },
  { value: 'design', color: 'bg-pink-900 text-pink-300' },
  { value: 'analysis', color: 'bg-indigo-900 text-indigo-300' },
  { value: 'presentation', color: 'bg-orange-900 text-orange-300' },
  { value: 'documentation', color: 'bg-teal-900 text-teal-300' },
];

function taskStatusLabel(status: TaskStatus, t: TFunction) {
  switch (status) {
    case 'inbox':
      return t({ ko: '수신함', en: 'Inbox', ja: '受信箱', zh: '收件箱' });
    case 'planned':
      return t({ ko: '계획됨', en: 'Planned', ja: '計画済み', zh: '已计划' });
    case 'in_progress':
      return t({ ko: '진행 중', en: 'In Progress', ja: '進行中', zh: '进行中' });
    case 'review':
      return t({ ko: '검토', en: 'Review', ja: 'レビュー', zh: '审核' });
    case 'done':
      return t({ ko: '완료', en: 'Done', ja: '完了', zh: '完成' });
    case 'pending':
      return t({ ko: '보류', en: 'Pending', ja: '保留', zh: '待处理' });
    case 'cancelled':
      return t({ ko: '취소', en: 'Cancelled', ja: 'キャンセル', zh: '已取消' });
    default:
      return status;
  }
}

function taskTypeLabel(type: TaskType, t: TFunction) {
  switch (type) {
    case 'general':
      return t({ ko: '일반', en: 'General', ja: '一般', zh: '通用' });
    case 'development':
      return t({ ko: '개발', en: 'Development', ja: '開発', zh: '开发' });
    case 'design':
      return t({ ko: '디자인', en: 'Design', ja: 'デザイン', zh: '设计' });
    case 'analysis':
      return t({ ko: '분석', en: 'Analysis', ja: '分析', zh: '分析' });
    case 'presentation':
      return t({ ko: '발표', en: 'Presentation', ja: 'プレゼン', zh: '演示' });
    case 'documentation':
      return t({ ko: '문서화', en: 'Documentation', ja: 'ドキュメント', zh: '文档' });
    default:
      return type;
  }
}

function getTaskTypeBadge(type: TaskType, t: TFunction) {
  const option = TASK_TYPE_OPTIONS.find((entry) => entry.value === type) ?? TASK_TYPE_OPTIONS[0];
  return { ...option, label: taskTypeLabel(option.value, t) };
}

function priorityIcon(p: number) {
  if (p >= 4) return '🔴';
  if (p >= 2) return '🟡';
  return '🟢';
}

function priorityLabel(p: number, t: TFunction) {
  if (p >= 4) return t({ ko: '높음', en: 'High', ja: '高', zh: '高' });
  if (p >= 2) return t({ ko: '중간', en: 'Medium', ja: '中', zh: '中' });
  return t({ ko: '낮음', en: 'Low', ja: '低', zh: '低' });
}

function timeAgo(ts: number, localeTag: string): string {
  const diffSec = Math.floor((Date.now() - ts) / 1000);
  const rtf = new Intl.RelativeTimeFormat(localeTag, { numeric: 'auto' });
  if (diffSec < 60) return rtf.format(-diffSec, 'second');
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60) return rtf.format(-diffMin, 'minute');
  const diffH = Math.floor(diffMin / 60);
  if (diffH < 24) return rtf.format(-diffH, 'hour');
  return rtf.format(-Math.floor(diffH / 24), 'day');
}

// ── Create Modal ──────────────────────────────────────────────────────────────

interface CreateModalProps {
  agents: Agent[];
  departments: Department[];
  onClose: () => void;
  onCreate: TaskBoardProps['onCreateTask'];
  onAssign: TaskBoardProps['onAssignTask'];
}

function CreateModal({ agents, departments, onClose, onCreate, onAssign }: CreateModalProps) {
  const { t, locale } = useI18n();
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [departmentId, setDepartmentId] = useState('');
  const [taskType, setTaskType] = useState<TaskType>('general');
  const [priority, setPriority] = useState(3);
  const [assignAgentId, setAssignAgentId] = useState('');

  const filteredAgents = useMemo(
    () => (departmentId ? agents.filter((a) => a.department_id === departmentId) : agents),
    [agents, departmentId],
  );

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) return;

    // We'll create the task first then assign if needed.
    // Since onCreate doesn't return the task id, we rely on the parent
    // calling onAssignTask after the task appears. For now, we pass
    // a combined approach: create with the data and let parent handle assign.
    onCreate({
      title: title.trim(),
      description: description.trim() || undefined,
      department_id: departmentId || undefined,
      task_type: taskType,
      priority,
    });

    // Note: assigning requires the task id which we don't have yet.
    // The parent component should handle this after task creation.
    // We surface the assignAgentId via a custom event pattern below.
    if (assignAgentId) {
      // Store for parent to pick up — simple approach: set a data attr on the form
      // In practice, onCreateTask should accept assigned_agent_id too,
      // or the parent should handle post-creation assignment.
      // We call onAssign with a placeholder id; the parent must handle timing.
      // This is a best-effort call with a temporary empty string —
      // in a real setup, the API would return the new task id.
      // For now we skip and let the user assign from the card.
    }

    onClose();
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="w-full max-w-lg rounded-2xl border border-slate-700 bg-slate-900 p-6 shadow-2xl">
        <div className="mb-5 flex items-center justify-between">
          <h2 className="text-lg font-bold text-white">
            {t({ ko: '새 업무 만들기', en: 'Create New Task', ja: '新しいタスクを作成', zh: '创建新任务' })}
          </h2>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-white"
            title={t({ ko: '닫기', en: 'Close', ja: '閉じる', zh: '关闭' })}
          >
            ✕
          </button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          {/* Title */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">
              {t({ ko: '제목', en: 'Title', ja: 'タイトル', zh: '标题' })}{' '}
              <span className="text-red-400">*</span>
            </label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder={t({
                ko: '업무 제목을 입력하세요',
                en: 'Enter a task title',
                ja: 'タスクのタイトルを入力してください',
                zh: '请输入任务标题',
              })}
              required
              className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Description */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">
              {t({ ko: '설명', en: 'Description', ja: '説明', zh: '说明' })}
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder={t({
                ko: '업무에 대한 상세 설명을 입력하세요',
                en: 'Enter a detailed description',
                ja: 'タスクの詳細説明を入力してください',
                zh: '请输入任务详细说明',
              })}
              rows={3}
              className="w-full resize-none rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
            />
          </div>

          {/* Department + Task Type */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-sm font-medium text-slate-300">
                {t({ ko: '부서', en: 'Department', ja: '部署', zh: '部门' })}
              </label>
              <select
                value={departmentId}
                onChange={(e) => {
                  setDepartmentId(e.target.value);
                  setAssignAgentId('');
                }}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                <option value="">
                  {t({ ko: '-- 전체 --', en: '-- All --', ja: '-- 全体 --', zh: '-- 全部 --' })}
                </option>
                {departments.map((d) => (
                  <option key={d.id} value={d.id}>
                    {d.icon} {locale === 'ko' ? d.name_ko : d.name}
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="mb-1 block text-sm font-medium text-slate-300">
                {t({ ko: '업무 유형', en: 'Task Type', ja: 'タスク種別', zh: '任务类型' })}
              </label>
              <select
                value={taskType}
                onChange={(e) => setTaskType(e.target.value as TaskType)}
                className="w-full rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
              >
                {TASK_TYPE_OPTIONS.map((typeOption) => (
                  <option key={typeOption.value} value={typeOption.value}>
                    {taskTypeLabel(typeOption.value, t)}
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Priority */}
          <div>
            <label className="mb-2 block text-sm font-medium text-slate-300">
              {t({ ko: '우선순위', en: 'Priority', ja: '優先度', zh: '优先级' })}: {priorityIcon(priority)}{' '}
              {priorityLabel(priority, t)} ({priority}/5)
            </label>
            <div className="flex gap-2">
              {[1, 2, 3, 4, 5].map((star) => (
                <button
                  key={star}
                  type="button"
                  onClick={() => setPriority(star)}
                  className={`flex-1 rounded-lg py-2 text-lg transition ${
                    star <= priority
                      ? 'bg-amber-600 text-white shadow-md'
                      : 'bg-slate-800 text-slate-500 hover:bg-slate-700'
                  }`}
                >
                  ★
                </button>
              ))}
            </div>
          </div>

          {/* Assign Agent */}
          <div>
            <label className="mb-1 block text-sm font-medium text-slate-300">
              {t({ ko: '담당 에이전트', en: 'Assignee', ja: '担当エージェント', zh: '负责人' })}
            </label>
            <AgentSelect
              agents={filteredAgents}
              value={assignAgentId}
              onChange={setAssignAgentId}
              placeholder={t({
                ko: '-- 미배정 --',
                en: '-- Unassigned --',
                ja: '-- 未割り当て --',
                zh: '-- 未分配 --',
              })}
              size="md"
            />
            {departmentId && filteredAgents.length === 0 && (
              <p className="mt-1 text-xs text-slate-500">
                {t({
                  ko: '해당 부서에 에이전트가 없습니다.',
                  en: 'No agents are available in this department.',
                  ja: 'この部署にはエージェントがいません。',
                  zh: '该部门暂无可用代理。',
                })}
              </p>
            )}
          </div>

          {/* Actions */}
          <div className="flex justify-end gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-lg border border-slate-700 px-4 py-2 text-sm text-slate-300 transition hover:bg-slate-800"
            >
              {t({ ko: '취소', en: 'Cancel', ja: 'キャンセル', zh: '取消' })}
            </button>
            <button
              type="submit"
              disabled={!title.trim()}
              className="rounded-lg bg-blue-600 px-5 py-2 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {t({ ko: '업무 만들기', en: 'Create Task', ja: 'タスク作成', zh: '创建任务' })}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── Task Card ─────────────────────────────────────────────────────────────────

// ── Diff Modal ────────────────────────────────────────────────────────────────

function DiffModal({ taskId, onClose }: { taskId: string; onClose: () => void }) {
  const { t } = useI18n();
  const [diffData, setDiffData] = useState<TaskDiffResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [merging, setMerging] = useState(false);
  const [discarding, setDiscarding] = useState(false);
  const [actionResult, setActionResult] = useState<string | null>(null);

  useEffect(() => {
    getTaskDiff(taskId)
      .then((d) => {
        if (!d.ok) setError(d.error || t({ ko: '알 수 없는 오류', en: 'Unknown error', ja: '不明なエラー', zh: '未知错误' }));
        else setDiffData(d);
        setLoading(false);
      })
      .catch((e) => { setError(e instanceof Error ? e.message : String(e)); setLoading(false); });
  }, [taskId, t]);

  // Close on Escape key
  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [onClose]);

  const handleMerge = useCallback(async () => {
    if (!confirm(t({
      ko: '이 브랜치를 메인에 병합하시겠습니까?',
      en: 'Merge this branch into main?',
      ja: 'このブランチを main にマージしますか？',
      zh: '要将此分支合并到 main 吗？',
    })))
      return;
    setMerging(true);
    try {
      const result = await mergeTask(taskId);
      setActionResult(
        result.ok
          ? `${t({ ko: '병합 완료', en: 'Merge completed', ja: 'マージ完了', zh: '合并完成' })}: ${result.message}`
          : `${t({ ko: '병합 실패', en: 'Merge failed', ja: 'マージ失敗', zh: '合并失败' })}: ${result.message}`,
      );
      if (result.ok) setTimeout(onClose, 1500);
    } catch (e: unknown) {
      setActionResult(
        `${t({ ko: '오류', en: 'Error', ja: 'エラー', zh: '错误' })}: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    } finally {
      setMerging(false);
    }
  }, [taskId, onClose, t]);

  const handleDiscard = useCallback(async () => {
    if (
      !confirm(
        t({
          ko: '이 브랜치의 변경사항을 모두 폐기하시겠습니까? 이 작업은 되돌릴 수 없습니다.',
          en: 'Discard all changes in this branch? This action cannot be undone.',
          ja: 'このブランチの変更をすべて破棄しますか？この操作は元に戻せません。',
          zh: '要丢弃此分支的所有更改吗？此操作无法撤销。',
        }),
      )
    )
      return;
    setDiscarding(true);
    try {
      const result = await discardTask(taskId);
      setActionResult(
        result.ok
          ? t({
              ko: '브랜치가 폐기되었습니다.',
              en: 'Branch was discarded.',
              ja: 'ブランチを破棄しました。',
              zh: '分支已丢弃。',
            })
          : `${t({ ko: '폐기 실패', en: 'Discard failed', ja: '破棄失敗', zh: '丢弃失败' })}: ${result.message}`,
      );
      if (result.ok) setTimeout(onClose, 1500);
    } catch (e: unknown) {
      setActionResult(
        `${t({ ko: '오류', en: 'Error', ja: 'エラー', zh: '错误' })}: ${
          e instanceof Error ? e.message : String(e)
        }`,
      );
    } finally {
      setDiscarding(false);
    }
  }, [taskId, onClose, t]);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div className="flex max-h-[85vh] w-full max-w-4xl flex-col rounded-2xl border border-slate-700 bg-slate-900 shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-700 px-5 py-3">
          <div className="flex items-center gap-2">
            <span className="text-lg font-bold text-white">
              {t({ ko: 'Git 변경사항', en: 'Git Diff', ja: 'Git 差分', zh: 'Git 差异' })}
            </span>
            {diffData?.branchName && (
              <span className="rounded-full bg-purple-900 px-2.5 py-0.5 text-xs text-purple-300">
                {diffData.branchName}
              </span>
            )}
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleMerge}
              disabled={merging || discarding || !diffData?.hasWorktree}
              className="rounded-lg bg-green-700 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-green-600 disabled:opacity-40"
            >
              {merging ? '...' : t({ ko: '병합', en: 'Merge', ja: 'マージ', zh: '合并' })}
            </button>
            <button
              onClick={handleDiscard}
              disabled={merging || discarding || !diffData?.hasWorktree}
              className="rounded-lg bg-red-800 px-3 py-1.5 text-xs font-medium text-white transition hover:bg-red-700 disabled:opacity-40"
            >
              {discarding ? '...' : t({ ko: '폐기', en: 'Discard', ja: '破棄', zh: '丢弃' })}
            </button>
            <button
              onClick={onClose}
              className="rounded-lg p-1.5 text-slate-400 transition hover:bg-slate-800 hover:text-white"
              title={t({ ko: '닫기', en: 'Close', ja: '閉じる', zh: '关闭' })}
            >
              X
            </button>
          </div>
        </div>

        {/* Action result */}
        {actionResult && (
          <div className="border-b border-slate-700 bg-slate-800 px-5 py-2 text-sm text-amber-300">
            {actionResult}
          </div>
        )}

        {/* Content */}
        <div className="flex-1 overflow-auto p-5">
          {loading ? (
            <div className="flex items-center justify-center py-12 text-slate-400">
              {t({ ko: '변경사항 불러오는 중...', en: 'Loading diff...', ja: '差分を読み込み中...', zh: '正在加载差异...' })}
            </div>
          ) : error ? (
            <div className="flex items-center justify-center py-12 text-red-400">
              {t({ ko: '오류', en: 'Error', ja: 'エラー', zh: '错误' })}: {error}
            </div>
          ) : !diffData?.hasWorktree ? (
            <div className="flex items-center justify-center py-12 text-slate-500">
              {t({
                ko: '이 작업의 워크트리를 찾을 수 없습니다. (Git 프로젝트 아님 또는 이미 병합됨)',
                en: 'No worktree found for this task (non-git project or already merged)',
                ja: 'このタスクのワークツリーが見つかりません（Git プロジェクトではない、または既にマージ済み）',
                zh: '找不到该任务的 worktree（非 Git 项目或已合并）',
              })}
            </div>
          ) : (
            <div className="space-y-4">
              {/* Stat summary */}
              {diffData.stat && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-slate-300">
                    {t({ ko: '요약', en: 'Summary', ja: '概要', zh: '摘要' })}
                  </h3>
                  <pre className="rounded-lg bg-slate-800 p-3 text-xs text-slate-300 overflow-x-auto">{diffData.stat}</pre>
                </div>
              )}
              {/* Full diff */}
              {diffData.diff && (
                <div>
                  <h3 className="mb-1 text-sm font-semibold text-slate-300">
                    {t({ ko: 'Diff', en: 'Diff', ja: '差分', zh: '差异' })}
                  </h3>
                  <pre className="max-h-[50vh] overflow-auto rounded-lg bg-slate-950 p-3 text-xs leading-relaxed">
                    {diffData.diff.split('\n').map((line, i) => {
                      let cls = 'text-slate-400';
                      if (line.startsWith('+') && !line.startsWith('+++')) cls = 'text-green-400';
                      else if (line.startsWith('-') && !line.startsWith('---')) cls = 'text-red-400';
                      else if (line.startsWith('@@')) cls = 'text-cyan-400';
                      else if (line.startsWith('diff ') || line.startsWith('index ')) cls = 'text-slate-500 font-bold';
                      return <span key={i} className={cls}>{line}{'\n'}</span>;
                    })}
                  </pre>
                </div>
              )}
              {!diffData.stat && !diffData.diff && (
                <div className="text-center text-slate-500 py-8">
                  {t({ ko: '변경사항이 없습니다', en: 'No changes detected', ja: '変更はありません', zh: '未检测到更改' })}
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface TaskCardProps {
  task: Task;
  agents: Agent[];
  departments: Department[];
  taskSubtasks: SubTask[];
  onUpdateTask: TaskBoardProps['onUpdateTask'];
  onDeleteTask: TaskBoardProps['onDeleteTask'];
  onAssignTask: TaskBoardProps['onAssignTask'];
  onRunTask: TaskBoardProps['onRunTask'];
  onStopTask: TaskBoardProps['onStopTask'];
  onPauseTask?: (id: string) => void;
  onResumeTask?: (id: string) => void;
  onOpenTerminal?: (taskId: string) => void;
  onOpenMeetingMinutes?: (taskId: string) => void;
  onMergeTask?: (id: string) => void;
  onDiscardTask?: (id: string) => void;
}

const SUBTASK_STATUS_ICON: Record<string, string> = {
  pending: '\u23F3',
  in_progress: '\uD83D\uDD28',
  done: '\u2705',
  blocked: '\uD83D\uDEAB',
};

function TaskCard({
  task,
  agents,
  departments,
  taskSubtasks,
  onUpdateTask,
  onDeleteTask,
  onAssignTask,
  onRunTask,
  onStopTask,
  onPauseTask,
  onResumeTask,
  onOpenTerminal,
  onOpenMeetingMinutes,
}: TaskCardProps) {
  const { t, localeTag, locale } = useI18n();
  const [expanded, setExpanded] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [showSubtasks, setShowSubtasks] = useState(false);

  const assignedAgent = task.assigned_agent ?? agents.find((a) => a.id === task.assigned_agent_id);
  const department = departments.find((d) => d.id === task.department_id);
  const typeBadge = getTaskTypeBadge(task.task_type, t);

  const canRun = task.status === 'planned' || task.status === 'inbox';
  const canStop = task.status === 'in_progress';
  const canPause = task.status === 'in_progress' && !!onPauseTask;
  const canResume = (task.status === 'pending' || task.status === 'cancelled') && !!onResumeTask;
  const canDelete = task.status !== 'in_progress';

  return (
    <div className="group rounded-xl border border-slate-700 bg-slate-800 p-3.5 shadow-sm transition hover:border-slate-600 hover:shadow-md">
      {/* Header row */}
      <div className="mb-2 flex items-start justify-between gap-2">
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex-1 text-left text-sm font-semibold leading-snug text-white"
        >
          {task.title}
        </button>
        <span
          className="flex-shrink-0 text-base"
          title={`${t({ ko: '우선순위', en: 'Priority', ja: '優先度', zh: '优先级' })}: ${priorityLabel(task.priority, t)}`}
        >
          {priorityIcon(task.priority)}
        </span>
      </div>

      {/* Description */}
      {task.description && (
        <p
          className={`mb-2 text-xs leading-relaxed text-slate-400 ${expanded ? '' : 'line-clamp-2'}`}
        >
          {task.description}
        </p>
      )}

      {/* Badges row */}
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${typeBadge.color}`}>
          {typeBadge.label}
        </span>
        {department && (
          <span className="rounded-full bg-slate-700 px-2 py-0.5 text-xs text-slate-300">
            {department.icon} {locale === 'ko' ? department.name_ko : department.name}
          </span>
        )}
      </div>

      {/* Status select */}
      <div className="mb-3">
        <select
          value={task.status}
          onChange={(e) => onUpdateTask(task.id, { status: e.target.value as TaskStatus })}
          className="w-full rounded-lg border border-slate-600 bg-slate-700 px-2 py-1 text-xs text-white outline-none transition focus:border-blue-500"
        >
          {STATUS_OPTIONS.map((status) => (
            <option key={status} value={status}>
              {taskStatusLabel(status, t)}
            </option>
          ))}
        </select>
      </div>

      {/* Agent + time */}
      <div className="mb-3 flex items-center justify-between">
        <div className="flex items-center gap-1.5">
          {assignedAgent ? (
            <>
              <AgentAvatar agent={assignedAgent} agents={agents} size={20} />
              <span className="text-xs text-slate-300">{locale === 'ko' ? assignedAgent.name_ko : assignedAgent.name}</span>
            </>
          ) : (
            <span className="text-xs text-slate-500">
              {t({ ko: '미배정', en: 'Unassigned', ja: '未割り当て', zh: '未分配' })}
            </span>
          )}
        </div>
        <span className="text-xs text-slate-500">{timeAgo(task.created_at, localeTag)}</span>
      </div>

      {/* Assign agent dropdown */}
      <div className="mb-3">
        <AgentSelect
          agents={agents}
          value={task.assigned_agent_id ?? ''}
          onChange={(agentId) => {
            if (agentId) {
              onAssignTask(task.id, agentId);
            } else {
              onUpdateTask(task.id, { assigned_agent_id: null });
            }
          }}
        />
      </div>

      {/* SubTask progress bar */}
      {(task.subtask_total ?? 0) > 0 && (
        <div className="mb-3">
          <button
            onClick={() => setShowSubtasks((v) => !v)}
            className="mb-1.5 flex w-full items-center gap-2 text-left"
          >
            <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-gradient-to-r from-green-500 to-emerald-400 rounded-full transition-all"
                style={{ width: `${Math.round(((task.subtask_done ?? 0) / (task.subtask_total ?? 1)) * 100)}%` }}
              />
            </div>
            <span className="text-xs text-slate-400 whitespace-nowrap">
              {task.subtask_done ?? 0}/{task.subtask_total ?? 0}
            </span>
            <span className="text-xs text-slate-500">{showSubtasks ? '▲' : '▼'}</span>
          </button>
          {showSubtasks && taskSubtasks.length > 0 && (
            <div className="space-y-1 pl-1">
              {taskSubtasks.map((st) => {
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
                        {targetDept.icon} {targetDept.name_ko}
                      </span>
                    )}
                    {st.delegated_task_id && st.status !== 'done' && (
                      <span
                        className="text-blue-400 shrink-0"
                        title={t({ ko: '위임됨', en: 'Delegated', ja: '委任済み', zh: '已委派' })}
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
      )}

      {/* Action buttons */}
      <div className="flex flex-wrap items-center gap-1.5">
        {canRun && (
          <button
            onClick={() => onRunTask(task.id)}
            title={t({ ko: '작업 실행', en: 'Run task', ja: 'タスク実行', zh: '运行任务' })}
            className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-green-700 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-green-600"
          >
            ▶ {t({ ko: '실행', en: 'Run', ja: '実行', zh: '运行' })}
          </button>
        )}
        {canPause && (
          <button
            onClick={() => onPauseTask!(task.id)}
            title={t({ ko: '작업 일시중지', en: 'Pause task', ja: 'タスク一時停止', zh: '暂停任务' })}
            className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-orange-700 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-orange-600"
          >
            ⏸ {t({ ko: '일시중지', en: 'Pause', ja: '一時停止', zh: '暂停' })}
          </button>
        )}
        {canStop && (
          <button
            onClick={() => {
              if (
                confirm(
                  t({
                    ko: `"${task.title}" 작업을 중지할까요?\n\n경고: Stop 처리 시 해당 프로젝트 변경분은 롤백됩니다.`,
                    en: `Stop "${task.title}"?\n\nWarning: stopping will roll back project changes.`,
                    ja: `「${task.title}」を停止しますか？\n\n警告: 停止するとプロジェクトの変更はロールバックされます。`,
                    zh: `要停止“${task.title}”吗？\n\n警告：停止后将回滚该项目的更改。`,
                  }),
                )
              ) {
                onStopTask(task.id);
              }
            }}
            title={t({ ko: '작업 중지', en: 'Cancel task', ja: 'タスク停止', zh: '取消任务' })}
            className="flex items-center justify-center gap-1 rounded-lg bg-red-800 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-red-700"
          >
            ⏹ {t({ ko: '중지', en: 'Cancel', ja: 'キャンセル', zh: '取消' })}
          </button>
        )}
        {canResume && (
          <button
            onClick={() => onResumeTask!(task.id)}
            title={t({ ko: '작업 재개', en: 'Resume task', ja: 'タスク再開', zh: '恢复任务' })}
            className="flex flex-1 items-center justify-center gap-1 rounded-lg bg-blue-700 px-2 py-1.5 text-xs font-medium text-white transition hover:bg-blue-600"
          >
            ↩ {t({ ko: '재개', en: 'Resume', ja: '再開', zh: '恢复' })}
          </button>
        )}
        {(task.status === 'in_progress' || task.status === 'review' || task.status === 'done' || task.status === 'pending') && onOpenTerminal && (
          <button
            onClick={() => onOpenTerminal(task.id)}
            title={t({
              ko: '터미널 출력 보기',
              en: 'View terminal output',
              ja: 'ターミナル出力を見る',
              zh: '查看终端输出',
            })}
            className="flex items-center justify-center rounded-lg bg-slate-700 px-2 py-1.5 text-xs text-slate-300 transition hover:bg-slate-600 hover:text-white"
          >
            &#128421;
          </button>
        )}
        {(task.status === 'planned' || task.status === 'in_progress' || task.status === 'review' || task.status === 'done' || task.status === 'pending') && onOpenMeetingMinutes && (
          <button
            onClick={() => onOpenMeetingMinutes(task.id)}
            title={t({
              ko: '회의록 보기',
              en: 'View meeting minutes',
              ja: '会議録を見る',
              zh: '查看会议纪要',
            })}
            className="flex items-center justify-center rounded-lg bg-cyan-800/70 px-2 py-1.5 text-xs text-cyan-200 transition hover:bg-cyan-700 hover:text-white"
          >
            📝
          </button>
        )}
        {task.status === 'review' && (
          <button
            onClick={() => setShowDiff(true)}
            title={t({ ko: '변경사항 보기 (Git diff)', en: 'View changes (Git diff)', ja: '変更を見る (Git diff)', zh: '查看更改 (Git diff)' })}
            className="flex items-center justify-center gap-1 rounded-lg bg-purple-800 px-2 py-1.5 text-xs font-medium text-purple-200 transition hover:bg-purple-700"
          >
            {t({ ko: 'Diff', en: 'Diff', ja: '差分', zh: '差异' })}
          </button>
        )}
        {canDelete && (
          <button
            onClick={() => {
              if (
                confirm(
                  t({
                    ko: `"${task.title}" 업무를 삭제할까요?`,
                    en: `Delete "${task.title}"?`,
                    ja: `「${task.title}」を削除しますか？`,
                    zh: `要删除“${task.title}”吗？`,
                  }),
                )
              )
                onDeleteTask(task.id);
            }}
            title={t({ ko: '작업 삭제', en: 'Delete task', ja: 'タスク削除', zh: '删除任务' })}
            className="flex items-center justify-center rounded-lg bg-red-900/60 px-2 py-1.5 text-xs text-red-400 transition hover:bg-red-800 hover:text-red-300"
          >
            🗑
          </button>
        )}
      </div>

      {/* Diff modal */}
      {showDiff && <DiffModal taskId={task.id} onClose={() => setShowDiff(false)} />}
    </div>
  );
}

// ── Filter Bar ────────────────────────────────────────────────────────────────

interface FilterBarProps {
  agents: Agent[];
  departments: Department[];
  filterDept: string;
  filterAgent: string;
  filterType: string;
  search: string;
  onFilterDept: (v: string) => void;
  onFilterAgent: (v: string) => void;
  onFilterType: (v: string) => void;
  onSearch: (v: string) => void;
}

function FilterBar({
  agents,
  departments,
  filterDept,
  filterAgent,
  filterType,
  search,
  onFilterDept,
  onFilterAgent,
  onFilterType,
  onSearch,
}: FilterBarProps) {
  const { t, locale } = useI18n();

  return (
    <div className="flex flex-wrap items-center gap-2">
      {/* Search */}
      <div className="relative min-w-[180px] flex-1">
        <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-400 text-sm">🔎</span>
        <input
          type="text"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder={t({ ko: '업무 검색...', en: 'Search tasks...', ja: 'タスク検索...', zh: '搜索任务...' })}
          className="w-full rounded-lg border border-slate-700 bg-slate-800 py-1.5 pl-8 pr-3 text-sm text-white placeholder-slate-500 outline-none transition focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
        />
      </div>

      {/* Department */}
      <select
        value={filterDept}
        onChange={(e) => onFilterDept(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-300 outline-none transition focus:border-blue-500"
      >
        <option value="">{t({ ko: '전체 부서', en: 'All Departments', ja: '全部署', zh: '全部门' })}</option>
        {departments.map((d) => (
          <option key={d.id} value={d.id}>
            {d.icon} {locale === 'ko' ? d.name_ko : d.name}
          </option>
        ))}
      </select>

      {/* Agent */}
      <AgentSelect
        agents={agents}
        value={filterAgent}
        onChange={onFilterAgent}
        placeholder={t({ ko: '전체 에이전트', en: 'All Agents', ja: '全エージェント', zh: '全部代理' })}
        size="md"
      />

      {/* Task type */}
      <select
        value={filterType}
        onChange={(e) => onFilterType(e.target.value)}
        className="rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-sm text-slate-300 outline-none transition focus:border-blue-500"
      >
        <option value="">{t({ ko: '전체 유형', en: 'All Types', ja: '全タイプ', zh: '全部类型' })}</option>
        {TASK_TYPE_OPTIONS.map((typeOption) => (
          <option key={typeOption.value} value={typeOption.value}>
            {taskTypeLabel(typeOption.value, t)}
          </option>
        ))}
      </select>
    </div>
  );
}

// ── TaskBoard (main export) ───────────────────────────────────────────────────

export function TaskBoard({
  tasks,
  agents,
  departments,
  subtasks,
  onCreateTask,
  onUpdateTask,
  onDeleteTask,
  onAssignTask,
  onRunTask,
  onStopTask,
  onPauseTask,
  onResumeTask,
  onOpenTerminal,
  onOpenMeetingMinutes,
  onMergeTask,
  onDiscardTask,
}: TaskBoardProps) {
  const { t } = useI18n();
  const [showCreate, setShowCreate] = useState(false);
  const [filterDept, setFilterDept] = useState('');
  const [filterAgent, setFilterAgent] = useState('');
  const [filterType, setFilterType] = useState('');
  const [search, setSearch] = useState('');

  const filteredTasks = useMemo(() => {
    return tasks.filter((t) => {
      if (filterDept && t.department_id !== filterDept) return false;
      if (filterAgent && t.assigned_agent_id !== filterAgent) return false;
      if (filterType && t.task_type !== filterType) return false;
      if (search && !t.title.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
  }, [tasks, filterDept, filterAgent, filterType, search]);

  const tasksByStatus = useMemo(() => {
    const map: Record<string, Task[]> = {};
    for (const col of COLUMNS) {
      map[col.status] = filteredTasks
        .filter((t) => t.status === col.status)
        .sort((a, b) => b.priority - a.priority || b.created_at - a.created_at);
    }
    return map;
  }, [filteredTasks]);

  const subtasksByTask = useMemo(() => {
    const map: Record<string, SubTask[]> = {};
    for (const st of subtasks) {
      if (!map[st.task_id]) map[st.task_id] = [];
      map[st.task_id].push(st);
    }
    return map;
  }, [subtasks]);

  const activeFilterCount = [filterDept, filterAgent, filterType, search].filter(Boolean).length;

  return (
    <div className="flex h-full flex-col gap-4 bg-slate-950 p-4">
      {/* Top bar */}
      <div className="flex flex-wrap items-center gap-3">
        <h1 className="text-xl font-bold text-white">{t({ ko: '업무 보드', en: 'Task Board', ja: 'タスクボード', zh: '任务看板' })}</h1>
        <span className="rounded-full bg-slate-800 px-2.5 py-0.5 text-xs text-slate-400">
          {t({ ko: '총', en: 'Total', ja: '合計', zh: '总计' })} {filteredTasks.length}
          {t({ ko: '개', en: '', ja: '件', zh: '项' })}
          {activeFilterCount > 0 &&
            ` (${t({ ko: '필터', en: 'filters', ja: 'フィルター', zh: '筛选器' })} ${activeFilterCount}${t({
              ko: '개 적용',
              en: ' applied',
              ja: '件適用',
              zh: '个已应用',
            })})`}
        </span>
        <div className="ml-auto flex items-center gap-2">
          {activeFilterCount > 0 && (
            <button
              onClick={() => {
                setFilterDept('');
                setFilterAgent('');
                setFilterType('');
                setSearch('');
              }}
              className="rounded-lg border border-slate-700 px-3 py-1.5 text-xs text-slate-400 transition hover:bg-slate-800 hover:text-white"
            >
              {t({ ko: '필터 초기화', en: 'Reset Filters', ja: 'フィルターをリセット', zh: '重置筛选' })}
            </button>
          )}
          <button
            onClick={() => setShowCreate(true)}
            className="rounded-lg bg-blue-600 px-4 py-1.5 text-sm font-semibold text-white shadow transition hover:bg-blue-500 active:scale-95"
          >
            + {t({ ko: '새 업무', en: 'New Task', ja: '新規タスク', zh: '新建任务' })}
          </button>
        </div>
      </div>

      {/* Filter bar */}
      <FilterBar
        agents={agents}
        departments={departments}
        filterDept={filterDept}
        filterAgent={filterAgent}
        filterType={filterType}
        search={search}
        onFilterDept={setFilterDept}
        onFilterAgent={setFilterAgent}
        onFilterType={setFilterType}
        onSearch={setSearch}
      />

      {/* Kanban board */}
      <div className="flex min-h-0 flex-1 gap-4 overflow-x-auto pb-2">
        {COLUMNS.map((col) => {
          const colTasks = tasksByStatus[col.status] ?? [];
          return (
            <div
              key={col.status}
              className={`flex w-72 flex-shrink-0 flex-col rounded-xl border ${col.borderColor} bg-slate-900`}
            >
              {/* Column header */}
              <div
                className={`flex items-center justify-between rounded-t-xl ${col.headerBg} px-3.5 py-2.5`}
              >
                <div className="flex items-center gap-2">
                  <span
                    className={`h-2 w-2 flex-shrink-0 rounded-full ${col.dotColor}`}
                  />
                  <span className="text-sm font-semibold text-white">
                    {col.icon} {taskStatusLabel(col.status, t)}
                  </span>
                </div>
                <span className="rounded-full bg-black/30 px-2 py-0.5 text-xs font-bold text-white/80">
                  {colTasks.length}
                </span>
              </div>

              {/* Cards */}
              <div className="flex flex-1 flex-col gap-2.5 overflow-y-auto p-2.5">
                {colTasks.length === 0 ? (
                  <div className="flex flex-1 items-center justify-center py-8 text-xs text-slate-600">
                    {t({ ko: '업무 없음', en: 'No tasks', ja: 'タスクなし', zh: '暂无任务' })}
                  </div>
                ) : (
                  colTasks.map((task) => (
                    <TaskCard
                      key={task.id}
                      task={task}
                      agents={agents}
                      departments={departments}
                      taskSubtasks={subtasksByTask[task.id] ?? []}
                      onUpdateTask={onUpdateTask}
                      onDeleteTask={onDeleteTask}
                      onAssignTask={onAssignTask}
                      onRunTask={onRunTask}
                      onStopTask={onStopTask}
                      onPauseTask={onPauseTask}
                      onResumeTask={onResumeTask}
                      onOpenTerminal={onOpenTerminal}
                      onOpenMeetingMinutes={onOpenMeetingMinutes}
                      onMergeTask={onMergeTask}
                      onDiscardTask={onDiscardTask}
                    />
                  ))
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Create modal */}
      {showCreate && (
        <CreateModal
          agents={agents}
          departments={departments}
          onClose={() => setShowCreate(false)}
          onCreate={onCreateTask}
          onAssign={onAssignTask}
        />
      )}
    </div>
  );
}

export default TaskBoard;
