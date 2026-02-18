import { useEffect, useMemo, useState, useCallback } from 'react';
import type { CompanyStats, Agent, Task } from '../types';
import AgentAvatar from './AgentAvatar';

interface DashboardProps {
  stats: CompanyStats | null;
  agents: Agent[];
  tasks: Task[];
  companyName: string;
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

  const t = useCallback((messages: Record<Locale, string>) => messages[locale] ?? messages.en, [locale]);

  return { locale, localeTag: LOCALE_TAGS[locale], t };
}

function useNow(localeTag: string, t: TFunction) {
  const [now, setNow] = useState(() => new Date());

  useEffect(() => {
    const timer = window.setInterval(() => {
      setNow(new Date());
    }, 30000);
    return () => window.clearInterval(timer);
  }, []);

  const date = now.toLocaleDateString(localeTag, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    weekday: 'long',
  });

  const time = now.toLocaleTimeString(localeTag, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });

  const hour = now.getHours();
  const briefing =
    hour < 12
      ? t({ ko: '오전 브리핑', en: 'Morning Briefing', ja: '午前ブリーフィング', zh: '上午简报' })
      : hour < 18
        ? t({ ko: '오후 운영 점검', en: 'Afternoon Ops Check', ja: '午後運用点検', zh: '下午运行检查' })
        : t({ ko: '저녁 마감 점검', en: 'Evening Wrap-up', ja: '夜間締め点検', zh: '晚间收尾检查' });

  return { date, time, briefing };
}

function timeAgo(timestamp: number, localeTag: string): string {
  const seconds = Math.floor((Date.now() - timestamp) / 1000);
  const rtf = new Intl.RelativeTimeFormat(localeTag, { numeric: 'auto' });
  if (seconds < 60) return rtf.format(-seconds, 'second');
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return rtf.format(-minutes, 'minute');
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return rtf.format(-hours, 'hour');
  const days = Math.floor(hours / 24);
  return rtf.format(-days, 'day');
}

// ─── RANK TIER SYSTEM ───
const RANK_TIERS = [
  { name: 'BRONZE',   nameKo: '브론즈',   minXp: 0,     color: '#CD7F32', glow: 'rgba(205,127,50,0.35)', icon: '⚔️' },
  { name: 'SILVER',   nameKo: '실버',     minXp: 100,   color: '#C0C0C0', glow: 'rgba(192,192,192,0.35)', icon: '🛡️' },
  { name: 'GOLD',     nameKo: '골드',     minXp: 500,   color: '#FFD700', glow: 'rgba(255,215,0,0.35)',   icon: '⭐' },
  { name: 'PLATINUM', nameKo: '플래티넘', minXp: 2000,  color: '#00c8b4', glow: 'rgba(0,200,180,0.35)',   icon: '💎' },
  { name: 'DIAMOND',  nameKo: '다이아',   minXp: 5000,  color: '#7df9ff', glow: 'rgba(125,249,255,0.35)', icon: '💠' },
  { name: 'MASTER',   nameKo: '마스터',   minXp: 15000, color: '#c45ff6', glow: 'rgba(196,95,246,0.35)',  icon: '👑' },
];

function getRankTier(xp: number) {
  for (let i = RANK_TIERS.length - 1; i >= 0; i--) {
    if (xp >= RANK_TIERS[i].minXp) return { ...RANK_TIERS[i], level: i };
  }
  return { ...RANK_TIERS[0], level: 0 };
}

const STATUS_LABELS: Record<string, { color: string; dot: string }> = {
  inbox:       { color: 'bg-slate-500/20 text-slate-200 border-slate-400/30', dot: 'bg-slate-400' },
  planned:     { color: 'bg-blue-500/20 text-blue-100 border-blue-400/30',   dot: 'bg-blue-400' },
  in_progress: { color: 'bg-amber-500/20 text-amber-100 border-amber-400/30', dot: 'bg-amber-400' },
  review:      { color: 'bg-violet-500/20 text-violet-100 border-violet-400/30', dot: 'bg-violet-400' },
  done:        { color: 'bg-emerald-500/20 text-emerald-100 border-emerald-400/30', dot: 'bg-emerald-400' },
  pending:     { color: 'bg-orange-500/20 text-orange-100 border-orange-400/30', dot: 'bg-orange-400' },
  cancelled:   { color: 'bg-rose-500/20 text-rose-100 border-rose-400/30',   dot: 'bg-rose-400' },
};

function taskStatusLabel(status: string, t: TFunction) {
  switch (status) {
    case 'inbox':
      return t({ ko: '수신함', en: 'Inbox', ja: '受信箱', zh: '收件箱' });
    case 'planned':
      return t({ ko: '계획됨', en: 'Planned', ja: '計画済み', zh: '已计划' });
    case 'in_progress':
      return t({ ko: '진행 중', en: 'In Progress', ja: '進行中', zh: '进行中' });
    case 'review':
      return t({ ko: '검토 중', en: 'Review', ja: 'レビュー', zh: '审核' });
    case 'done':
      return t({ ko: '완료', en: 'Done', ja: '完了', zh: '完成' });
    case 'pending':
      return t({ ko: '보류', en: 'Pending', ja: '保留', zh: '待处理' });
    case 'cancelled':
      return t({ ko: '취소됨', en: 'Cancelled', ja: 'キャンセル', zh: '已取消' });
    default:
      return status;
  }
}

const DEPT_COLORS = [
  { bar: 'from-blue-500 to-cyan-400', badge: 'bg-blue-500/20 text-blue-200 border-blue-400/30' },
  { bar: 'from-violet-500 to-fuchsia-400', badge: 'bg-violet-500/20 text-violet-200 border-violet-400/30' },
  { bar: 'from-emerald-500 to-teal-400', badge: 'bg-emerald-500/20 text-emerald-200 border-emerald-400/30' },
  { bar: 'from-amber-500 to-orange-400', badge: 'bg-amber-500/20 text-amber-100 border-amber-400/30' },
  { bar: 'from-rose-500 to-pink-400', badge: 'bg-rose-500/20 text-rose-100 border-rose-400/30' },
  { bar: 'from-cyan-500 to-sky-400', badge: 'bg-cyan-500/20 text-cyan-100 border-cyan-400/30' },
  { bar: 'from-orange-500 to-red-400', badge: 'bg-orange-500/20 text-orange-100 border-orange-400/30' },
  { bar: 'from-teal-500 to-lime-400', badge: 'bg-teal-500/20 text-teal-100 border-teal-400/30' },
];

// ─── XP Progress Bar ───
function XpBar({ xp, maxXp, color }: { xp: number; maxXp: number; color: string }) {
  const pct = maxXp > 0 ? Math.min(100, Math.round((xp / maxXp) * 100)) : 0;
  return (
    <div className="relative h-2.5 w-full overflow-hidden rounded-full border border-white/[0.08] bg-white/[0.04]">
      <div
        className="xp-bar-fill h-full rounded-full transition-all duration-1000 ease-out"
        style={{
          width: `${pct}%`,
          background: `linear-gradient(90deg, ${color}88, ${color})`,
          boxShadow: `0 0 8px ${color}60`,
        }}
      />
    </div>
  );
}

// ─── Rank Badge ───
function RankBadge({ xp, size = 'md' }: { xp: number; size?: 'sm' | 'md' | 'lg' }) {
  const tier = getRankTier(xp);
  const sizeClasses = {
    sm: 'px-1.5 py-0.5 text-[8px] gap-0.5',
    md: 'px-2 py-0.5 text-[10px] gap-1',
    lg: 'px-3 py-1 text-xs gap-1',
  };
  return (
    <span
      className={`inline-flex items-center rounded-md font-black uppercase tracking-wider ${sizeClasses[size]}`}
      style={{
        background: tier.glow,
        color: tier.color,
        border: `1px solid ${tier.color}50`,
        boxShadow: `0 0 8px ${tier.glow}`,
        textShadow: `0 0 6px ${tier.glow}`,
      }}
    >
      {tier.icon} {tier.name}
    </span>
  );
}

export default function Dashboard({ stats, agents, tasks, companyName }: DashboardProps) {
  const { t, locale, localeTag } = useI18n();
  const { date, time, briefing } = useNow(localeTag, t);
  const agentMap = useMemo(() => new Map(agents.map((a) => [a.id, a])), [agents]);
  const numberFormatter = useMemo(() => new Intl.NumberFormat(localeTag), [localeTag]);

  // ─── Stats (same logic) ───
  const totalTasks = stats?.tasks?.total ?? tasks.length;
  const completedTasks = stats?.tasks?.done ?? tasks.filter((t) => t.status === 'done').length;
  const inProgressTasks = stats?.tasks?.in_progress ?? tasks.filter((t) => t.status === 'in_progress').length;
  const plannedTasks = stats?.tasks?.planned ?? tasks.filter((t) => t.status === 'planned').length;
  const reviewTasks = stats?.tasks?.review ?? tasks.filter((t) => t.status === 'review').length;
  const pendingTasks = tasks.filter((t) => t.status === 'pending').length;
  const activeAgents = stats?.agents?.working ?? agents.filter((a) => a.status === 'working').length;
  const idleAgents = stats?.agents?.idle ?? agents.filter((a) => a.status === 'idle').length;
  const totalAgents = stats?.agents?.total ?? agents.length;
  const completionRate = stats?.tasks?.completion_rate ?? (totalTasks > 0 ? Math.round((completedTasks / totalTasks) * 100) : 0);
  const activeRate = totalAgents > 0 ? Math.round((activeAgents / totalAgents) * 100) : 0;
  const reviewQueue = reviewTasks + pendingTasks;

  // ─── Department data (same logic) ───
  const deptData = useMemo(() => {
    if (stats?.tasks_by_department && stats.tasks_by_department.length > 0) {
      return stats.tasks_by_department
        .map((d, i) => ({
          id: d.id,
          name: d.name,
          icon: d.icon ?? '🏢',
          done: d.done_tasks,
          total: d.total_tasks,
          ratio: d.total_tasks > 0 ? Math.round((d.done_tasks / d.total_tasks) * 100) : 0,
          color: DEPT_COLORS[i % DEPT_COLORS.length],
        }))
        .sort((a, b) => b.ratio - a.ratio || b.total - a.total);
    }

    const deptMap = new Map<string, { name: string; icon: string; done: number; total: number }>();
    for (const agent of agents) {
      if (!agent.department_id) continue;
      if (!deptMap.has(agent.department_id)) {
        deptMap.set(agent.department_id, {
          name:
            locale === 'ko'
              ? agent.department?.name_ko ?? agent.department?.name ?? agent.department_id
              : agent.department?.name ?? agent.department?.name_ko ?? agent.department_id,
          icon: agent.department?.icon ?? '🏢',
          done: 0,
          total: 0,
        });
      }
    }
    for (const task of tasks) {
      if (!task.department_id) continue;
      const entry = deptMap.get(task.department_id);
      if (!entry) continue;
      entry.total += 1;
      if (task.status === 'done') entry.done += 1;
    }
    return Array.from(deptMap.entries())
      .map(([id, value], i) => ({
        id,
        ...value,
        ratio: value.total > 0 ? Math.round((value.done / value.total) * 100) : 0,
        color: DEPT_COLORS[i % DEPT_COLORS.length],
      }))
      .sort((a, b) => b.ratio - a.ratio || b.total - a.total);
  }, [stats, agents, tasks, locale]);

  // ─── Top agents (same logic) ───
  const topAgents = useMemo(() => {
    if (stats?.top_agents && stats.top_agents.length > 0) {
      return stats.top_agents.slice(0, 5).map((topAgent) => {
        const agent = agentMap.get(topAgent.id);
        return {
          id: topAgent.id,
          name: locale === 'ko' ? agent?.name_ko ?? agent?.name ?? topAgent.name : agent?.name ?? agent?.name_ko ?? topAgent.name,
          department:
            locale === 'ko'
              ? agent?.department?.name_ko ?? agent?.department?.name ?? ''
              : agent?.department?.name ?? agent?.department?.name_ko ?? '',
          tasksDone: topAgent.stats_tasks_done,
          xp: topAgent.stats_xp,
        };
      });
    }
    return [...agents]
      .sort((a, b) => b.stats_xp - a.stats_xp)
      .slice(0, 5)
      .map((agent) => ({
        id: agent.id,
        name: locale === 'ko' ? agent.name_ko ?? agent.name : agent.name ?? agent.name_ko,
        department:
          locale === 'ko'
            ? agent.department?.name_ko ?? agent.department?.name ?? ''
            : agent.department?.name ?? agent.department?.name_ko ?? '',
        tasksDone: agent.stats_tasks_done,
        xp: agent.stats_xp,
      }));
  }, [stats, agents, agentMap, locale]);

  const maxXp = topAgents.length > 0 ? Math.max(...topAgents.map((a) => a.xp), 1) : 1;

  const recentTasks = useMemo(
    () => [...tasks].sort((a, b) => b.updated_at - a.updated_at).slice(0, 6),
    [tasks]
  );

  const workingAgents = agents.filter((a) => a.status === 'working');
  const idleAgentsList = agents.filter((a) => a.status === 'idle');

  // Podium: [2nd, 1st, 3rd]
  const podiumOrder =
    topAgents.length >= 3
      ? [topAgents[1], topAgents[0], topAgents[2]]
      : topAgents.length === 2
      ? [topAgents[1], topAgents[0]]
      : topAgents;

  const STATUS_LEFT_BORDER: Record<string, string> = {
    inbox:       'border-l-slate-400',
    planned:     'border-l-blue-400',
    in_progress: 'border-l-amber-400',
    review:      'border-l-violet-400',
    done:        'border-l-emerald-400',
    pending:     'border-l-orange-400',
    cancelled:   'border-l-rose-400',
  };

  // ─── HUD Stats ───
  const hudStats = [
    {
      id: 'total',
      label: t({ ko: '미션', en: 'MISSIONS', ja: 'ミッション', zh: '任务' }),
      value: totalTasks,
      sub: t({ ko: '누적 태스크', en: 'Total tasks', ja: '累積タスク', zh: '累计任务' }),
      color: '#3b82f6',
      icon: '📋',
    },
    {
      id: 'clear',
      label: t({ ko: '완료율', en: 'CLEAR RATE', ja: 'クリア率', zh: '完成率' }),
      value: `${completionRate}%`,
      sub: `${numberFormatter.format(completedTasks)} ${t({ ko: '클리어', en: 'cleared', ja: 'クリア', zh: '完成' })}`,
      color: '#10b981',
      icon: '✅',
    },
    {
      id: 'squad',
      label: t({ ko: '스쿼드', en: 'SQUAD', ja: 'スクワッド', zh: '小队' }),
      value: `${activeAgents}/${totalAgents}`,
      sub: `${t({ ko: '가동률', en: 'uptime', ja: '稼働率', zh: '运行率' })} ${activeRate}%`,
      color: '#00f0ff',
      icon: '🤖',
    },
    {
      id: 'active',
      label: t({ ko: '진행중', en: 'IN PROGRESS', ja: '進行中', zh: '进行中' }),
      value: inProgressTasks,
      sub: `${t({ ko: '계획', en: 'planned', ja: '計画', zh: '计划' })} ${numberFormatter.format(plannedTasks)}${t({
        ko: '건',
        en: '',
        ja: '件',
        zh: '项',
      })}`,
      color: '#f59e0b',
      icon: '⚡',
    },
  ];

  return (
    <section className="relative isolate space-y-4 text-slate-100">

      {/* Ambient background orbs */}
      <div className="pointer-events-none absolute -left-40 -top-32 h-96 w-96 rounded-full bg-violet-600/10 blur-[100px] animate-drift-slow" />
      <div className="pointer-events-none absolute -right-32 top-20 h-80 w-80 rounded-full bg-cyan-500/10 blur-[100px] animate-drift-slow-rev" />
      <div className="pointer-events-none absolute left-1/3 bottom-32 h-72 w-72 rounded-full bg-amber-500/[0.05] blur-[80px]" />

      {/* ═══ GAME HEADER ═══ */}
      <div className="game-panel relative overflow-hidden p-5">
        {/* Scanline overlay */}
        <div className="pointer-events-none absolute inset-0 bg-[repeating-linear-gradient(0deg,transparent,transparent_2px,rgba(0,0,0,0.03)_2px,rgba(0,0,0,0.03)_4px)]" />

        <div className="relative flex flex-wrap items-center justify-between gap-4">
          <div className="space-y-1.5">
            <div className="flex items-center gap-3">
              <h1
                className="text-2xl font-black tracking-tight sm:text-3xl"
                style={{
                  background: 'linear-gradient(135deg, #00f0ff, #3b82f6, #c45ff6)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  filter: 'drop-shadow(0 0 12px rgba(0,240,255,0.3))',
                }}
              >
                {companyName}
              </h1>
              <span className="flex items-center gap-1.5 rounded-full border border-emerald-400/40 bg-emerald-500/15 px-2.5 py-0.5 text-[10px] font-bold uppercase tracking-widest text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                {t({ ko: '실시간', en: 'LIVE', ja: 'ライブ', zh: '实时' })}
              </span>
            </div>
            <p className="text-xs text-slate-500">
              {t({
                ko: '에이전트들이 실시간으로 미션을 수행 중입니다',
                en: 'Agents are executing missions in real time',
                ja: 'エージェントがリアルタイムでミッションを実行中です',
                zh: '代理正在实时执行任务',
              })}
            </p>
          </div>

          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2 rounded-xl border border-cyan-400/20 bg-cyan-500/[0.06] px-4 py-2">
              <span className="text-xs text-cyan-400/60">⏰</span>
              <span
                className="font-mono text-xl font-bold tracking-tight text-cyan-200"
                style={{ textShadow: '0 0 10px rgba(0,240,255,0.4)' }}
              >
                {time}
              </span>
            </div>
            <div className="hidden flex-col gap-1 sm:flex">
              <span className="rounded-md border border-white/[0.06] bg-white/[0.03] px-2 py-0.5 text-[10px] text-slate-400">
                {date}
              </span>
              <span className="rounded-md border border-cyan-400/20 bg-cyan-500/[0.06] px-2 py-0.5 text-[10px] text-cyan-300">
                {briefing}
              </span>
            </div>
            {reviewQueue > 0 && (
              <span className="flex items-center gap-1.5 rounded-lg border border-orange-400/30 bg-orange-500/15 px-3 py-1.5 text-xs font-bold text-orange-300 animate-neon-pulse-orange">
                🔔 {t({ ko: '대기', en: 'Queued', ja: '待機', zh: '待处理' })} {numberFormatter.format(reviewQueue)}
                {t({ ko: '건', en: '', ja: '件', zh: '项' })}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* ═══ HUD STATS ═══ */}
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {hudStats.map((stat) => (
          <div
            key={stat.id}
            className="game-panel group relative overflow-hidden p-4 transition-all duration-300 hover:-translate-y-0.5"
            style={{ borderColor: `${stat.color}25` }}
          >
            {/* Top accent line */}
            <div
              className="absolute top-0 left-0 right-0 h-[2px] opacity-60"
              style={{ background: `linear-gradient(90deg, transparent, ${stat.color}, transparent)` }}
            />
            <div className="relative flex items-center justify-between">
              <div>
                <p className="text-[9px] font-bold uppercase tracking-[0.15em] text-slate-500">{stat.label}</p>
                <p
                  className="mt-1 text-3xl font-black tracking-tight"
                  style={{ color: stat.color, textShadow: `0 0 20px ${stat.color}40` }}
                >
                  {typeof stat.value === 'number' ? numberFormatter.format(stat.value) : stat.value}
                </p>
                <p className="mt-0.5 text-[10px] text-slate-500">{stat.sub}</p>
              </div>
              <span
                className="text-3xl opacity-20 transition-all duration-300 group-hover:opacity-40 group-hover:scale-110"
                style={{ filter: `drop-shadow(0 0 8px ${stat.color}40)` }}
              >
                {stat.icon}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* ═══ RANKING BOARD — HERO ═══ */}
      <div className="game-panel relative overflow-hidden p-5">
        {/* Background gradient */}
        <div className="pointer-events-none absolute inset-0 bg-gradient-to-b from-amber-500/[0.03] via-transparent to-transparent" />

        {/* Title */}
        <div className="relative mb-6 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <span
              className="text-2xl animate-crown-wiggle"
              style={{ display: 'inline-block', filter: 'drop-shadow(0 0 8px rgba(255,215,0,0.5))' }}
            >
              🏆
            </span>
            <div>
              <h2
                className="text-lg font-black uppercase tracking-wider"
                style={{
                  background: 'linear-gradient(135deg, #FFD700, #FFA500)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                  filter: 'drop-shadow(0 0 8px rgba(255,215,0,0.3))',
                }}
              >
                {t({ ko: '랭킹 보드', en: 'RANKING BOARD', ja: 'ランキングボード', zh: '排行榜' })}
              </h2>
              <p className="text-[10px] text-slate-500">
                {t({ ko: 'XP 기준 에이전트 순위', en: 'Agent ranking by XP', ja: 'XP 基準のエージェント順位', zh: '按 XP 排名' })}
              </p>
            </div>
          </div>
          <span className="rounded-md border border-white/[0.06] bg-white/[0.03] px-2.5 py-1 text-[10px] font-bold text-slate-400">
            TOP {topAgents.length}
          </span>
        </div>

        {topAgents.length === 0 ? (
          <div className="flex min-h-[200px] flex-col items-center justify-center gap-3 text-sm text-slate-500">
            <span className="text-4xl opacity-30">⚔️</span>
            <p>{t({ ko: '등록된 에이전트가 없습니다', en: 'No agents registered', ja: '登録されたエージェントがいません', zh: '暂无已注册代理' })}</p>
            <p className="text-[10px]">
              {t({
                ko: '에이전트를 추가하고 미션을 시작하세요',
                en: 'Add agents and start missions',
                ja: 'エージェントを追加してミッションを開始しましょう',
                zh: '添加代理并开始任务',
              })}
            </p>
          </div>
        ) : (
          <div className="relative space-y-5">

            {/* ── Podium: Top 3 ── */}
            {topAgents.length >= 2 && (
              <div className="flex items-end justify-center gap-4 pb-3 pt-2 sm:gap-6">
                {podiumOrder.map((agent, visualIdx) => {
                  const ranks = topAgents.length >= 3 ? [2, 1, 3] : [2, 1];
                  const rank = ranks[visualIdx];
                  const tier = getRankTier(agent.xp);
                  const isFirst = rank === 1;
                  const avatarSize = isFirst ? 64 : 48;
                  const podiumH = isFirst ? 'h-24' : rank === 2 ? 'h-16' : 'h-12';

                  return (
                    <div
                      key={agent.id}
                      className={`flex flex-col items-center gap-2 ${isFirst ? 'animate-rank-float' : ''}`}
                    >
                      {/* Medal */}
                      {rank === 1 && (
                        <span
                          className="text-2xl animate-crown-wiggle"
                          style={{ display: 'inline-block', filter: 'drop-shadow(0 0 12px rgba(255,215,0,0.6))' }}
                        >
                          🥇
                        </span>
                      )}
                      {rank === 2 && <span className="text-lg" style={{ filter: 'drop-shadow(0 0 6px rgba(192,192,192,0.5))' }}>🥈</span>}
                      {rank === 3 && <span className="text-lg" style={{ filter: 'drop-shadow(0 0 6px rgba(205,127,50,0.5))' }}>🥉</span>}

                      {/* Avatar with neon glow */}
                      <div
                        className="relative rounded-2xl overflow-hidden transition-transform duration-300 hover:scale-105"
                        style={{
                          boxShadow: isFirst
                            ? `0 0 20px ${tier.glow}, 0 0 40px ${tier.glow}`
                            : `0 0 12px ${tier.glow}`,
                          border: `2px solid ${tier.color}80`,
                        }}
                      >
                        <AgentAvatar agent={agentMap.get(agent.id)} agents={agents} size={avatarSize} rounded="2xl" />
                      </div>

                      {/* Name */}
                      <span
                        className={`max-w-[80px] truncate text-center font-bold ${isFirst ? 'text-sm' : 'text-xs'}`}
                        style={{
                          color: tier.color,
                          textShadow: isFirst ? `0 0 8px ${tier.glow}` : 'none',
                        }}
                      >
                        {agent.name}
                      </span>

                      {/* XP + Rank */}
                      <div className="flex flex-col items-center gap-1">
                        <span
                          className="font-mono text-xs font-bold"
                          style={{ color: tier.color, textShadow: `0 0 6px ${tier.glow}` }}
                        >
                          {numberFormatter.format(agent.xp)} XP
                        </span>
                        <RankBadge xp={agent.xp} size="sm" />
                      </div>

                      {/* Podium block */}
                      <div
                        className={`${podiumH} w-20 sm:w-24 rounded-t-xl flex items-center justify-center animate-podium-rise`}
                        style={{
                          background: `linear-gradient(to bottom, ${tier.color}30, ${tier.color}10)`,
                          border: `1px solid ${tier.color}40`,
                          borderBottom: 'none',
                          boxShadow: `inset 0 1px 0 ${tier.color}30, 0 -4px 12px ${tier.glow}`,
                        }}
                      >
                        <span className="text-2xl font-black" style={{ color: `${tier.color}50` }}>
                          #{rank}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* ── Ranked List: #4+ ── */}
            {topAgents.length > 3 && (
              <div className="space-y-2 border-t border-white/[0.06] pt-4">
                {topAgents.slice(3).map((agent, idx) => {
                  const rank = idx + 4;
                  const tier = getRankTier(agent.xp);
                  return (
                    <div
                      key={agent.id}
                      className="group flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 transition-all duration-200 hover:bg-white/[0.05] hover:translate-x-1"
                      style={{ borderLeftWidth: '3px', borderLeftColor: `${tier.color}60` }}
                    >
                      <span className="w-8 text-center font-mono text-sm font-black" style={{ color: `${tier.color}80` }}>
                        #{rank}
                      </span>
                      <div className="rounded-xl overflow-hidden flex-shrink-0" style={{ border: `1px solid ${tier.color}40` }}>
                        <AgentAvatar agent={agentMap.get(agent.id)} agents={agents} size={36} rounded="xl" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-bold text-slate-200">{agent.name}</p>
                        <p className="text-[10px] text-slate-500">
                          {agent.department ||
                            t({ ko: '미지정', en: 'Unassigned', ja: '未指定', zh: '未指定' })}
                        </p>
                      </div>
                      <div className="hidden w-28 sm:block">
                        <XpBar xp={agent.xp} maxXp={maxXp} color={tier.color} />
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold" style={{ color: tier.color }}>
                          {numberFormatter.format(agent.xp)}
                        </span>
                        <RankBadge xp={agent.xp} size="sm" />
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Single agent */}
            {topAgents.length === 1 && (() => {
              const agent = topAgents[0];
              const tier = getRankTier(agent.xp);
              return (
                <div
                  className="flex items-center gap-4 rounded-xl p-4"
                  style={{
                    background: `linear-gradient(135deg, ${tier.color}15, transparent)`,
                    border: `1px solid ${tier.color}30`,
                    boxShadow: `0 0 20px ${tier.glow}`,
                  }}
                >
                  <span className="text-2xl animate-crown-wiggle" style={{ display: 'inline-block' }}>🥇</span>
                  <div
                    className="rounded-2xl overflow-hidden"
                    style={{ border: `2px solid ${tier.color}60`, boxShadow: `0 0 15px ${tier.glow}` }}
                  >
                    <AgentAvatar agent={agentMap.get(agent.id)} agents={agents} size={52} rounded="2xl" />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-base font-black" style={{ color: tier.color }}>{agent.name}</p>
                    <p className="text-xs text-slate-400">
                      {agent.department ||
                        t({ ko: '미지정', en: 'Unassigned', ja: '未指定', zh: '未指定' })}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-mono text-lg font-black" style={{ color: tier.color, textShadow: `0 0 10px ${tier.glow}` }}>
                      {numberFormatter.format(agent.xp)} XP
                    </p>
                    <RankBadge xp={agent.xp} size="md" />
                  </div>
                </div>
              );
            })()}
          </div>
        )}
      </div>

      {/* ═══ GUILDS + SQUAD ═══ */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[1.2fr_1fr]">

        {/* Guild Rankings */}
        <div className="game-panel p-5">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-black uppercase tracking-wider text-slate-300">
            <span
              className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-500/15 text-sm"
              style={{ boxShadow: '0 0 8px rgba(59,130,246,0.3)' }}
            >
              🏰
            </span>
            {t({ ko: '부서 성과', en: 'DEPT. PERFORMANCE', ja: '部署パフォーマンス', zh: '部门绩效' })}
            <span className="ml-auto text-[9px] font-medium normal-case tracking-normal text-slate-500">
              {t({ ko: '부서별 성과', en: 'by department', ja: '部署別', zh: '按部门' })}
            </span>
          </h2>

          {deptData.length === 0 ? (
            <div className="flex min-h-[200px] flex-col items-center justify-center gap-2 text-sm text-slate-500">
              <span className="text-3xl opacity-30">🏰</span>
              {t({ ko: '데이터가 없습니다', en: 'No data available', ja: 'データがありません', zh: '暂无数据' })}
            </div>
          ) : (
            <div className="space-y-2.5">
              {deptData.map((dept) => (
                <article
                  key={dept.id}
                  className="group relative overflow-hidden rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 transition-all duration-200 hover:bg-white/[0.04] hover:translate-x-1"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2.5">
                      <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-800/80 text-base transition-transform duration-200 group-hover:scale-110">
                        {dept.icon}
                      </span>
                      <span className="text-sm font-bold text-slate-200">{dept.name}</span>
                    </div>
                    <span className={`rounded-md border px-2 py-0.5 text-[10px] font-black ${dept.color.badge}`}>
                      {dept.ratio}%
                    </span>
                  </div>

                  <div className="mt-2.5 relative h-2 overflow-hidden rounded-full border border-white/[0.06] bg-white/[0.04]">
                    <div
                      className={`xp-bar-fill h-full rounded-full bg-gradient-to-r ${dept.color.bar} transition-all duration-700`}
                      style={{ width: `${dept.ratio}%` }}
                    />
                  </div>

                  <div className="mt-1.5 flex justify-between text-[9px] font-semibold uppercase tracking-wider text-slate-500">
                    <span>
                      {t({ ko: '클리어', en: 'cleared', ja: 'クリア', zh: '完成' })} {numberFormatter.format(dept.done)}
                    </span>
                    <span>
                      {t({ ko: '전체', en: 'total', ja: '全体', zh: '总计' })} {numberFormatter.format(dept.total)}
                    </span>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        {/* Squad Roster */}
        <div className="game-panel p-5">
          <div className="mb-4 flex items-center justify-between">
            <h2 className="flex items-center gap-2 text-sm font-black uppercase tracking-wider text-slate-300">
              <span
                className="flex h-7 w-7 items-center justify-center rounded-lg bg-cyan-500/15 text-sm"
                style={{ boxShadow: '0 0 8px rgba(0,240,255,0.2)' }}
              >
                🤖
              </span>
              {t({ ko: '스쿼드', en: 'SQUAD', ja: 'スクワッド', zh: '小队' })}
            </h2>
            <div className="flex items-center gap-2 text-[10px]">
              <span className="flex items-center gap-1 rounded-md border border-emerald-400/30 bg-emerald-500/10 px-2 py-0.5 font-bold text-emerald-300">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                {t({ ko: 'ON', en: 'ON', ja: 'ON', zh: '在线' })} {numberFormatter.format(workingAgents.length)}
              </span>
              <span className="flex items-center gap-1 rounded-md border border-slate-600/40 bg-slate-700/30 px-2 py-0.5 font-bold text-slate-400">
                {t({ ko: 'OFF', en: 'OFF', ja: 'OFF', zh: '离线' })} {numberFormatter.format(idleAgentsList.length)}
              </span>
            </div>
          </div>

          <div className="flex flex-wrap gap-3">
            {agents.map((agent) => {
              const isWorking = agent.status === 'working';
              const tier = getRankTier(agent.stats_xp);
              // Deterministic delay from agent id
              const delay = (agent.id.charCodeAt(0) * 137) % 1500;
              return (
                <div
                  key={agent.id}
                  title={`${locale === 'ko' ? agent.name_ko ?? agent.name : agent.name ?? agent.name_ko} — ${
                    isWorking
                      ? t({ ko: '작업 중', en: 'Working', ja: '作業中', zh: '工作中' })
                      : t({ ko: '대기 중', en: 'Idle', ja: '待機中', zh: '空闲' })
                  } — ${tier.name}`}
                  className={`group relative flex flex-col items-center gap-1.5 ${isWorking ? 'animate-bubble-float' : ''}`}
                  style={isWorking ? { animationDelay: `${delay}ms` } : {}}
                >
                  <div className="relative">
                    <div
                      className="rounded-2xl overflow-hidden transition-transform duration-200 group-hover:scale-110"
                      style={{
                        boxShadow: isWorking ? `0 0 12px ${tier.glow}` : 'none',
                        border: isWorking ? `2px solid ${tier.color}60` : '1px solid rgba(255,255,255,0.08)',
                      }}
                    >
                      <AgentAvatar agent={agent} agents={agents} size={40} rounded="2xl" />
                    </div>
                    <span
                      className={`absolute -bottom-0.5 -right-0.5 h-3 w-3 rounded-full border-2 border-slate-900 ${
                        isWorking ? 'bg-emerald-400 animate-status-glow' : 'bg-slate-600'
                      }`}
                    />
                  </div>
                  <span className={`max-w-[52px] truncate text-center text-[9px] font-bold leading-tight ${
                    isWorking ? 'text-slate-200' : 'text-slate-500'
                  }`}>
                    {locale === 'ko' ? agent.name_ko ?? agent.name : agent.name ?? agent.name_ko}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ═══ MISSION LOG ═══ */}
      <div className="game-panel p-5">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="flex items-center gap-2 text-sm font-black uppercase tracking-wider text-slate-300">
            <span
              className="flex h-7 w-7 items-center justify-center rounded-lg bg-violet-500/15 text-sm"
              style={{ boxShadow: '0 0 8px rgba(139,92,246,0.2)' }}
            >
              📡
            </span>
            {t({ ko: '미션 로그', en: 'MISSION LOG', ja: 'ミッションログ', zh: '任务日志' })}
            <span className="ml-2 text-[9px] font-medium normal-case tracking-normal text-slate-500">
              {t({ ko: '최근 활동', en: 'Recent activity', ja: '最近の活動', zh: '最近活动' })}
            </span>
          </h2>
          <span className="flex items-center gap-1.5 rounded-md border border-slate-600/40 bg-slate-700/30 px-2 py-0.5 text-[10px] font-bold text-slate-400">
            {t({ ko: '유휴', en: 'Idle', ja: '待機', zh: '空闲' })} {numberFormatter.format(idleAgents)}
            {t({ ko: '명', en: '', ja: '人', zh: '人' })}
          </span>
        </div>

        {recentTasks.length === 0 ? (
          <div className="flex flex-col items-center justify-center gap-2 py-10 text-sm text-slate-500">
            <span className="text-3xl opacity-30">📡</span>
            {t({ ko: '로그 없음', en: 'No logs', ja: 'ログなし', zh: '暂无日志' })}
          </div>
        ) : (
          <div className="space-y-2">
            {recentTasks.map((task) => {
              const statusInfo = STATUS_LABELS[task.status] ?? {
                color: 'bg-slate-600/20 text-slate-200 border-slate-500/30',
                dot: 'bg-slate-400',
              };
              const assignedAgent =
                task.assigned_agent ??
                (task.assigned_agent_id ? agentMap.get(task.assigned_agent_id) : undefined);
              const leftBorder = STATUS_LEFT_BORDER[task.status] ?? 'border-l-slate-500';

              return (
                <article
                  key={task.id}
                  className={`group grid grid-cols-[auto_1fr_auto] items-center gap-3 rounded-xl border border-white/[0.06] border-l-[3px] ${leftBorder} bg-white/[0.02] p-3 transition-all duration-200 hover:bg-white/[0.04] hover:translate-x-1`}
                >
                  {assignedAgent ? (
                    <AgentAvatar agent={assignedAgent} agents={agents} size={36} rounded="xl" />
                  ) : (
                    <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-700/50 bg-slate-800/80 text-base text-slate-500">
                      📄
                    </div>
                  )}

                  <div className="min-w-0">
                    <p className="truncate text-sm font-bold text-slate-200 transition-colors group-hover:text-white">
                      {task.title}
                    </p>
                    <p className="mt-0.5 flex items-center gap-1.5 text-[10px] text-slate-500">
                      <span className={`h-1.5 w-1.5 flex-shrink-0 rounded-full ${statusInfo.dot}`} />
                      {assignedAgent
                        ? (locale === 'ko' ? assignedAgent.name_ko : assignedAgent.name)
                        : t({ ko: '미배정', en: 'Unassigned', ja: '未割り当て', zh: '未分配' })}
                    </p>
                  </div>

                  <div className="flex flex-col items-end gap-1">
                    <span className={`rounded-md border px-2 py-0.5 text-[9px] font-black uppercase tracking-wider ${statusInfo.color}`}>
                      {taskStatusLabel(task.status, t)}
                    </span>
                    <span className="text-[9px] font-medium text-slate-500">{timeAgo(task.updated_at, localeTag)}</span>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>
    </section>
  );
}
