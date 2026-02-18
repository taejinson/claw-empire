import { useState, useEffect, useMemo, useCallback } from "react";
import { getSkills, type SkillEntry } from "../api";

/* ================================================================== */
/*  Skills data from skills.sh (loaded dynamically via /api/skills)    */
/* ================================================================== */

interface CategorizedSkill extends SkillEntry {
  category: string;
  installsDisplay: string;
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

function categorize(name: string, repo: string): string {
  const n = name.toLowerCase();
  const r = repo.toLowerCase();
  if (
    n.includes("design") ||
    n.includes("ui") ||
    n.includes("ux") ||
    n.includes("brand") ||
    n.includes("canvas") ||
    n.includes("theme") ||
    n.includes("interface") ||
    n.includes("visual") ||
    n.includes("interaction")
  )
    return "Design";
  if (
    n.includes("marketing") ||
    n.includes("seo") ||
    n.includes("copywriting") ||
    n.includes("content") ||
    n.includes("social") ||
    n.includes("pricing") ||
    n.includes("launch") ||
    n.includes("analytics") ||
    n.includes("cro") ||
    n.includes("ads") ||
    n.includes("email-sequence") ||
    n.includes("referral") ||
    n.includes("competitor") ||
    n.includes("onboarding") ||
    n.includes("signup") ||
    n.includes("paywall") ||
    n.includes("popup") ||
    n.includes("ab-test") ||
    n.includes("free-tool") ||
    n.includes("backlink") ||
    r.includes("marketingskills")
  )
    return "Marketing";
  if (
    n.includes("test") ||
    n.includes("debug") ||
    n.includes("audit") ||
    n.includes("review") ||
    n.includes("verification") ||
    n.includes("e2e")
  )
    return "Testing & QA";
  if (
    n.includes("react") ||
    n.includes("vue") ||
    n.includes("next") ||
    n.includes("expo") ||
    n.includes("flutter") ||
    n.includes("swift") ||
    n.includes("angular") ||
    n.includes("tailwind") ||
    n.includes("shadcn") ||
    n.includes("nuxt") ||
    n.includes("vite") ||
    n.includes("native") ||
    n.includes("responsive") ||
    n.includes("component") ||
    n.includes("frontend") ||
    n.includes("remotion") ||
    n.includes("slidev") ||
    n.includes("stitch")
  )
    return "Frontend";
  if (
    n.includes("api") ||
    n.includes("backend") ||
    n.includes("node") ||
    n.includes("fastapi") ||
    n.includes("nest") ||
    n.includes("laravel") ||
    n.includes("python") ||
    n.includes("golang") ||
    n.includes("async") ||
    n.includes("sql") ||
    n.includes("postgres") ||
    n.includes("supabase") ||
    n.includes("convex") ||
    n.includes("stripe") ||
    n.includes("auth") ||
    n.includes("microservices") ||
    n.includes("error-handling")
  )
    return "Backend";
  if (
    n.includes("docker") ||
    n.includes("github-actions") ||
    n.includes("cicd") ||
    n.includes("deploy") ||
    n.includes("monorepo") ||
    n.includes("turborepo") ||
    n.includes("pnpm") ||
    n.includes("uv-package") ||
    n.includes("git") ||
    n.includes("release") ||
    n.includes("worktree")
  )
    return "DevOps";
  if (
    n.includes("agent") ||
    n.includes("mcp") ||
    n.includes("prompt") ||
    n.includes("langchain") ||
    n.includes("rag") ||
    n.includes("ai-sdk") ||
    n.includes("browser-use") ||
    n.includes("skill-creator") ||
    n.includes("find-skills") ||
    n.includes("remembering") ||
    n.includes("subagent") ||
    n.includes("dispatching") ||
    n.includes("planning") ||
    n.includes("executing") ||
    n.includes("writing-plans") ||
    n.includes("brainstorming") ||
    n.includes("using-superpowers") ||
    n.includes("finishing") ||
    n.includes("requesting") ||
    n.includes("receiving") ||
    n.includes("agentation") ||
    n.includes("clawdirect") ||
    n.includes("instaclaw") ||
    n.includes("nblm") ||
    n.includes("context7")
  )
    return "AI & Agent";
  if (
    n.includes("pdf") ||
    n.includes("pptx") ||
    n.includes("docx") ||
    n.includes("xlsx") ||
    n.includes("doc-coauthor") ||
    n.includes("internal-comms") ||
    n.includes("slack") ||
    n.includes("writing") ||
    n.includes("copy-editing") ||
    n.includes("humanizer") ||
    n.includes("obsidian") ||
    n.includes("baoyu") ||
    n.includes("firecrawl") ||
    n.includes("web-artifacts") ||
    n.includes("comic") ||
    n.includes("image") ||
    n.includes("infographic") ||
    n.includes("url-to-markdown")
  )
    return "Productivity";
  if (n.includes("security") || n.includes("accessibility"))
    return "Security";
  if (
    n.includes("typescript") ||
    n.includes("javascript") ||
    n.includes("architecture") ||
    n.includes("state-management") ||
    n.includes("modern-javascript")
  )
    return "Architecture";
  return "Other";
}

function formatInstalls(n: number, localeTag: string): string {
  return new Intl.NumberFormat(localeTag, {
    notation: n >= 1000 ? "compact" : "standard",
    maximumFractionDigits: 1,
  }).format(n);
}

const CATEGORIES = [
  "All",
  "Frontend",
  "Backend",
  "Design",
  "AI & Agent",
  "Marketing",
  "Testing & QA",
  "DevOps",
  "Productivity",
  "Architecture",
  "Security",
  "Other",
];

const CATEGORY_ICONS: Record<string, string> = {
  All: "📚",
  Frontend: "🎨",
  Backend: "🔧",
  Design: "✨",
  "AI & Agent": "🤖",
  Marketing: "📈",
  "Testing & QA": "🧪",
  DevOps: "🚀",
  Productivity: "📝",
  Architecture: "🏗️",
  Security: "🔒",
  Other: "📦",
};

const CATEGORY_COLORS: Record<string, string> = {
  Frontend: "text-blue-400 bg-blue-500/15 border-blue-500/30",
  Backend: "text-green-400 bg-green-500/15 border-green-500/30",
  Design: "text-pink-400 bg-pink-500/15 border-pink-500/30",
  "AI & Agent": "text-purple-400 bg-purple-500/15 border-purple-500/30",
  Marketing: "text-amber-400 bg-amber-500/15 border-amber-500/30",
  "Testing & QA": "text-cyan-400 bg-cyan-500/15 border-cyan-500/30",
  DevOps: "text-orange-400 bg-orange-500/15 border-orange-500/30",
  Productivity: "text-emerald-400 bg-emerald-500/15 border-emerald-500/30",
  Architecture: "text-indigo-400 bg-indigo-500/15 border-indigo-500/30",
  Security: "text-red-400 bg-red-500/15 border-red-500/30",
  Other: "text-slate-400 bg-slate-500/15 border-slate-500/30",
};

function categoryLabel(category: string, t: TFunction) {
  switch (category) {
    case "All":
      return t({ ko: "전체", en: "All", ja: "すべて", zh: "全部" });
    case "Frontend":
      return t({ ko: "프론트엔드", en: "Frontend", ja: "フロントエンド", zh: "前端" });
    case "Backend":
      return t({ ko: "백엔드", en: "Backend", ja: "バックエンド", zh: "后端" });
    case "Design":
      return t({ ko: "디자인", en: "Design", ja: "デザイン", zh: "设计" });
    case "AI & Agent":
      return t({ ko: "AI & 에이전트", en: "AI & Agent", ja: "AI & エージェント", zh: "AI 与代理" });
    case "Marketing":
      return t({ ko: "마케팅", en: "Marketing", ja: "マーケティング", zh: "营销" });
    case "Testing & QA":
      return t({ ko: "테스트 & QA", en: "Testing & QA", ja: "テスト & QA", zh: "测试与 QA" });
    case "DevOps":
      return t({ ko: "데브옵스", en: "DevOps", ja: "DevOps", zh: "DevOps" });
    case "Productivity":
      return t({ ko: "생산성", en: "Productivity", ja: "生産性", zh: "效率" });
    case "Architecture":
      return t({ ko: "아키텍처", en: "Architecture", ja: "アーキテクチャ", zh: "架构" });
    case "Security":
      return t({ ko: "보안", en: "Security", ja: "セキュリティ", zh: "安全" });
    case "Other":
      return t({ ko: "기타", en: "Other", ja: "その他", zh: "其他" });
    default:
      return category;
  }
}

function getRankBadge(rank: number) {
  if (rank === 1) return { icon: "🥇", color: "text-yellow-400" };
  if (rank === 2) return { icon: "🥈", color: "text-slate-300" };
  if (rank === 3) return { icon: "🥉", color: "text-amber-600" };
  if (rank <= 10) return { icon: "🏆", color: "text-amber-400" };
  if (rank <= 50) return { icon: "⭐", color: "text-blue-400" };
  return { icon: "", color: "text-slate-500" };
}

/* ================================================================== */
/*  Component                                                          */
/* ================================================================== */

export default function SkillsLibrary() {
  const { t, localeTag } = useI18n();
  const [skills, setSkills] = useState<SkillEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("All");
  const [sortBy, setSortBy] = useState<"rank" | "name" | "installs">("rank");
  const [copiedSkill, setCopiedSkill] = useState<string | null>(null);

  useEffect(() => {
    getSkills()
      .then(setSkills)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const categorizedSkills = useMemo<CategorizedSkill[]>(
    () =>
      skills.map((s) => ({
        ...s,
        category: categorize(s.name, s.repo),
        installsDisplay: formatInstalls(s.installs, localeTag),
      })),
    [skills, localeTag]
  );

  const filtered = useMemo(() => {
    let result = categorizedSkills;

    if (selectedCategory !== "All") {
      result = result.filter((s) => s.category === selectedCategory);
    }

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (s) =>
          s.name.toLowerCase().includes(q) ||
          s.repo.toLowerCase().includes(q) ||
          s.category.toLowerCase().includes(q)
      );
    }

    if (sortBy === "name") {
      result = [...result].sort((a, b) => a.name.localeCompare(b.name, localeTag));
    } else if (sortBy === "installs") {
      result = [...result].sort((a, b) => b.installs - a.installs);
    }
    // rank is default order

    return result;
  }, [categorizedSkills, search, selectedCategory, sortBy, localeTag]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { All: categorizedSkills.length };
    for (const s of categorizedSkills) {
      counts[s.category] = (counts[s.category] || 0) + 1;
    }
    return counts;
  }, [categorizedSkills]);

  function handleCopy(skill: CategorizedSkill) {
    const cmd = `npx skills add ${skill.repo}`;
    navigator.clipboard.writeText(cmd).then(() => {
      setCopiedSkill(skill.name);
      setTimeout(() => setCopiedSkill(null), 2000);
    });
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="text-center">
          <div className="animate-spin w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full mx-auto mb-4" />
          <div className="text-slate-400 text-sm">
            {t({
              ko: "skills.sh 데이터 로딩중...",
              en: "Loading skills.sh data...",
              ja: "skills.sh データを読み込み中...",
              zh: "正在加载 skills.sh 数据...",
            })}
          </div>
        </div>
      </div>
    );
  }

  if (error && skills.length === 0) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="text-center">
          <div className="text-4xl mb-3">⚠️</div>
          <div className="text-slate-400 text-sm">
            {t({
              ko: "스킬 데이터를 불러올 수 없습니다",
              en: "Unable to load skills data",
              ja: "スキルデータを読み込めません",
              zh: "无法加载技能数据",
            })}
          </div>
          <div className="text-slate-500 text-xs mt-1">{error}</div>
          <button
            onClick={() => {
              setLoading(true);
              setError(null);
              getSkills()
                .then(setSkills)
                .catch((e) => setError(e.message))
                .finally(() => setLoading(false));
            }}
            className="mt-4 px-4 py-2 text-sm bg-blue-600/20 text-blue-400 border border-blue-500/30 rounded-lg hover:bg-blue-600/30 transition-all"
          >
            {t({ ko: "다시 시도", en: "Retry", ja: "再試行", zh: "重试" })}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-slate-800/60 backdrop-blur-sm border border-slate-700/50 rounded-xl p-5">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-lg font-bold text-white flex items-center gap-2">
              <span className="text-2xl">📚</span>
              {t({
                ko: "Agent Skills 문서고",
                en: "Agent Skills Library",
                ja: "Agent Skills ライブラリ",
                zh: "Agent Skills 资料库",
              })}
            </h2>
            <p className="text-sm text-slate-400 mt-1">
              {t({
                ko: "AI 에이전트 스킬 디렉토리 · skills.sh 실시간 데이터",
                en: "AI agent skill directory · live skills.sh data",
                ja: "AI エージェントスキルディレクトリ · skills.sh リアルタイムデータ",
                zh: "AI 代理技能目录 · skills.sh 实时数据",
              })}
            </p>
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold text-empire-gold">{skills.length}</div>
            <div className="text-xs text-slate-500">
              {t({ ko: "등록된 스킬", en: "Registered skills", ja: "登録済みスキル", zh: "已收录技能" })}
            </div>
          </div>
        </div>

        {/* Search & Sort */}
        <div className="flex gap-3">
          <div className="flex-1 relative">
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder={t({
                ko: "스킬 검색... (이름, 저장소, 카테고리)",
                en: "Search skills... (name, repo, category)",
                ja: "スキル検索...（名前・リポジトリ・カテゴリ）",
                zh: "搜索技能...（名称、仓库、分类）",
              })}
              className="w-full bg-slate-900/60 border border-slate-600/50 rounded-lg px-4 py-2.5 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/25"
            />
            {search && (
              <button
                onClick={() => setSearch("")}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                &times;
              </button>
            )}
          </div>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
            className="bg-slate-900/60 border border-slate-600/50 rounded-lg px-3 py-2.5 text-sm text-slate-300 focus:outline-none focus:border-blue-500/50"
          >
            <option value="rank">{t({ ko: "순위순", en: "By Rank", ja: "順位順", zh: "按排名" })}</option>
            <option value="installs">{t({ ko: "설치순", en: "By Installs", ja: "インストール順", zh: "按安装量" })}</option>
            <option value="name">{t({ ko: "이름순", en: "By Name", ja: "名前順", zh: "按名称" })}</option>
          </select>
        </div>
      </div>

      {/* Category Filter */}
      <div className="flex flex-wrap gap-2">
        {CATEGORIES.map((cat) => (
          <button
            key={cat}
            onClick={() => setSelectedCategory(cat)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition-all ${
              selectedCategory === cat
                ? "bg-blue-600/20 text-blue-400 border-blue-500/40"
                : "bg-slate-800/40 text-slate-400 border-slate-700/50 hover:bg-slate-700/40 hover:text-slate-300"
            }`}
          >
            {CATEGORY_ICONS[cat]} {categoryLabel(cat, t)}
            <span className="ml-1 text-slate-500">
              {categoryCounts[cat] || 0}
            </span>
          </button>
        ))}
      </div>

      {/* Results count */}
      <div className="text-xs text-slate-500 px-1">
        {filtered.length}
        {t({ ko: "개 스킬 표시중", en: " skills shown", ja: "件のスキルを表示中", zh: " 个技能已显示" })}
        {search &&
          ` · "${search}" ${t({
            ko: "검색 결과",
            en: "search results",
            ja: "検索結果",
            zh: "搜索结果",
          })}`}
      </div>

      {/* Skills Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
        {filtered.map((skill) => {
          const badge = getRankBadge(skill.rank);
          const catColor =
            CATEGORY_COLORS[skill.category] || CATEGORY_COLORS.Other;
          return (
            <div
              key={`${skill.rank}-${skill.name}`}
              className="bg-slate-800/50 border border-slate-700/40 rounded-xl p-4 hover:bg-slate-800/70 hover:border-slate-600/50 transition-all group"
            >
              {/* Top row: rank + name */}
              <div className="flex items-start gap-3 mb-3">
                <div className="flex items-center justify-center w-8 h-8 rounded-lg bg-slate-900/60 text-sm font-bold shrink-0">
                  {badge.icon ? (
                    <span>{badge.icon}</span>
                  ) : (
                    <span className={badge.color}>#{skill.rank}</span>
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="font-semibold text-white text-sm truncate">
                    {skill.name}
                  </div>
                  <div className="text-xs text-slate-500 truncate mt-0.5">
                    {skill.repo}
                  </div>
                </div>
              </div>

              {/* Bottom row: category + installs + copy */}
              <div className="flex items-center justify-between">
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full border ${catColor}`}
                >
                  {CATEGORY_ICONS[skill.category]} {categoryLabel(skill.category, t)}
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-xs text-slate-400">
                    <span className="text-empire-green font-medium">
                      {skill.installsDisplay}
                    </span>{" "}
                    {t({ ko: "설치", en: "installs", ja: "インストール", zh: "安装" })}
                  </span>
                  <button
                    onClick={() => handleCopy(skill)}
                    className="px-2 py-1 text-[10px] bg-blue-600/20 text-blue-400 border border-blue-500/30 rounded-md hover:bg-blue-600/30 transition-all"
                    title={`npx skills add ${skill.repo}`}
                  >
                    {copiedSkill === skill.name
                      ? t({ ko: "복사됨", en: "Copied", ja: "コピー済み", zh: "已复制" })
                      : t({ ko: "복사", en: "Copy", ja: "コピー", zh: "复制" })}
                  </button>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Empty state */}
      {filtered.length === 0 && (
        <div className="text-center py-16">
          <div className="text-4xl mb-3">🔍</div>
          <div className="text-slate-400 text-sm">
            {t({ ko: "검색 결과가 없습니다", en: "No search results", ja: "検索結果はありません", zh: "没有搜索结果" })}
          </div>
          <div className="text-slate-500 text-xs mt-1">
            {t({
              ko: "다른 키워드로 검색해보세요",
              en: "Try a different keyword",
              ja: "別のキーワードで検索してください",
              zh: "请尝试其他关键词",
            })}
          </div>
        </div>
      )}

      {/* Footer note */}
      <div className="text-center text-xs text-slate-600 py-4">
        {t({
          ko: "데이터 출처: skills.sh · 설치: npx skills add <owner/repo>",
          en: "Source: skills.sh · Install: npx skills add <owner/repo>",
          ja: "データソース: skills.sh · インストール: npx skills add <owner/repo>",
          zh: "数据来源: skills.sh · 安装: npx skills add <owner/repo>",
        })}
      </div>
    </div>
  );
}
