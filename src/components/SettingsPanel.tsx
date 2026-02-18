import { useState, useEffect, useRef, useCallback } from "react";
import type { CompanySettings, CliStatusMap, CliProvider, CliModelInfo } from "../types";
import * as api from "../api";
import type { OAuthStatus, OAuthConnectProvider, DeviceCodeStart, GatewayTarget } from "../api";
import type { OAuthCallbackResult } from "../App";

interface SettingsPanelProps {
  settings: CompanySettings;
  cliStatus: CliStatusMap | null;
  onSave: (settings: CompanySettings) => void;
  onRefreshCli: () => void;
  oauthResult?: OAuthCallbackResult | null;
  onOauthResultClear?: () => void;
}

type Locale = "ko" | "en" | "ja" | "zh";
type TFunction = (messages: Record<Locale, string>) => string;
type LocalSettings = Omit<CompanySettings, "language"> & { language: Locale };

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

// SVG logos matching OfficeView CLI Usage icons
function CliClaudeLogo() {
  return (
    <svg width="18" height="18" viewBox="0 0 400 400" fill="none">
      <path fill="#D97757" d="m124.011 241.251 49.164-27.585.826-2.396-.826-1.333h-2.396l-8.217-.506-28.09-.759-24.363-1.012-23.603-1.266-5.938-1.265L75 197.79l.574-3.661 4.994-3.358 7.153.625 15.808 1.079 23.722 1.637 17.208 1.012 25.493 2.649h4.049l.574-1.637-1.384-1.012-1.079-1.012-24.548-16.635-26.573-17.58-13.919-10.123-7.524-5.129-3.796-4.808-1.637-10.494 6.833-7.525 9.178.624 2.345.625 9.296 7.153 19.858 15.37 25.931 19.098 3.796 3.155 1.519-1.08.185-.759-1.704-2.851-14.104-25.493-15.049-25.931-6.698-10.747-1.772-6.445c-.624-2.649-1.08-4.876-1.08-7.592l7.778-10.561L144.729 75l10.376 1.383 4.37 3.797 6.445 14.745 10.443 23.215 16.197 31.566 4.741 9.364 2.53 8.672.945 2.649h1.637v-1.519l1.332-17.782 2.464-21.832 2.395-28.091.827-7.912 3.914-9.482 7.778-5.129 6.074 2.902 4.994 7.153-.692 4.623-2.969 19.301-5.821 30.234-3.796 20.245h2.21l2.531-2.53 10.241-13.599 17.208-21.511 7.593-8.537 8.857-9.431 5.686-4.488h10.747l7.912 11.76-3.543 12.147-11.067 14.037-9.178 11.895-13.16 17.714-8.216 14.172.759 1.131 1.957-.186 29.727-6.327 16.062-2.901 19.166-3.29 8.672 4.049.944 4.116-3.408 8.419-20.498 5.062-24.042 4.808-35.801 8.469-.439.321.506.624 16.13 1.519 6.9.371h16.888l31.448 2.345 8.217 5.433 4.926 6.647-.827 5.061-12.653 6.445-17.074-4.049-39.85-9.482-13.666-3.408h-1.889v1.131l11.388 11.135 20.87 18.845 26.133 24.295 1.333 6.006-3.357 4.741-3.543-.506-22.962-17.277-8.858-7.777-20.06-16.888H238.5v1.771l4.623 6.765 24.413 36.696 1.265 11.253-1.771 3.661-6.327 2.21-6.951-1.265-14.29-20.06-14.745-22.591-11.895-20.246-1.451.827-7.018 75.601-3.29 3.863-7.592 2.902-6.327-4.808-3.357-7.778 3.357-15.37 4.049-20.06 3.29-15.943 2.969-19.807 1.772-6.58-.118-.439-1.451.186-14.931 20.498-22.709 30.689-17.968 19.234-4.302 1.704-7.458-3.864.692-6.9 4.167-6.141 24.869-31.634 14.999-19.605 9.684-11.32-.068-1.637h-.573l-66.052 42.887-11.759 1.519-5.062-4.741.625-7.778 2.395-2.531 19.858-13.665-.068.067z"/>
    </svg>
  );
}

function CliChatGPTLogo() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M22.282 9.821a5.985 5.985 0 00-.516-4.91 6.046 6.046 0 00-6.51-2.9A6.065 6.065 0 0011.708.413a6.12 6.12 0 00-5.834 4.27 5.984 5.984 0 00-3.996 2.9 6.043 6.043 0 00.743 7.097 5.98 5.98 0 00.51 4.911 6.051 6.051 0 006.515 2.9A5.985 5.985 0 0013.192 24a6.116 6.116 0 005.84-4.27 5.99 5.99 0 003.997-2.9 6.056 6.056 0 00-.747-7.01zM13.192 22.784a4.474 4.474 0 01-2.876-1.04l.141-.081 4.779-2.758a.795.795 0 00.392-.681v-6.737l2.02 1.168a.071.071 0 01.038.052v5.583a4.504 4.504 0 01-4.494 4.494zM3.658 18.607a4.47 4.47 0 01-.535-3.014l.142.085 4.783 2.759a.77.77 0 00.78 0l5.843-3.369v2.332a.08.08 0 01-.033.062L9.74 20.236a4.508 4.508 0 01-6.083-1.63zM2.328 7.847A4.477 4.477 0 014.68 5.879l-.002.159v5.52a.78.78 0 00.391.676l5.84 3.37-2.02 1.166a.08.08 0 01-.073.007L3.917 13.98a4.506 4.506 0 01-1.589-6.132zM19.835 11.94l-5.844-3.37 2.02-1.166a.08.08 0 01.073-.007l4.898 2.794a4.494 4.494 0 01-.69 8.109v-5.68a.79.79 0 00-.457-.68zm2.01-3.023l-.141-.085-4.774-2.782a.776.776 0 00-.785 0L10.302 9.42V7.088a.08.08 0 01.033-.062l4.898-2.824a4.497 4.497 0 016.612 4.66v.054zM9.076 12.59l-2.02-1.164a.08.08 0 01-.038-.057V5.79A4.498 4.498 0 0114.392 3.2l-.141.08-4.778 2.758a.795.795 0 00-.392.681l-.005 5.87zm1.098-2.358L12 9.019l1.826 1.054v2.109L12 13.235l-1.826-1.054v-2.108z" fill="#10A37F"/>
    </svg>
  );
}

function CliGeminiLogo() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
      <path d="M12 0C12 6.627 6.627 12 0 12c6.627 0 12 5.373 12 12 0-6.627 5.373-12 12-12-6.627 0-12-5.373-12-12z" fill="url(#cli_gemini_grad)"/>
      <defs>
        <linearGradient id="cli_gemini_grad" x1="0" y1="0" x2="24" y2="24" gradientUnits="userSpaceOnUse">
          <stop stopColor="#4285F4"/>
          <stop offset="1" stopColor="#886FBF"/>
        </linearGradient>
      </defs>
    </svg>
  );
}

const CLI_INFO: Record<string, { label: string; icon: React.ReactNode }> = {
  claude: { label: "Claude Code", icon: <CliClaudeLogo /> },
  codex: { label: "Codex CLI", icon: <CliChatGPTLogo /> },
  gemini: { label: "Gemini CLI", icon: <CliGeminiLogo /> },
  opencode: { label: "OpenCode", icon: "⚪" },
  copilot: { label: "GitHub Copilot", icon: "\uD83D\uDE80" },
  antigravity: { label: "Antigravity", icon: "\uD83C\uDF0C" },
};

const OAUTH_INFO: Record<string, { label: string }> = {
  "github-copilot": { label: "GitHub Copilot" },
  antigravity: { label: "Antigravity" },
};

// SVG Logo components for OAuth providers
function GitHubCopilotLogo({ className }: { className?: string }) {
  return (
    <svg className={className || "w-5 h-5"} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.374 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.599.111.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0112 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z"/>
    </svg>
  );
}

function AntigravityLogo({ className }: { className?: string }) {
  return (
    <svg className={className || "w-5 h-5"} viewBox="0 0 24 24" fill="#1a73e8">
      <path d="m19.94,20.59c1.09.82,2.73.27,1.23-1.23-4.5-4.36-3.55-16.36-9.14-16.36S7.39,15,2.89,19.36c-1.64,1.64.14,2.05,1.23,1.23,4.23-2.86,3.95-7.91,7.91-7.91s3.68,5.05,7.91,7.91Z"/>
    </svg>
  );
}

const CONNECTABLE_PROVIDERS: Array<{
  id: OAuthConnectProvider;
  label: string;
  Logo: ({ className }: { className?: string }) => React.ReactElement;
  description: string;
}> = [
  { id: "github-copilot", label: "GitHub Copilot", Logo: GitHubCopilotLogo, description: "GitHub OAuth (Copilot)" },
  { id: "antigravity", label: "Antigravity", Logo: AntigravityLogo, description: "Google OAuth (Antigravity)" },
];

export default function SettingsPanel({
  settings,
  cliStatus,
  onSave,
  onRefreshCli,
  oauthResult,
  onOauthResultClear,
}: SettingsPanelProps) {
  const [form, setForm] = useState<LocalSettings>(settings as LocalSettings);
  const { t, localeTag } = useI18n(form.language);
  const [saved, setSaved] = useState(false);
  const [tab, setTab] = useState<"general" | "cli" | "oauth" | "gateway">(
    oauthResult ? "oauth" : "general"
  );
  const [oauthStatus, setOauthStatus] = useState<OAuthStatus | null>(null);
  const [oauthLoading, setOauthLoading] = useState(false);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState<string | null>(null);
  const [savingAccountId, setSavingAccountId] = useState<string | null>(null);
  const [accountDrafts, setAccountDrafts] = useState<Record<string, { label: string; modelOverride: string; priority: string }>>({});

  // OAuth model selection state
  const [models, setModels] = useState<Record<string, string[]> | null>(null);
  const [modelsLoading, setModelsLoading] = useState(false);

  // CLI model selection state
  const [cliModels, setCliModels] = useState<Record<string, CliModelInfo[]> | null>(null);
  const [cliModelsLoading, setCliModelsLoading] = useState(false);

  // GitHub Device Code flow state
  const [deviceCode, setDeviceCode] = useState<DeviceCodeStart | null>(null);
  const [deviceStatus, setDeviceStatus] = useState<string | null>(null); // "polling" | "complete" | "error" | "expired"
  const [deviceError, setDeviceError] = useState<string | null>(null);
  const pollTimerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Gateway channel messaging state
  const [gwTargets, setGwTargets] = useState<GatewayTarget[]>([]);
  const [gwLoading, setGwLoading] = useState(false);
  const [gwSelected, setGwSelected] = useState<string>(
    () => (typeof window !== "undefined" ? localStorage.getItem("climpire.gateway.lastTarget") ?? "" : "")
  );
  const [gwText, setGwText] = useState("");
  const [gwSending, setGwSending] = useState(false);
  const [gwStatus, setGwStatus] = useState<{ ok: boolean; msg: string } | null>(null);

  const persistSettings = useCallback(
    (next: LocalSettings) => {
      onSave(next as unknown as CompanySettings);
    },
    [onSave]
  );

  const loadOAuthStatus = useCallback(async () => {
    setOauthLoading(true);
    try {
      const next = await api.getOAuthStatus();
      setOauthStatus(next);
      setAccountDrafts((prev) => {
        const merged = { ...prev };
        for (const info of Object.values(next.providers)) {
          for (const account of info.accounts ?? []) {
            if (!merged[account.id]) {
              merged[account.id] = {
                label: account.label ?? "",
                modelOverride: account.modelOverride ?? "",
                priority: String(account.priority ?? 100),
              };
            }
          }
        }
        return merged;
      });
    } finally {
      setOauthLoading(false);
    }
  }, []);

  useEffect(() => {
    setForm(settings as LocalSettings);
    const syncedLocale = normalizeLocale((settings as LocalSettings).language) ?? "en";
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, syncedLocale);
    window.dispatchEvent(new Event("climpire-language-change"));
  }, [settings]);

  // Auto-switch to oauth tab when callback result arrives
  useEffect(() => {
    if (oauthResult) {
      setTab("oauth");
      setOauthStatus(null);
    }
  }, [oauthResult]);

  useEffect(() => {
    if (tab === "oauth" && !oauthStatus) {
      loadOAuthStatus().catch(console.error);
    }
  }, [tab, oauthStatus, loadOAuthStatus]);

  // Load CLI models when cli tab is visible
  useEffect(() => {
    if (tab !== "cli" || cliModels) return;
    setCliModelsLoading(true);
    api.getCliModels()
      .then(setCliModels)
      .catch(console.error)
      .finally(() => setCliModelsLoading(false));
  }, [tab, cliModels]);

  // Load models when oauth tab is visible and has connected providers
  useEffect(() => {
    if (tab !== "oauth" || !oauthStatus || models) return;
    const hasConnected = Object.values(oauthStatus.providers).some(p => p.connected);
    if (!hasConnected) return;
    setModelsLoading(true);
    api.getOAuthModels()
      .then(setModels)
      .catch(console.error)
      .finally(() => setModelsLoading(false));
  }, [tab, oauthStatus, models]);

  // Auto-dismiss oauth result banner after 8 seconds
  useEffect(() => {
    if (oauthResult) {
      const timer = setTimeout(() => onOauthResultClear?.(), 8000);
      return () => clearTimeout(timer);
    }
  }, [oauthResult, onOauthResultClear]);

  // Cleanup poll timer on unmount
  useEffect(() => {
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  // Load gateway targets when tab is visible
  const loadGwTargets = useCallback(() => {
    setGwLoading(true);
    setGwStatus(null);
    api.getGatewayTargets()
      .then((targets) => {
        setGwTargets(targets);
        if (targets.length > 0 && !targets.find((t) => t.sessionKey === gwSelected)) {
          const fallback = targets[0].sessionKey;
          setGwSelected(fallback);
          localStorage.setItem("climpire.gateway.lastTarget", fallback);
        }
      })
      .catch((err) => setGwStatus({ ok: false, msg: String(err) }))
      .finally(() => setGwLoading(false));
  }, [gwSelected]);

  useEffect(() => {
    if (tab === "gateway" && gwTargets.length === 0 && !gwLoading) loadGwTargets();
  }, [tab]); // eslint-disable-line react-hooks/exhaustive-deps

  const handleGwSend = useCallback(async () => {
    if (!gwSelected || !gwText.trim()) return;
    setGwSending(true);
    setGwStatus(null);
    try {
      const res = await api.sendGatewayMessage(gwSelected, gwText.trim());
      if (res.ok) {
        setGwStatus({ ok: true, msg: t({ ko: "전송 완료!", en: "Sent!", ja: "送信完了!", zh: "发送成功!" }) });
        setGwText("");
      } else {
        setGwStatus({ ok: false, msg: res.error || "Send failed" });
      }
    } catch (err) {
      setGwStatus({ ok: false, msg: String(err) });
    } finally {
      setGwSending(false);
    }
  }, [gwSelected, gwText, t]);

  function handleSave() {
    const nextLocale = normalizeLocale(form.language) ?? "en";
    window.localStorage.setItem(LANGUAGE_STORAGE_KEY, nextLocale);
    window.dispatchEvent(new Event("climpire-language-change"));
    persistSettings(form);
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  // Antigravity: web redirect OAuth (Google OAuth works on any localhost port)
  function handleConnect(provider: OAuthConnectProvider) {
    const redirectTo = window.location.origin + window.location.pathname;
    window.location.assign(api.getOAuthStartUrl(provider, redirectTo));
  }

  // GitHub Copilot: Device Code flow
  const startDeviceCodeFlow = useCallback(async () => {
    setDeviceError(null);
    setDeviceStatus(null);
    try {
      const dc = await api.startGitHubDeviceFlow();
      setDeviceCode(dc);
      setDeviceStatus("polling");
      // Open verification URL
      window.open(dc.verificationUri, "_blank");
      // Start polling with expiration timeout
      const interval = Math.max((dc.interval || 5) * 1000, 5000);
      const expiresAt = Date.now() + (dc.expiresIn || 900) * 1000;
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      pollTimerRef.current = setInterval(async () => {
        if (Date.now() > expiresAt) {
          if (pollTimerRef.current) clearInterval(pollTimerRef.current);
          pollTimerRef.current = null;
          setDeviceStatus("expired");
          setDeviceCode(null);
          setDeviceError(
            t({
              ko: "코드가 만료되었습니다. 다시 시도하세요.",
              en: "Code expired. Please try again.",
              ja: "コードの有効期限が切れました。再試行してください。",
              zh: "代码已过期，请重试。",
            })
          );
          return;
        }
        try {
          const result = await api.pollGitHubDevice(dc.stateId);
          if (result.status === "complete") {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            pollTimerRef.current = null;
            setDeviceStatus("complete");
            setDeviceCode(null);
            // Refresh OAuth status
            await loadOAuthStatus();
          } else if (result.status === "expired" || result.status === "denied") {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            pollTimerRef.current = null;
            setDeviceStatus(result.status);
            setDeviceError(
              result.status === "expired"
                ? t({ ko: "코드가 만료되었습니다", en: "Code expired", ja: "コードの期限切れ", zh: "代码已过期" })
                : t({ ko: "인증이 거부되었습니다", en: "Authentication denied", ja: "認証が拒否されました", zh: "认证被拒绝" })
            );
          } else if (result.status === "error") {
            if (pollTimerRef.current) clearInterval(pollTimerRef.current);
            pollTimerRef.current = null;
            setDeviceStatus("error");
            setDeviceError(
              result.error ||
                t({ ko: "알 수 없는 오류", en: "Unknown error", ja: "不明なエラー", zh: "未知错误" })
            );
          }
          // "pending" and "slow_down" → keep polling
        } catch {
          // Network error — keep polling
        }
      }, interval);
    } catch (err) {
      setDeviceError(err instanceof Error ? err.message : String(err));
      setDeviceStatus("error");
    }
  }, [t]);

  async function handleDisconnect(provider: OAuthConnectProvider) {
    setDisconnecting(provider);
    try {
      await api.disconnectOAuth(provider);
      await loadOAuthStatus();
      // Reset device code state if disconnecting github-copilot
      if (provider === "github-copilot") {
        setDeviceCode(null);
        setDeviceStatus(null);
        if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      }
    } catch (err) {
      console.error("Disconnect failed:", err);
    } finally {
      setDisconnecting(null);
    }
  }

  function updateAccountDraft(accountId: string, patch: Partial<{ label: string; modelOverride: string; priority: string }>) {
    setAccountDrafts((prev) => ({
      ...prev,
      [accountId]: {
        label: prev[accountId]?.label ?? "",
        modelOverride: prev[accountId]?.modelOverride ?? "",
        priority: prev[accountId]?.priority ?? "100",
        ...patch,
      },
    }));
  }

  async function handleActivateAccount(
    provider: OAuthConnectProvider,
    accountId: string,
    currentlyActive: boolean,
  ) {
    setSavingAccountId(accountId);
    try {
      await api.activateOAuthAccount(provider, accountId, currentlyActive ? "remove" : "add");
      await loadOAuthStatus();
    } catch (err) {
      console.error("Activate account failed:", err);
    } finally {
      setSavingAccountId(null);
    }
  }

  async function handleSaveAccount(accountId: string) {
    const draft = accountDrafts[accountId];
    if (!draft) return;
    setSavingAccountId(accountId);
    try {
      await api.updateOAuthAccount(accountId, {
        label: draft.label.trim() || null,
        model_override: draft.modelOverride.trim() || null,
        priority: Number.isFinite(Number(draft.priority)) ? Math.max(1, Math.round(Number(draft.priority))) : 100,
      });
      await loadOAuthStatus();
    } catch (err) {
      console.error("Save account failed:", err);
    } finally {
      setSavingAccountId(null);
    }
  }

  async function handleToggleAccount(accountId: string, nextStatus: "active" | "disabled") {
    setSavingAccountId(accountId);
    try {
      await api.updateOAuthAccount(accountId, { status: nextStatus });
      await loadOAuthStatus();
    } catch (err) {
      console.error("Toggle account failed:", err);
    } finally {
      setSavingAccountId(null);
    }
  }

  async function handleDeleteAccount(provider: OAuthConnectProvider, accountId: string) {
    if (!window.confirm(
      t({
        ko: "이 OAuth 계정을 삭제하시겠습니까?",
        en: "Delete this OAuth account?",
        ja: "この OAuth アカウントを削除しますか？",
        zh: "要删除此 OAuth 账号吗？",
      }),
    )) return;
    setSavingAccountId(accountId);
    try {
      await api.deleteOAuthAccount(provider, accountId);
      await loadOAuthStatus();
    } catch (err) {
      console.error("Delete account failed:", err);
    } finally {
      setSavingAccountId(null);
    }
  }

  return (
    <div className="mx-auto max-w-2xl space-y-4 sm:space-y-6">
      <h2 className="text-xl font-bold text-white flex items-center gap-2">
        ⚙️ {t({ ko: "설정", en: "Settings", ja: "設定", zh: "设置" })}
      </h2>

      {/* Tab navigation */}
      <div className="flex flex-wrap gap-1 border-b border-slate-700/50 pb-1">
        {[
          {
            key: "general",
            label: t({ ko: "일반 설정", en: "General", ja: "一般設定", zh: "常规设置" }),
            icon: "⚙️",
          },
          {
            key: "cli",
            label: t({ ko: "CLI 도구", en: "CLI Tools", ja: "CLI ツール", zh: "CLI 工具" }),
            icon: "🔧",
          },
          {
            key: "oauth",
            label: t({ ko: "OAuth 인증", en: "OAuth", ja: "OAuth 認証", zh: "OAuth 认证" }),
            icon: "🔑",
          },
          {
            key: "gateway",
            label: t({ ko: "채널 메시지", en: "Channel", ja: "チャネル", zh: "频道" }),
            icon: "📡",
          },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key as typeof tab)}
            className={`flex items-center gap-1.5 rounded-t-lg px-3 py-2 text-xs font-medium transition-colors sm:px-4 sm:py-2.5 sm:text-sm ${
              tab === t.key
                ? "text-blue-400 border-b-2 border-blue-400"
                : "text-slate-400 hover:text-slate-200"
            }`}
          >
            <span>{t.icon}</span>
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {/* General Settings Tab */}
      {tab === "general" && (
      <>
      <section className="space-y-4 rounded-xl border border-slate-700/50 bg-slate-800/60 p-4 sm:p-5">
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
          {t({ ko: "회사 정보", en: "Company", ja: "会社情報", zh: "公司信息" })}
        </h3>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            {t({ ko: "회사명", en: "Company Name", ja: "会社名", zh: "公司名称" })}
          </label>
          <input
            type="text"
            value={form.companyName}
            onChange={(e) =>
              setForm({ ...form, companyName: e.target.value })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          />
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            {t({ ko: "CEO 이름", en: "CEO Name", ja: "CEO 名", zh: "CEO 名称" })}
          </label>
          <input
            type="text"
            value={form.ceoName}
            onChange={(e) =>
              setForm({ ...form, ceoName: e.target.value })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          />
        </div>

        <div className="flex items-center gap-3">
          <label className="text-sm text-slate-300">
            {t({ ko: "자동 배정", en: "Auto Assign", ja: "自動割り当て", zh: "自动分配" })}
          </label>
          <button
            onClick={() =>
              setForm({ ...form, autoAssign: !form.autoAssign })
            }
            className={`w-10 h-5 rounded-full transition-colors relative ${
              form.autoAssign ? "bg-blue-500" : "bg-slate-600"
            }`}
          >
            <div
              className={`w-4 h-4 bg-white rounded-full absolute top-0.5 transition-all ${
                form.autoAssign ? "left-5.5" : "left-0.5"
              }`}
            />
          </button>
        </div>

        <div className="flex items-center gap-3">
          <label className="text-sm text-slate-300">
            {t({ ko: "OAuth 자동 스왑", en: "OAuth Auto Swap", ja: "OAuth 自動スワップ", zh: "OAuth 自动切换" })}
          </label>
          <button
            onClick={() =>
              setForm({ ...form, oauthAutoSwap: !(form.oauthAutoSwap !== false) })
            }
            className={`w-10 h-5 rounded-full transition-colors relative ${
              form.oauthAutoSwap !== false ? "bg-blue-500" : "bg-slate-600"
            }`}
            title={t({
              ko: "실패/한도 시 다음 OAuth 계정으로 자동 전환",
              en: "Auto-switch to next OAuth account on failures/limits",
              ja: "失敗/上限時に次の OAuth アカウントへ自動切替",
              zh: "失败/额度限制时自动切换到下一个 OAuth 账号",
            })}
          >
            <div
              className={`w-4 h-4 bg-white rounded-full absolute top-0.5 transition-all ${
                form.oauthAutoSwap !== false ? "left-5.5" : "left-0.5"
              }`}
            />
          </button>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            {t({ ko: "기본 CLI 프로바이더", en: "Default CLI Provider", ja: "デフォルト CLI プロバイダ", zh: "默认 CLI 提供方" })}
          </label>
          <select
            value={form.defaultProvider}
            onChange={(e) =>
              setForm({
                ...form,
                defaultProvider: e.target.value as CliProvider,
              })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="claude">Claude Code</option>
            <option value="codex">Codex CLI</option>
            <option value="gemini">Gemini CLI</option>
            <option value="opencode">OpenCode</option>
          </select>
        </div>

        <div>
          <label className="block text-xs text-slate-400 mb-1">
            {t({ ko: "언어", en: "Language", ja: "言語", zh: "语言" })}
          </label>
          <select
            value={form.language}
            onChange={(e) =>
              setForm({
                ...form,
                language: e.target.value as Locale,
              })
            }
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
          >
            <option value="ko">{t({ ko: "한국어", en: "Korean", ja: "韓国語", zh: "韩语" })}</option>
            <option value="en">{t({ ko: "영어", en: "English", ja: "英語", zh: "英语" })}</option>
            <option value="ja">{t({ ko: "일본어", en: "Japanese", ja: "日本語", zh: "日语" })}</option>
            <option value="zh">{t({ ko: "중국어", en: "Chinese", ja: "中国語", zh: "中文" })}</option>
          </select>
        </div>
      </section>

      {/* Save */}
      <div className="flex justify-end gap-3">
        {saved && (
          <span className="text-green-400 text-sm self-center">
            ✅ {t({ ko: "저장 완료", en: "Saved", ja: "保存完了", zh: "已保存" })}
          </span>
        )}
        <button
          onClick={handleSave}
          className="px-6 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors"
        >
          {t({ ko: "저장", en: "Save", ja: "保存", zh: "保存" })}
        </button>
      </div>
      </>
      )}

      {/* CLI Status Tab */}
      {tab === "cli" && (
      <section className="space-y-4 rounded-xl border border-slate-700/50 bg-slate-800/60 p-4 sm:p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            {t({ ko: "CLI 도구 상태", en: "CLI Tool Status", ja: "CLI ツール状態", zh: "CLI 工具状态" })}
          </h3>
          <button
            onClick={onRefreshCli}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            🔄 {t({ ko: "새로고침", en: "Refresh", ja: "更新", zh: "刷新" })}
          </button>
        </div>

        {cliStatus ? (
          <div className="space-y-2">
            {Object.entries(cliStatus)
              .filter(([provider]) => !["copilot", "antigravity"].includes(provider))
              .map(([provider, status]) => {
              const info = CLI_INFO[provider];
              const isReady = status.installed && status.authenticated;
              const hasSubModel = provider === "claude" || provider === "codex";
              const modelList = cliModels?.[provider] ?? [];
              const currentModel = form.providerModelConfig?.[provider]?.model || "";
              const currentSubModel = form.providerModelConfig?.[provider]?.subModel || "";
              const currentReasoningLevel = form.providerModelConfig?.[provider]?.reasoningLevel || "";

              // For Codex: find the selected model's reasoning levels
              const selectedModel = modelList.find((m) => m.slug === currentModel);
              const reasoningLevels = selectedModel?.reasoningLevels;
              const defaultReasoning = selectedModel?.defaultReasoningLevel || "";

              return (
                <div
                  key={provider}
                  className="bg-slate-700/30 rounded-lg p-3 space-y-2"
                >
                  <div className="flex items-center gap-3">
                    <span className="text-lg">{info?.icon ?? "?"}</span>
                    <div className="flex-1">
                      <div className="text-sm text-white">
                        {info?.label ?? provider}
                      </div>
                      <div className="text-xs text-slate-500">
                        {status.version ?? t({ ko: "미설치", en: "Not installed", ja: "未インストール", zh: "未安装" })}
                      </div>
                    </div>
                    <div className="flex gap-2">
                      <span
                        className={`text-xs px-2 py-0.5 rounded-full ${
                          status.installed
                            ? "bg-green-500/20 text-green-400"
                            : "bg-slate-600/50 text-slate-400"
                        }`}
                      >
                        {status.installed
                          ? t({ ko: "설치됨", en: "Installed", ja: "インストール済み", zh: "已安装" })
                          : t({ ko: "미설치", en: "Not installed", ja: "未インストール", zh: "未安装" })}
                      </span>
                      {status.installed && (
                        <span
                          className={`text-xs px-2 py-0.5 rounded-full ${
                            status.authenticated
                              ? "bg-blue-500/20 text-blue-400"
                              : "bg-yellow-500/20 text-yellow-400"
                          }`}
                        >
                          {status.authenticated
                            ? t({ ko: "인증됨", en: "Authenticated", ja: "認証済み", zh: "已认证" })
                            : t({ ko: "미인증", en: "Not Authenticated", ja: "未認証", zh: "未认证" })}
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Model selection — only for installed+authenticated CLI providers */}
                  {isReady && (
                    <div className="space-y-1.5 pl-0 sm:pl-8">
                      {/* Main model */}
                      <div className="flex min-w-0 flex-col items-stretch gap-1.5 sm:flex-row sm:items-center sm:gap-2">
                        <span className="w-auto shrink-0 text-xs text-slate-400 sm:w-20">
                          {hasSubModel
                            ? t({ ko: "메인 모델:", en: "Main model:", ja: "メインモデル:", zh: "主模型:" })
                            : t({ ko: "모델:", en: "Model:", ja: "モデル:", zh: "模型:" })}
                        </span>
                        {cliModelsLoading ? (
                          <span className="text-xs text-slate-500 animate-pulse">
                            {t({ ko: "로딩 중...", en: "Loading...", ja: "読み込み中...", zh: "加载中..." })}
                          </span>
                        ) : modelList.length > 0 ? (
                          <select
                            value={currentModel}
                            onChange={(e) => {
                              const newSlug = e.target.value;
                              const newModel = modelList.find((m) => m.slug === newSlug);
                              const prev = form.providerModelConfig?.[provider] || {};
                              const newConfig = {
                                ...form.providerModelConfig,
                                [provider]: {
                                  ...prev,
                                  model: newSlug,
                                  reasoningLevel: newModel?.defaultReasoningLevel || undefined,
                                },
                              };
                              const newForm = { ...form, providerModelConfig: newConfig };
                              setForm(newForm);
                              persistSettings(newForm);
                            }}
                            className="w-full min-w-0 rounded border border-slate-600 bg-slate-700/50 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none sm:flex-1"
                          >
                            <option value="">{t({ ko: "기본값", en: "Default", ja: "デフォルト", zh: "默认" })}</option>
                            {modelList.map((m) => (
                              <option key={m.slug} value={m.slug}>
                                {m.displayName || m.slug}
                              </option>
                            ))}
                          </select>
                        ) : (
                          <span className="text-xs text-slate-500">
                            {t({ ko: "모델 목록 없음", en: "No models", ja: "モデル一覧なし", zh: "无模型列表" })}
                          </span>
                        )}
                      </div>

                      {/* Reasoning level dropdown — Codex only */}
                      {provider === "codex" && reasoningLevels && reasoningLevels.length > 0 && (
                        <div className="flex min-w-0 flex-col items-stretch gap-1.5 sm:flex-row sm:items-center sm:gap-2">
                          <span className="w-auto shrink-0 text-xs text-slate-400 sm:w-20">
                            {t({ ko: "추론 레벨:", en: "Reasoning:", ja: "推論レベル:", zh: "推理级别:" })}
                          </span>
                          <select
                            value={currentReasoningLevel || defaultReasoning}
                            onChange={(e) => {
                              const prev = form.providerModelConfig?.[provider] || { model: "" };
                              const newConfig = {
                                ...form.providerModelConfig,
                                [provider]: { ...prev, reasoningLevel: e.target.value },
                              };
                              const newForm = { ...form, providerModelConfig: newConfig };
                              setForm(newForm);
                              persistSettings(newForm);
                            }}
                            className="w-full min-w-0 rounded border border-slate-600 bg-slate-700/50 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none sm:flex-1"
                          >
                            {reasoningLevels.map((rl) => (
                              <option key={rl.effort} value={rl.effort}>
                                {rl.effort} ({rl.description})
                              </option>
                            ))}
                          </select>
                        </div>
                      )}

                      {/* Sub-agent model — claude/codex only */}
                      {hasSubModel && (
                        <>
                          <div className="flex min-w-0 flex-col items-stretch gap-1.5 sm:flex-row sm:items-center sm:gap-2">
                            <span className="w-auto shrink-0 text-xs text-slate-400 sm:w-20">
                              {t({ ko: "알바생 모델:", en: "Sub-agent model:", ja: "サブモデル:", zh: "子代理模型:" })}
                            </span>
                            {cliModelsLoading ? (
                              <span className="text-xs text-slate-500 animate-pulse">
                                {t({ ko: "로딩 중...", en: "Loading...", ja: "読み込み中...", zh: "加载中..." })}
                              </span>
                            ) : modelList.length > 0 ? (
                              <select
                                value={currentSubModel}
                                onChange={(e) => {
                                  const newSlug = e.target.value;
                                  const newSubModel = modelList.find((m) => m.slug === newSlug);
                                  const prev = form.providerModelConfig?.[provider] || { model: "" };
                                  const newConfig = {
                                    ...form.providerModelConfig,
                                    [provider]: {
                                      ...prev,
                                      subModel: newSlug,
                                      subModelReasoningLevel: newSubModel?.defaultReasoningLevel || undefined,
                                    },
                                  };
                                  const newForm = { ...form, providerModelConfig: newConfig };
                                  setForm(newForm);
                                  persistSettings(newForm);
                                }}
                                className="w-full min-w-0 rounded border border-slate-600 bg-slate-700/50 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none sm:flex-1"
                              >
                                <option value="">{t({ ko: "기본값", en: "Default", ja: "デフォルト", zh: "默认" })}</option>
                                {modelList.map((m) => (
                                  <option key={m.slug} value={m.slug}>
                                    {m.displayName || m.slug}
                                  </option>
                                ))}
                              </select>
                            ) : (
                              <span className="text-xs text-slate-500">
                                {t({ ko: "모델 목록 없음", en: "No models", ja: "モデル一覧なし", zh: "无模型列表" })}
                              </span>
                            )}
                          </div>

                          {/* Sub-agent reasoning level — Codex only */}
                          {(() => {
                            const subSelected = modelList.find((m) => m.slug === currentSubModel);
                            const subLevels = subSelected?.reasoningLevels;
                            const subDefault = subSelected?.defaultReasoningLevel || "";
                            const currentSubRL = form.providerModelConfig?.[provider]?.subModelReasoningLevel || "";
                            if (provider !== "codex" || !subLevels || subLevels.length === 0) return null;
                            return (
                              <div className="flex min-w-0 flex-col items-stretch gap-1.5 sm:flex-row sm:items-center sm:gap-2">
                                <span className="w-auto shrink-0 text-xs text-slate-400 sm:w-20">
                                  {t({ ko: "알바 추론:", en: "Sub reasoning:", ja: "サブ推論:", zh: "子推理:" })}
                                </span>
                                <select
                                  value={currentSubRL || subDefault}
                                  onChange={(e) => {
                                    const prev = form.providerModelConfig?.[provider] || { model: "" };
                                    const newConfig = {
                                      ...form.providerModelConfig,
                                      [provider]: { ...prev, subModelReasoningLevel: e.target.value },
                                    };
                                    const newForm = { ...form, providerModelConfig: newConfig };
                                    setForm(newForm);
                                    persistSettings(newForm);
                                  }}
                                  className="w-full min-w-0 rounded border border-slate-600 bg-slate-700/50 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none sm:flex-1"
                                >
                                  {subLevels.map((rl) => (
                                    <option key={rl.effort} value={rl.effort}>
                                      {rl.effort} ({rl.description})
                                    </option>
                                  ))}
                                </select>
                              </div>
                            );
                          })()}
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ) : (
          <div className="text-center py-4 text-slate-500 text-sm">
            {t({ ko: "로딩 중...", en: "Loading...", ja: "読み込み中...", zh: "加载中..." })}
          </div>
        )}

        <p className="text-xs text-slate-500">
          {t({
            ko: "각 에이전트의 CLI 도구는 오피스에서 에이전트 클릭 후 변경할 수 있습니다. Copilot/Antigravity 모델은 OAuth 탭에서 설정합니다.",
            en: "Each agent's CLI tool can be changed in Office by clicking an agent. Configure Copilot/Antigravity models in OAuth tab.",
            ja: "各エージェントの CLI ツールは Office でエージェントをクリックして変更できます。Copilot/Antigravity のモデルは OAuth タブで設定してください。",
            zh: "每个代理的 CLI 工具可在 Office 中点击代理后修改。Copilot/Antigravity 模型请在 OAuth 页签配置。",
          })}
        </p>
      </section>
      )}

      {/* OAuth Tab */}
      {tab === "oauth" && (
      <section className="space-y-4 rounded-xl border border-slate-700/50 bg-slate-800/60 p-4 sm:p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            {t({ ko: "OAuth 인증 현황", en: "OAuth Status", ja: "OAuth 認証状態", zh: "OAuth 认证状态" })}
          </h3>
          <button
            onClick={() => {
              setOauthStatus(null);
              setOauthLoading(true);
              loadOAuthStatus().catch(console.error);
            }}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors"
          >
            🔄 {t({ ko: "새로고침", en: "Refresh", ja: "更新", zh: "刷新" })}
          </button>
        </div>

        {/* OAuth callback result banner */}
        {oauthResult && (
          <div className={`flex items-center justify-between px-3 py-2 rounded-lg text-sm ${
            oauthResult.error
              ? "bg-red-500/10 text-red-400 border border-red-500/20"
              : "bg-green-500/10 text-green-400 border border-green-500/20"
          }`}>
            <span>
              {oauthResult.error
                ? `${t({ ko: "OAuth 연결 실패", en: "OAuth connection failed", ja: "OAuth 接続失敗", zh: "OAuth 连接失败" })}: ${oauthResult.error}`
                : `${OAUTH_INFO[oauthResult.provider || ""]?.label || oauthResult.provider} ${t({ ko: "연결 완료!", en: "connected!", ja: "接続完了!", zh: "连接成功!" })}`}
            </span>
            <button
              onClick={() => onOauthResultClear?.()}
              className="text-xs opacity-60 hover:opacity-100 ml-2"
            >
              ✕
            </button>
          </div>
        )}

        {/* Storage status */}
        {oauthStatus && (
          <div className={`flex items-center gap-2 px-3 py-2 rounded-lg text-xs ${
            oauthStatus.storageReady
              ? "bg-green-500/10 text-green-400 border border-green-500/20"
              : "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
          }`}>
            <span>{oauthStatus.storageReady ? "🔒" : "⚠️"}</span>
            <span>
              {oauthStatus.storageReady
                ? t({
                    ko: "OAuth 저장소 활성화됨 (암호화 키 설정됨)",
                    en: "OAuth storage is active (encryption key configured)",
                    ja: "OAuth ストレージ有効（暗号化キー設定済み）",
                    zh: "OAuth 存储已启用（已配置加密密钥）",
                  })
                : t({
                    ko: "OAUTH_ENCRYPTION_SECRET 환경변수가 설정되지 않았습니다",
                    en: "OAUTH_ENCRYPTION_SECRET environment variable is not set",
                    ja: "OAUTH_ENCRYPTION_SECRET 環境変数が設定されていません",
                    zh: "未设置 OAUTH_ENCRYPTION_SECRET 环境变量",
                  })}
            </span>
          </div>
        )}

        {oauthLoading ? (
          <div className="text-center py-8 text-slate-500 text-sm">
            {t({ ko: "로딩 중...", en: "Loading...", ja: "読み込み中...", zh: "加载中..." })}
          </div>
        ) : oauthStatus ? (
          <>
            {/* Connected services section */}
            {(() => {
              const detectedProviders = Object.entries(oauthStatus.providers).filter(
                ([, info]) => Boolean(info.detected ?? info.connected),
              );
              if (detectedProviders.length === 0) return null;
              const logoMap: Record<string, ({ className }: { className?: string }) => React.ReactElement> = {
                "github-copilot": GitHubCopilotLogo, antigravity: AntigravityLogo,
              };
              return (
                <div className="space-y-2">
                  <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
                    {t({ ko: "인증 상태", en: "Auth Status", ja: "認証状態", zh: "认证状态" })}
                  </div>
                  {detectedProviders.map(([provider, info]) => {
                    const oauthInfo = OAUTH_INFO[provider];
                    const LogoComp = logoMap[provider];
                    const expiresAt = info.expires_at ? new Date(info.expires_at) : null;
                    const isExpired = expiresAt ? expiresAt.getTime() < Date.now() : false;
                    const isWebOAuth = info.source === "web-oauth";
                    const isFileDetected = info.source === "file-detected";
                    const isRunnable = Boolean(info.executionReady ?? info.connected);
                    const accountList = info.accounts ?? [];
                    return (
                      <div key={provider} className="space-y-2 overflow-hidden rounded-lg bg-slate-700/30 p-4">
                        <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                          <div className="flex min-w-0 flex-wrap items-center gap-x-2.5 gap-y-1">
                            {LogoComp ? <LogoComp className="w-5 h-5" /> : <span className="text-lg">🔑</span>}
                            <span className="text-sm font-medium text-white">
                              {oauthInfo?.label ?? provider}
                            </span>
                            {info.email && (
                              <span className="max-w-full break-all text-xs text-slate-400">{info.email}</span>
                            )}
                            {isFileDetected && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-600/50 text-slate-400">
                                {t({ ko: "CLI 감지", en: "CLI detected", ja: "CLI 検出", zh: "检测到 CLI" })}
                              </span>
                            )}
                            {isWebOAuth && (
                              <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400">
                                {t({ ko: "웹 OAuth", en: "Web OAuth", ja: "Web OAuth", zh: "网页 OAuth" })}
                              </span>
                            )}
                          </div>
                          <div className="flex flex-wrap items-center gap-2 sm:justify-end">
                            {/* Status badge */}
                            {!isRunnable ? (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-amber-500/20 text-amber-300">
                                {t({
                                  ko: "감지됨 (실행 불가)",
                                  en: "Detected (not runnable)",
                                  ja: "検出済み（実行不可）",
                                  zh: "已检测（不可执行）",
                                })}
                              </span>
                            ) : !isExpired ? (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-green-500/20 text-green-400">
                                {info.lastRefreshed
                                  ? t({ ko: "자동 갱신됨", en: "Auto-refreshed", ja: "自動更新済", zh: "已自动刷新" })
                                  : t({ ko: "연결됨", en: "Connected", ja: "接続中", zh: "已连接" })}
                              </span>
                            ) : info.refreshFailed ? (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-orange-500/20 text-orange-400">
                                {t({ ko: "갱신 실패", en: "Refresh failed", ja: "更新失敗", zh: "刷新失败" })}
                              </span>
                            ) : isExpired && !info.hasRefreshToken ? (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400">
                                {t({ ko: "만료됨 — 재인증 필요", en: "Expired — re-auth needed", ja: "期限切れ — 再認証が必要", zh: "已过期 — 需重新认证" })}
                              </span>
                            ) : (
                              <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/20 text-red-400">
                                {t({ ko: "만료됨", en: "Expired", ja: "期限切れ", zh: "已过期" })}
                              </span>
                            )}
                            {/* Manual refresh button (only for providers with refresh token) */}
                            {info.hasRefreshToken && isWebOAuth && (
                              <button
                                onClick={async () => {
                                  setRefreshing(provider);
                                  try {
                                    await api.refreshOAuthToken(provider as OAuthConnectProvider);
                                    await loadOAuthStatus();
                                  } catch (err) {
                                    console.error("Manual refresh failed:", err);
                                  } finally {
                                    setRefreshing(null);
                                  }
                                }}
                                disabled={refreshing === provider}
                                className="text-xs px-2.5 py-1 rounded-lg bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/30 transition-colors disabled:opacity-50"
                              >
                                {refreshing === provider
                                  ? t({ ko: "갱신 중...", en: "Refreshing...", ja: "更新中...", zh: "刷新中..." })
                                  : t({ ko: "갱신", en: "Refresh", ja: "更新", zh: "刷新" })}
                              </button>
                            )}
                            {/* Re-connect button for expired tokens without refresh token */}
                            {isExpired && !info.hasRefreshToken && isWebOAuth && (
                              <button
                                onClick={() => handleConnect(provider as OAuthConnectProvider)}
                                className="text-xs px-2.5 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors"
                              >
                                {t({ ko: "재연결", en: "Reconnect", ja: "再接続", zh: "重新连接" })}
                              </button>
                            )}
                            {isWebOAuth && (
                              <button
                                onClick={() => handleDisconnect(provider as OAuthConnectProvider)}
                                disabled={disconnecting === provider}
                                className="text-xs px-2.5 py-1 rounded-lg bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/30 transition-colors disabled:opacity-50"
                              >
                                {disconnecting === provider
                                  ? t({ ko: "해제 중...", en: "Disconnecting...", ja: "切断中...", zh: "断开中..." })
                                  : t({ ko: "연결 해제", en: "Disconnect", ja: "接続解除", zh: "断开连接" })}
                              </button>
                            )}
                          </div>
                        </div>
                        {info.requiresWebOAuth && (
                          <div className="text-[11px] text-amber-300 bg-amber-500/10 border border-amber-500/20 rounded px-2.5 py-1.5">
                            {t({
                              ko: "CLI에서 감지된 자격 증명은 Claw-Empire 실행에 직접 사용되지 않습니다. Web OAuth로 다시 연결하세요.",
                              en: "CLI-detected credentials are not used directly for Claw-Empire execution. Reconnect with Web OAuth.",
                              ja: "CLI 検出の資格情報は Claw-Empire 実行では直接利用されません。Web OAuth で再接続してください。",
                              zh: "CLI 检测到的凭据不会直接用于 Claw-Empire 执行。请使用 Web OAuth 重新连接。",
                            })}
                          </div>
                        )}
                        {(info.scope || expiresAt || (info.created_at > 0)) && (
                          <div className="grid grid-cols-1 gap-2 text-xs sm:grid-cols-2">
                            {info.scope && (
                              <div className="col-span-2">
                                <span className="text-slate-500">
                                  {t({ ko: "스코프", en: "Scope", ja: "スコープ", zh: "范围" })}:{" "}
                                </span>
                                <span className="break-all font-mono text-[10px] leading-relaxed text-slate-300">{info.scope}</span>
                              </div>
                            )}
                            {expiresAt && (
                              <div>
                                <span className="text-slate-500">
                                  {t({ ko: "만료", en: "Expires", ja: "期限", zh: "到期" })}:{" "}
                                </span>
                                <span className={isExpired ? "text-red-400" : "text-slate-300"}>
                                  {expiresAt.toLocaleString(localeTag)}
                                </span>
                              </div>
                            )}
                            {info.created_at > 0 && (
                              <div>
                                <span className="text-slate-500">
                                  {t({ ko: "등록", en: "Created", ja: "登録", zh: "创建" })}:{" "}
                                </span>
                                <span className="text-slate-300">
                                  {new Date(info.created_at).toLocaleString(localeTag)}
                                </span>
                              </div>
                            )}
                          </div>
                        )}
                        {/* Model selection dropdown */}
                        {(() => {
                          const modelKey = provider === "github-copilot" ? "copilot" : provider === "antigravity" ? "antigravity" : null;
                          if (!modelKey) return null;
                          const modelList = models?.[modelKey];
                          const currentModel = form.providerModelConfig?.[modelKey]?.model || "";
                          return (
                            <div className="flex min-w-0 flex-col items-stretch gap-1.5 pt-1 sm:flex-row sm:items-center sm:gap-2">
                              <span className="w-auto shrink-0 text-xs text-slate-400">
                                {t({ ko: "모델:", en: "Model:", ja: "モデル:", zh: "模型:" })}
                              </span>
                              {modelsLoading ? (
                                <span className="text-xs text-slate-500 animate-pulse">
                                  {t({ ko: "로딩 중...", en: "Loading...", ja: "読み込み中...", zh: "加载中..." })}
                                </span>
                              ) : modelList && modelList.length > 0 ? (
                                <select
                                  value={currentModel}
                                  onChange={(e) => {
                                    const newConfig = { ...form.providerModelConfig, [modelKey]: { model: e.target.value } };
                                    const newForm = { ...form, providerModelConfig: newConfig };
                                    setForm(newForm);
                                    persistSettings(newForm);
                                  }}
                                  className="w-full min-w-0 rounded border border-slate-600 bg-slate-700/50 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none sm:flex-1"
                                >
                                  {!currentModel && (
                                    <option value="">
                                      {t({ ko: "선택하세요...", en: "Select...", ja: "選択してください...", zh: "请选择..." })}
                                    </option>
                                  )}
                                  {modelList.map((m) => (
                                    <option key={m} value={m}>{m}</option>
                                  ))}
                                </select>
                              ) : (
                                <span className="text-xs text-slate-500">
                                  {t({ ko: "모델 목록 없음", en: "No models", ja: "モデル一覧なし", zh: "无模型列表" })}
                                </span>
                              )}
                            </div>
                          );
                        })()}

                        {accountList.length > 0 && (
                          <div className="space-y-2 rounded-lg border border-slate-600/40 bg-slate-800/40 p-2.5">
                            <div className="flex flex-wrap items-center justify-between gap-1.5">
                              <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                                {t({ ko: "계정 풀", en: "Account Pool", ja: "アカウントプール", zh: "账号池" })}
                              </div>
                              <div className="text-[10px] text-slate-500 text-right">
                                {t({
                                  ko: "여러 계정을 동시에 활성 가능 · 우선순위 숫자가 낮을수록 먼저 시도",
                                  en: "Multiple active accounts supported · lower priority runs first",
                                  ja: "複数アクティブ対応 · 優先度の数字が小さいほど先に実行",
                                  zh: "支持多账号同时激活 · 优先级数字越小越先执行",
                                })}
                              </div>
                            </div>
                            {accountList.map((account) => {
                              const modelKey = provider === "github-copilot" ? "copilot" : provider === "antigravity" ? "antigravity" : null;
                              const modelList = modelKey ? (models?.[modelKey] ?? []) : [];
                              const draft = accountDrafts[account.id] ?? {
                                label: account.label ?? "",
                                modelOverride: account.modelOverride ?? "",
                                priority: String(account.priority ?? 100),
                              };
                              const hasCustomOverride = Boolean(draft.modelOverride) && !modelList.includes(draft.modelOverride);
                              return (
                                <div key={account.id} className="rounded border border-slate-700/70 bg-slate-900/30 p-2.5 space-y-2">
                                  <div className="flex flex-wrap items-center gap-1.5">
                                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${account.active ? "bg-green-500/20 text-green-300" : "bg-slate-700 text-slate-400"}`}>
                                      {account.active
                                        ? t({ ko: "활성", en: "Active", ja: "有効", zh: "活动" })
                                        : t({ ko: "대기", en: "Standby", ja: "待機", zh: "待命" })}
                                    </span>
                                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${account.executionReady ? "bg-blue-500/20 text-blue-300" : "bg-amber-500/20 text-amber-300"}`}>
                                      {account.executionReady
                                        ? t({ ko: "실행 가능", en: "Runnable", ja: "実行可能", zh: "可执行" })
                                        : t({ ko: "실행 불가", en: "Not runnable", ja: "実行不可", zh: "不可执行" })}
                                    </span>
                                    {account.email && (
                                      <span className="text-[11px] text-slate-300 break-all">{account.email}</span>
                                    )}
                                  </div>

                                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                                    <label className="space-y-1">
                                      <span className="block text-[10px] uppercase tracking-wider text-slate-500">
                                        {t({ ko: "라벨", en: "Label", ja: "ラベル", zh: "标签" })}
                                      </span>
                                      <input
                                        value={draft.label}
                                        onChange={(e) => updateAccountDraft(account.id, { label: e.target.value })}
                                        placeholder={t({ ko: "계정 별칭", en: "Account alias", ja: "アカウント別名", zh: "账号别名" })}
                                        className="w-full rounded border border-slate-600 bg-slate-800/70 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none"
                                      />
                                    </label>
                                    <label className="space-y-1">
                                      <span className="block text-[10px] uppercase tracking-wider text-slate-500">
                                        {t({ ko: "모델 오버라이드", en: "Model Override", ja: "モデル上書き", zh: "模型覆盖" })}
                                      </span>
                                      <select
                                        value={draft.modelOverride}
                                        onChange={(e) => updateAccountDraft(account.id, { modelOverride: e.target.value })}
                                        className="w-full rounded border border-slate-600 bg-slate-800/70 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none"
                                      >
                                        <option value="">
                                          {t({
                                            ko: "프로바이더 기본값 사용",
                                            en: "Use provider default",
                                            ja: "プロバイダ既定値を使用",
                                            zh: "使用提供方默认值",
                                          })}
                                        </option>
                                        {hasCustomOverride && (
                                          <option value={draft.modelOverride}>
                                            {draft.modelOverride}
                                          </option>
                                        )}
                                        {modelList.map((m) => (
                                          <option key={m} value={m}>
                                            {m}
                                          </option>
                                        ))}
                                      </select>
                                    </label>
                                    <label className="space-y-1">
                                      <span className="block text-[10px] uppercase tracking-wider text-slate-500">
                                        {t({ ko: "우선순위", en: "Priority", ja: "優先度", zh: "优先级" })}
                                      </span>
                                      <input
                                        type="number"
                                        min={1}
                                        step={1}
                                        value={draft.priority}
                                        onChange={(e) => updateAccountDraft(account.id, { priority: e.target.value })}
                                        placeholder="100"
                                        className="w-full rounded border border-slate-600 bg-slate-800/70 px-2 py-1 text-xs text-white focus:border-blue-500 focus:outline-none"
                                      />
                                    </label>
                                  </div>

                                  <div className="flex flex-wrap gap-1.5">
                                    <button
                                      onClick={() => handleActivateAccount(provider as OAuthConnectProvider, account.id, account.active)}
                                      disabled={savingAccountId === account.id || account.status !== "active"}
                                      className={`text-[11px] px-2 py-1 rounded disabled:opacity-50 ${
                                        account.active
                                          ? "bg-orange-600/20 hover:bg-orange-600/35 text-orange-200"
                                          : "bg-blue-600/30 hover:bg-blue-600/45 text-blue-200"
                                      }`}
                                    >
                                      {account.active
                                        ? t({ ko: "풀 해제", en: "Pool Off", ja: "プール解除", zh: "移出池" })
                                        : t({ ko: "풀 추가", en: "Pool On", ja: "プール追加", zh: "加入池" })}
                                    </button>
                                    <button
                                      onClick={() => handleSaveAccount(account.id)}
                                      disabled={savingAccountId === account.id}
                                      className="text-[11px] px-2 py-1 rounded bg-emerald-600/25 hover:bg-emerald-600/40 text-emerald-200 disabled:opacity-50"
                                    >
                                      {t({ ko: "저장", en: "Save", ja: "保存", zh: "保存" })}
                                    </button>
                                    <button
                                      onClick={() => handleToggleAccount(account.id, account.status === "active" ? "disabled" : "active")}
                                      disabled={savingAccountId === account.id}
                                      className="text-[11px] px-2 py-1 rounded bg-amber-600/20 hover:bg-amber-600/35 text-amber-200 disabled:opacity-50"
                                    >
                                      {account.status === "active"
                                        ? t({ ko: "비활성", en: "Disable", ja: "無効化", zh: "禁用" })
                                        : t({ ko: "활성화", en: "Enable", ja: "有効化", zh: "启用" })}
                                    </button>
                                    <button
                                      onClick={() => handleDeleteAccount(provider as OAuthConnectProvider, account.id)}
                                      disabled={savingAccountId === account.id}
                                      className="text-[11px] px-2 py-1 rounded bg-red-600/20 hover:bg-red-600/35 text-red-300 disabled:opacity-50"
                                    >
                                      {t({ ko: "삭제", en: "Delete", ja: "削除", zh: "删除" })}
                                    </button>
                                  </div>

                                  {account.lastError && (
                                    <div className="text-[10px] text-red-300 break-words">
                                      {account.lastError}
                                    </div>
                                  )}
                                </div>
                              );
                            })}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              );
            })()}

            {/* New OAuth Connect section — provider cards */}
            <div className="space-y-3">
              <div className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
                {t({ ko: "OAuth 계정 추가", en: "Add OAuth Account", ja: "OAuth アカウント追加", zh: "添加 OAuth 账号" })}
              </div>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {CONNECTABLE_PROVIDERS.map(({ id, label, Logo, description }) => {
                  const providerInfo = oauthStatus.providers[id];
                  const isConnected = Boolean(providerInfo?.executionReady ?? providerInfo?.connected);
                  const isDetectedOnly = Boolean(providerInfo?.detected) && !isConnected;
                  const storageOk = oauthStatus.storageReady;
                  const isGitHub = id === "github-copilot";

                  return (
                    <div
                      key={id}
                      className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${
                        isConnected
                          ? "bg-green-500/5 border-green-500/30"
                          : isDetectedOnly
                          ? "bg-amber-500/5 border-amber-500/30"
                          : storageOk
                          ? "bg-slate-700/30 border-slate-600/50 hover:border-blue-400/50 hover:bg-slate-700/50"
                          : "bg-slate-800/30 border-slate-700/30 opacity-50"
                      }`}
                    >
                      <Logo className="w-8 h-8" />
                      <span className="text-sm font-medium text-white">{label}</span>
                      <span className="text-[10px] text-slate-400 text-center leading-tight">{description}</span>
                      {!storageOk ? (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-yellow-500/20 text-yellow-500">
                          {t({ ko: "암호화 키 필요", en: "Encryption key required", ja: "暗号化キーが必要", zh: "需要加密密钥" })}
                        </span>
                      ) : (
                        <>
                          {isConnected ? (
                            <span className="text-[11px] px-2.5 py-1 rounded-lg bg-green-500/20 text-green-400 font-medium">
                              {t({ ko: "실행 가능", en: "Runnable", ja: "実行可能", zh: "可执行" })}
                            </span>
                          ) : isDetectedOnly ? (
                            <span className="text-[11px] px-2.5 py-1 rounded-lg bg-amber-500/20 text-amber-300 font-medium">
                              {t({ ko: "감지됨", en: "Detected", ja: "検出済み", zh: "已检测" })}
                            </span>
                          ) : null}
                          {isGitHub ? (
                            /* GitHub Copilot: Device Code flow */
                            deviceCode && deviceStatus === "polling" ? (
                              <div className="flex flex-col items-center gap-1.5">
                                <div className="text-xs text-slate-300 font-mono bg-slate-700/60 px-3 py-1.5 rounded-lg tracking-widest select-all">
                                  {deviceCode.userCode}
                                </div>
                                <span className="text-[10px] text-blue-400 animate-pulse">
                                  {t({ ko: "코드 입력 대기 중...", en: "Waiting for code...", ja: "コード入力待機中...", zh: "等待输入代码..." })}
                                </span>
                              </div>
                            ) : (
                              <button
                                onClick={startDeviceCodeFlow}
                                className="text-[11px] px-3 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors"
                              >
                                {isConnected || isDetectedOnly
                                  ? t({ ko: "계정 추가", en: "Add Account", ja: "アカウント追加", zh: "添加账号" })
                                  : t({ ko: "연결하기", en: "Connect", ja: "接続", zh: "连接" })}
                              </button>
                            )
                          ) : (
                            /* Antigravity: Web redirect OAuth */
                            <button
                              onClick={() => handleConnect(id)}
                              className="text-[11px] px-3 py-1 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium transition-colors"
                            >
                              {isConnected || isDetectedOnly
                                ? t({ ko: "계정 추가", en: "Add Account", ja: "アカウント追加", zh: "添加账号" })
                                : t({ ko: "연결하기", en: "Connect", ja: "接続", zh: "连接" })}
                            </button>
                          )}
                        </>
                      )}
                    </div>
                  );
                })}
              </div>
              {/* Device Code flow status messages */}
              {deviceStatus === "complete" && (
                <div className="text-xs text-green-400 bg-green-500/10 border border-green-500/20 px-3 py-2 rounded-lg">
                  {t({ ko: "GitHub Copilot 연결 완료!", en: "GitHub Copilot connected!", ja: "GitHub Copilot 接続完了!", zh: "GitHub Copilot 已连接!" })}
                </div>
              )}
              {deviceError && (
                <div className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 px-3 py-2 rounded-lg">
                  {deviceError}
                </div>
              )}
            </div>
          </>
        ) : null}
      </section>
      )}

      {/* Gateway Channel Messaging Tab */}
      {tab === "gateway" && (
      <section className="space-y-4 rounded-xl border border-slate-700/50 bg-slate-800/60 p-4 sm:p-5">
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">
            {t({ ko: "채널 메시지 전송", en: "Channel Messaging", ja: "チャネルメッセージ", zh: "频道消息" })}
          </h3>
          <button
            onClick={loadGwTargets}
            disabled={gwLoading}
            className="text-xs text-blue-400 hover:text-blue-300 transition-colors disabled:opacity-50"
          >
            🔄 {t({ ko: "새로고침", en: "Refresh", ja: "更新", zh: "刷新" })}
          </button>
        </div>

        {/* Channel selector */}
        <div>
          <label className="block text-xs text-slate-400 mb-1">
            {t({ ko: "대상 채널", en: "Target Channel", ja: "対象チャネル", zh: "目标频道" })}
          </label>
          {gwLoading ? (
            <div className="text-xs text-slate-500 animate-pulse py-2">
              {t({ ko: "채널 목록 로딩 중...", en: "Loading channels...", ja: "チャネル読み込み中...", zh: "正在加载频道..." })}
            </div>
          ) : gwTargets.length === 0 ? (
            <div className="text-xs text-slate-500 py-2">
              {t({
                ko: "채널이 없습니다. Gateway가 실행 중인지 확인하세요.",
                en: "No channels found. Make sure Gateway is running.",
                ja: "チャネルがありません。ゲートウェイが実行中か確認してください。",
                zh: "未找到频道。请确认网关正在运行。",
              })}
            </div>
          ) : (
            <select
              value={gwSelected}
              onChange={(e) => {
                setGwSelected(e.target.value);
                localStorage.setItem("climpire.gateway.lastTarget", e.target.value);
              }}
              className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500"
            >
              {gwTargets.map((tgt) => (
                <option key={tgt.sessionKey} value={tgt.sessionKey}>
                  {tgt.displayName} ({tgt.channel})
                </option>
              ))}
            </select>
          )}
        </div>

        {/* Message input */}
        <div>
          <label className="block text-xs text-slate-400 mb-1">
            {t({ ko: "메시지", en: "Message", ja: "メッセージ", zh: "消息" })}
          </label>
          <textarea
            value={gwText}
            onChange={(e) => setGwText(e.target.value)}
            placeholder={t({ ko: "메시지를 입력하세요...", en: "Type a message...", ja: "メッセージを入力...", zh: "输入消息..." })}
            rows={3}
            className="w-full px-3 py-2 bg-slate-700/50 border border-slate-600 rounded-lg text-white text-sm focus:outline-none focus:border-blue-500 resize-y"
            onKeyDown={(e) => {
              if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                handleGwSend();
              }
            }}
          />
        </div>

        {/* Send button + status */}
        <div className="flex items-center gap-3">
          <button
            onClick={handleGwSend}
            disabled={gwSending || !gwSelected || !gwText.trim()}
            className="px-5 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {gwSending
              ? t({ ko: "전송 중...", en: "Sending...", ja: "送信中...", zh: "发送中..." })
              : t({ ko: "전송", en: "Send", ja: "送信", zh: "发送" })}
          </button>
          <span className="text-xs text-slate-500">
            {t({ ko: "Ctrl+Enter로 전송", en: "Ctrl+Enter to send", ja: "Ctrl+Enterで送信", zh: "Ctrl+Enter 发送" })}
          </span>
        </div>

        {/* Status feedback */}
        {gwStatus && (
          <div className={`text-xs px-3 py-2 rounded-lg ${
            gwStatus.ok
              ? "bg-green-500/10 text-green-400 border border-green-500/20"
              : "bg-red-500/10 text-red-400 border border-red-500/20"
          }`}>
            {gwStatus.msg}
          </div>
        )}
      </section>
      )}
    </div>
  );
}
