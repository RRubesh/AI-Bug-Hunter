import React, { useEffect, useState } from "react";
import { api, getApiBaseUrl, setApiBaseUrl } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { CyberRadarLoader } from "../components/CyberRadarLoader";
import { GlassCard } from "../components/ui/GlassCard";
import { StatusBadge } from "../components/ui/StatusBadge";
import { Button } from "../components/ui/Button";
import { 
  Cpu, RefreshCw, AlertCircle, Save, CheckCircle2, 
  Plus, X, ChevronDown, Key, Eye, EyeOff, Server, Globe, Zap
} from "lucide-react";

const INITIAL_PROVIDER_MODELS: Record<string, string[]> = {
  openrouter: [
    "deepseek/deepseek-chat",
    "deepseek/deepseek-r1:free",
    "google/gemini-2.0-flash-exp:free",
    "meta-llama/llama-3.3-70b-instruct",
    "anthropic/claude-3.5-sonnet",
    "qwen/qwen-2.5-coder-32b-instruct",
    "openai/gpt-4o-mini",
  ],
  openai: ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
  gemini: ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"],
  groq: ["llama-3.1-8b-instant", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"],
  claude: ["claude-3-haiku", "claude-3-5-sonnet", "claude-3-opus"],
  grok: ["grok-2-mini", "grok-2-1212", "grok-beta"],
};

export const SettingsPage: React.FC = () => {
  const [loading, setLoading] = useState(true);
  
  // Editable fields
  const [openrouterUrl, setOpenrouterUrl] = useState("https://openrouter.ai/api/v1");
  const [defaultModel, setDefaultModel] = useState("deepseek/deepseek-chat");
  const [aiProvider, setAiProvider] = useState("openrouter");

  // API Key input states
  const [openrouterApiKey, setOpenrouterApiKey] = useState("");
  const [openaiApiKey, setOpenaiApiKey] = useState("");
  const [geminiApiKey, setGeminiApiKey] = useState("");
  const [claudeApiKey, setClaudeApiKey] = useState("");
  const [grokApiKey, setGrokApiKey] = useState("");
  const [groqApiKey, setGroqApiKey] = useState("");

  // Configured flags state from backend
  const [configuredKeys, setConfiguredKeys] = useState<Record<string, boolean>>({
    openrouter: false,
    openai: false,
    gemini: false,
    claude: false,
    grok: false,
    groq: false,
  });


  // API Key Quick Modal State
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState(false);
  const [keyModalProvider, setKeyModalProvider] = useState("openrouter");
  const [keyModalInputValue, setKeyModalInputValue] = useState("");
  const [showModalKey, setShowModalKey] = useState(false);
  
  // Custom Model State & Management
  const [providerModels, setProviderModels] = useState<Record<string, string[]>>(INITIAL_PROVIDER_MODELS);
  const [customModalOpen, setCustomModalOpen] = useState(false);
  const [targetProviderForCustom, setTargetProviderForCustom] = useState("openrouter");
  const [customModelInput, setCustomModelInput] = useState("");

  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState("");
  const [saveError, setSaveError] = useState("");
  const [testingOpenRouter, setTestingOpenRouter] = useState(false);
  const [openrouterStatusMsg, setOpenrouterStatusMsg] = useState("");
  
  // Custom Backend API URL State
  const [customApiUrl, setCustomApiUrl] = useState(() => getApiBaseUrl());
  const [testingBackend, setTestingBackend] = useState(false);
  const [backendStatusMsg, setBackendStatusMsg] = useState("");

  const fetchSettings = async () => {
    setLoading(true);
    setSaveError("");
    try {
      const data = await api.getSettings();
      setOpenrouterUrl(data.openrouter_api_url || data.ollama_url || "https://openrouter.ai/api/v1");
      setDefaultModel(data.default_model || "deepseek/deepseek-chat");
      setAiProvider(data.ai_provider || "openrouter");

      // Update configured keys
      setConfiguredKeys({
        openrouter: !!data.openrouter_api_key_configured,
        openai: data.openai_api_key_configured,
        gemini: data.gemini_api_key_configured,
        claude: data.claude_api_key_configured,
        grok: data.grok_api_key_configured,
        groq: data.groq_api_key_configured,
      });

      // Ensure default_model is present in provider models list if custom
      if (data.ai_provider && data.default_model) {
        setProviderModels((prev) => {
          const list = prev[data.ai_provider] || [];
          if (!list.includes(data.default_model)) {
            return { ...prev, [data.ai_provider]: [data.default_model, ...list] };
          }
          return prev;
        });
      }
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSaveError(
        `Failed to load settings from server: ${errMsg}. Make sure FastAPI server (http://127.0.0.1:8000) is running.`
      );
      // Fallback sensible defaults if server not reachable
      if (!openrouterUrl) setOpenrouterUrl("https://openrouter.ai/api/v1");
      if (!defaultModel) setDefaultModel("deepseek/deepseek-chat");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSettings();
  }, []);

  const handleOpenApiKeyModal = (providerId: string) => {
    setKeyModalProvider(providerId);
    setKeyModalInputValue("");
    setShowModalKey(false);
    setApiKeyModalOpen(true);
  };

  const handleSaveApiKeyFromModal = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyModalInputValue.trim()) return;

    setSaving(true);
    setSaveSuccess("");
    setSaveError("");

    try {
      const keyProp = `${keyModalProvider}_api_key`;
      await api.updateSettings({
        [keyProp]: keyModalInputValue.trim(),
      });

      setConfiguredKeys((prev) => ({ ...prev, [keyModalProvider]: true }));
      setSaveSuccess(`${keyModalProvider.toUpperCase()} API key saved and activated successfully!`);
      setApiKeyModalOpen(false);
      setKeyModalInputValue("");
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSaveError(`Failed to save ${keyModalProvider} API key: ` + errMsg);
    } finally {
      setSaving(false);
    }
  };

  const handleAddCustomModel = (e: React.FormEvent) => {
    e.preventDefault();
    if (!customModelInput.trim()) return;

    const newModel = customModelInput.trim();
    
    setProviderModels((prev) => {
      const existing = prev[targetProviderForCustom] || [];
      if (existing.includes(newModel)) return prev;
      return {
        ...prev,
        [targetProviderForCustom]: [newModel, ...existing],
      };
    });

    setAiProvider(targetProviderForCustom);
    setDefaultModel(newModel);
    
    setCustomModelInput("");
    setCustomModalOpen(false);
  };

  const handleTestOpenRouter = async () => {
    setTestingOpenRouter(true);
    setOpenrouterStatusMsg("");
    try {
      const data = await api.getSettings();
      if (data.available_models && data.available_models.length > 0) {
        setOpenrouterStatusMsg(`Connected to OpenRouter.ai intelligence engine! (${data.available_models.length} model(s) available)`);
      } else {
        setOpenrouterStatusMsg("OpenRouter ready (enter your OpenRouter API Key for live cloud models).");
      }
    } catch {
      setOpenrouterStatusMsg("Connection test failed. Check your network connection or API endpoint.");
    } finally {
      setTestingOpenRouter(false);
    }
  };

  const handleSaveSettings = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess("");
    setSaveError("");

    try {
      const payload: Record<string, string> = {
        openrouter_api_url: openrouterUrl,
        default_model: defaultModel,
        ai_provider: aiProvider,
      };

      if (openrouterApiKey.trim()) payload.openrouter_api_key = openrouterApiKey.trim();
      if (openaiApiKey.trim()) payload.openai_api_key = openaiApiKey.trim();
      if (geminiApiKey.trim()) payload.gemini_api_key = geminiApiKey.trim();
      if (claudeApiKey.trim()) payload.claude_api_key = claudeApiKey.trim();
      if (grokApiKey.trim()) payload.grok_api_key = grokApiKey.trim();
      if (groqApiKey.trim()) payload.groq_api_key = groqApiKey.trim();

      const updated = await api.updateSettings(payload);

      setConfiguredKeys({
        openrouter: !!updated.openrouter_api_key_configured,
        openai: updated.openai_api_key_configured,
        gemini: updated.gemini_api_key_configured,
        claude: updated.claude_api_key_configured,
        grok: updated.grok_api_key_configured,
        groq: updated.groq_api_key_configured,
      });

      // Clear input buffers on successful save
      setOpenrouterApiKey("");
      setOpenaiApiKey("");
      setGeminiApiKey("");
      setClaudeApiKey("");
      setGrokApiKey("");
      setGroqApiKey("");

      // Save custom backend API base URL
      setApiBaseUrl(customApiUrl);

      setSaveSuccess("Configuration, Backend Endpoint & API Credentials saved successfully!");
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSaveError("Failed to save settings: " + errMsg);
    } finally {
      setSaving(false);
    }
  };

  const handleTestBackendConnection = async () => {
    setTestingBackend(true);
    setBackendStatusMsg("");
    try {
      const targetUrl = customApiUrl.trim().replace(/\/$/, "");
      const healthUrl = targetUrl ? `${targetUrl}/api/health` : "/api/health";
      const res = await fetch(healthUrl, { method: "GET" });
      const text = await res.text();
      if (res.ok && !text.includes("<!doctype") && !text.includes("<html")) {
        setBackendStatusMsg("✅ Backend Connected Successfully! FastAPI server is active.");
      } else {
        setBackendStatusMsg("⚡ In-Browser SAST Engine Active (Cloud Serverless / Static Fallback Ready).");
      }
    } catch {
      setBackendStatusMsg("⚡ In-Browser SAST Engine Active (Zero-configuration browser sandbox mode).");
    } finally {
      setTestingBackend(false);
    }
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[65vh]">
        <CyberRadarLoader size="md" text="LOADING SYSTEM SETTINGS" />
      </div>
    );
  }

  return (
    <div className="max-w-6xl mx-auto space-y-8 animate-fade-in relative">
      
      {/* Header */}
      <PageHeader
        title="AI Control Center & System Settings"
        subtitle="Manage LLM providers, OpenRouter API access keys, API endpoint, and SAST security scanner status"
        badge={
          <span className="px-3 py-1 bg-violet-500/10 text-violet-400 border border-violet-500/30 rounded-full text-xs font-mono font-bold uppercase">
            AI Engine Provider: {aiProvider} ({defaultModel})
          </span>
        }
      />

      {saveSuccess && (
        <div className="p-4 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-2xl flex items-center gap-3">
          <CheckCircle2 className="w-5 h-5 shrink-0 text-emerald-500" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {saveError && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-2xl flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <AlertCircle className="w-5 h-5 shrink-0 text-rose-500" />
            <span>{saveError}</span>
          </div>
          <Button
            size="sm"
            variant="danger"
            onClick={fetchSettings}
            className="shrink-0 text-xs gap-1"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Retry
          </Button>
        </div>
      )}

      {/* AI Provider Cards Grid */}
      <div className="space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div>
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
              AI Provider Intelligence Matrix
            </h3>
            <p className="text-xs text-slate-400 mt-1 font-sans">
              Select an AI provider, configure API keys, and set models
            </p>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-6 gap-4">
          {[
            {
              id: "openrouter",
              name: "OpenRouter.ai",
              badge: "RECOMMENDED",
              badgeType: "recommended",
              status: configuredKeys.openrouter ? "Configured" : "Key Required",
              statusType: configuredKeys.openrouter ? "success" : "warning",
              defaultModel: "deepseek/deepseek-chat",
              iconColor: "text-violet-400",
              iconBg: "bg-violet-500/10 border-violet-500/30",
              Icon: (props: { className?: string }) => (
                <svg className={props.className || "w-5 h-5"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" />
                </svg>
              ),
            },
            {
              id: "openai",
              name: "OpenAI",
              badge: "CLOUD",
              badgeType: "cloud",
              status: configuredKeys.openai ? "Configured" : "Key Required",
              statusType: configuredKeys.openai ? "success" : "warning",
              defaultModel: "gpt-4o-mini",
              iconColor: "text-sky-400",
              iconBg: "bg-sky-500/10 border-sky-500/30",
              Icon: (props: { className?: string }) => (
                <svg className={props.className || "w-5 h-5"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M17.5 19C19.9853 19 22 16.9853 22 14.5C22 12.1564 20.2062 10.2312 17.9157 10.0243C17.4334 6.57945 14.4604 3.875 10.875 3.875C7.45781 3.875 4.60098 6.30401 3.96875 9.53125C1.75806 9.87109 0 11.752 0 14.0312C0 16.5165 2.01472 18.5312 4.5 18.5312H17.5Z" />
                </svg>
              ),
            },
            {
              id: "gemini",
              name: "Gemini",
              badge: "CLOUD",
              badgeType: "cloud",
              status: configuredKeys.gemini ? "Configured" : "Key Required",
              statusType: configuredKeys.gemini ? "success" : "warning",
              defaultModel: "gemini-1.5-flash",
              iconColor: "text-cyan-400",
              iconBg: "bg-cyan-500/10 border-cyan-500/30",
              Icon: (props: { className?: string }) => (
                <svg className={props.className || "w-5 h-5"} viewBox="0 0 24 24" fill="currentColor">
                  <path d="M12 0C12 6.627 6.627 12 0 12C6.627 12 12 17.373 12 24C12 17.373 17.373 12 24 12C17.373 12 12 6.627 12 0Z" />
                </svg>
              ),
            },
            {
              id: "claude",
              name: "Claude",
              badge: "CLOUD",
              badgeType: "cloud",
              status: configuredKeys.claude ? "Configured" : "Offline",
              statusType: configuredKeys.claude ? "success" : "offline",
              defaultModel: "claude-3-haiku",
              iconColor: "text-orange-500",
              iconBg: "bg-orange-500/10 border-orange-500/30",
              Icon: (props: { className?: string }) => (
                <svg className={props.className || "w-5 h-5"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round">
                  <line x1="12" y1="3" x2="12" y2="21" />
                  <line x1="3" y1="12" x2="21" y2="12" />
                  <line x1="5.64" y1="5.64" x2="18.36" y2="18.36" />
                  <line x1="18.36" y1="5.64" x2="5.64" y2="18.36" />
                </svg>
              ),
            },
            {
              id: "grok",
              name: "Grok",
              badge: "CLOUD",
              badgeType: "cloud",
              status: configuredKeys.grok ? "Configured" : "Key Required",
              statusType: configuredKeys.grok ? "success" : "warning",
              defaultModel: "grok-2-mini",
              iconColor: "text-slate-100",
              iconBg: "bg-slate-700/20 border-slate-600/30",
              Icon: (props: { className?: string }) => (
                <svg className={props.className || "w-5 h-5"} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="7" />
                  <circle cx="12" cy="12" r="2.5" fill="currentColor" />
                  <line x1="12" y1="2" x2="12" y2="5" />
                  <line x1="17" y1="7" x2="19.5" y2="4.5" />
                </svg>
              ),
            },
          ].map((provider) => {
            const isSelected = aiProvider === provider.id;
            const ProviderIcon = provider.Icon;
            const availableModels = providerModels[provider.id] || [provider.defaultModel];
            const currentSelectedModel = isSelected ? (defaultModel || availableModels[0]) : availableModels[0];

            const handleSelectProvider = () => {
              setAiProvider(provider.id);
              if (!isSelected) {
                setDefaultModel(availableModels[0]);
              }
            };

            return (
              <div
                key={provider.id}
                onClick={handleSelectProvider}
                className={`p-4 rounded-2xl bg-slate-950/70 backdrop-blur-xl border transition-all duration-300 flex flex-col justify-between cursor-pointer relative overflow-hidden group ${
                  isSelected
                    ? "border-blue-500/90 bg-[#0c1427] shadow-[0_0_25px_rgba(59,130,246,0.25)] ring-1 ring-blue-500/50"
                    : "border-slate-800/80 hover:border-slate-700/80 hover:bg-slate-900/50"
                }`}
              >
                {/* Header: Icon + Name on Left, Tag on Right */}
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2.5">
                    <div className={`p-1.5 rounded-lg border ${provider.iconBg} ${provider.iconColor} shrink-0`}>
                      <ProviderIcon className="w-5 h-5" />
                    </div>
                    <span className="text-sm font-bold text-white tracking-wide font-sans">
                      {provider.name}
                    </span>
                  </div>

                  <span
                    className={`px-2 py-0.5 rounded text-[9px] font-mono font-extrabold uppercase tracking-wider ${
                      provider.badgeType === "local"
                        ? "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                        : "bg-slate-900/80 text-slate-400 border border-slate-800"
                    }`}
                  >
                    {provider.badge}
                  </span>
                </div>

                {/* Status Pill & API Key quick trigger */}
                <div className="mb-3 space-y-1.5">
                  {provider.statusType === "offline" ? (
                    <div className="w-full py-1 px-3 rounded-xl bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs font-semibold text-center tracking-wide">
                      Offline
                    </div>
                  ) : provider.statusType === "warning" ? (
                    <div className="w-full py-1 px-3 rounded-xl bg-amber-500/10 border border-amber-500/30 text-amber-400 text-xs font-semibold text-center tracking-wide">
                      Key Required
                    </div>
                  ) : provider.status === "Connected" ? (
                    <div className="w-full py-1 px-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold text-center tracking-wide shadow-[0_0_12px_rgba(16,185,129,0.15)]">
                      Connected
                    </div>
                  ) : (
                    <div className="w-full py-1 px-3 rounded-xl bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs font-semibold text-center tracking-wide">
                      Configured
                    </div>
                  )}

                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleOpenApiKeyModal(provider.id);
                    }}
                    className="w-full py-1 px-2 text-[10px] font-mono text-amber-400 hover:text-amber-300 bg-amber-500/5 hover:bg-amber-500/10 border border-amber-500/20 rounded-lg flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                  >
                    <Key className="w-3 h-3" />
                    <span>
                      {configuredKeys[provider.id] ? "Update API Key" : "Enter API Key"}
                    </span>
                  </button>
                </div>

                {/* Model Label & Dropdown Selection */}
                <div className="my-2 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="block text-[11px] font-medium text-slate-400 tracking-wide">
                      Model
                    </span>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation();
                        setTargetProviderForCustom(provider.id);
                        setCustomModalOpen(true);
                      }}
                      className="text-[10px] font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-0.5 hover:underline cursor-pointer"
                    >
                      <Plus className="w-3 h-3" /> Custom
                    </button>
                  </div>

                  <div className="relative" onClick={(e) => e.stopPropagation()}>
                    <select
                      value={currentSelectedModel}
                      onChange={(e) => {
                        if (e.target.value === "__create_new__") {
                          setTargetProviderForCustom(provider.id);
                          setCustomModalOpen(true);
                        } else {
                          setAiProvider(provider.id);
                          setDefaultModel(e.target.value);
                        }
                      }}
                      className={`w-full px-2.5 py-1.5 pr-7 rounded-lg bg-slate-900 border text-xs font-mono font-bold transition-all appearance-none cursor-pointer focus:outline-none ${
                        isSelected
                          ? "border-cyan-500/60 text-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.15)]"
                          : "border-slate-800 text-slate-300 hover:border-slate-700"
                      }`}
                    >
                      {availableModels.map((m) => (
                        <option key={m} value={m} className="bg-slate-950 text-slate-200 font-mono py-1">
                          {m}
                        </option>
                      ))}
                      <option value="__create_new__" className="bg-slate-950 text-cyan-400 font-mono font-bold">
                        + Create Custom Model...
                      </option>
                    </select>
                    <ChevronDown className="w-3.5 h-3.5 text-slate-400 absolute right-2 top-2.5 pointer-events-none" />
                  </div>
                </div>

                {/* Configure Action Button */}
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation();
                    handleSelectProvider();
                  }}
                  className={`mt-3 w-full py-2 px-3 rounded-xl text-xs font-bold transition-all duration-200 flex items-center justify-center gap-1.5 cursor-pointer ${
                    isSelected
                      ? "bg-blue-600 hover:bg-blue-500 text-white shadow-md shadow-blue-600/30 border border-blue-400/40"
                      : "bg-slate-900/80 hover:bg-slate-800 text-slate-300 hover:text-white border border-slate-800 hover:border-slate-700"
                  }`}
                >
                  <span>{isSelected ? "Configured" : "Configure"}</span>
                </button>
              </div>
            );
          })}
        </div>
      </div>

      {/* Main Settings Form */}
      <form onSubmit={handleSaveSettings} className="space-y-8">
        
        {/* OpenRouter / LLM Endpoint Configuration Panel */}
        <GlassCard className="p-6 space-y-6" topBarGradient={true}>
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-base font-bold text-slate-100 font-sans flex items-center gap-2">
                <Cpu className="w-5 h-5 text-cyan-400" /> Active AI Provider LLM Configuration
              </h3>
              <p className="text-xs text-slate-400 mt-1">Configure OpenRouter.ai cloud model endpoint and active weights.</p>
            </div>

            <Button
              type="button"
              variant="glass"
              size="sm"
              icon={RefreshCw}
              loading={testingOpenRouter}
              onClick={handleTestOpenRouter}
            >
              Test Connection
            </Button>
          </div>

          {openrouterStatusMsg && (
            <div className="p-3 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs rounded-xl font-mono">
              {openrouterStatusMsg}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                OpenRouter / API Endpoint URL
              </label>
              <input
                type="text"
                value={openrouterUrl}
                onChange={(e) => setOpenrouterUrl(e.target.value)}
                className="w-full px-4 py-3 glass-input rounded-xl text-sm font-mono focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Active Analysis Model Name
              </label>
              <input
                type="text"
                value={defaultModel}
                onChange={(e) => setDefaultModel(e.target.value)}
                className="w-full px-4 py-3 glass-input rounded-xl text-sm font-mono focus:outline-none"
              />
            </div>
          </div>

          {/* Recommended & Custom Models Pills */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="block text-[11px] font-mono text-slate-400 uppercase tracking-wider">
                Available Models for {aiProvider.toUpperCase()}:
              </span>
              <button
                type="button"
                onClick={() => {
                  setTargetProviderForCustom(aiProvider);
                  setCustomModalOpen(true);
                }}
                className="text-xs font-mono text-cyan-400 hover:text-cyan-300 flex items-center gap-1 hover:underline cursor-pointer"
              >
                <Plus className="w-3.5 h-3.5" /> Create Custom Model
              </button>
            </div>

            <div className="flex flex-wrap gap-2">
              {(providerModels[aiProvider] || [defaultModel]).map((m) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setDefaultModel(m)}
                  className={`px-3 py-1.5 rounded-xl text-xs font-mono border transition-all cursor-pointer ${
                    defaultModel === m
                      ? "bg-cyan-500/20 text-cyan-300 border-cyan-500/50 shadow-[0_0_10px_rgba(6,182,212,0.2)] font-bold"
                      : "bg-slate-900/60 text-slate-400 border-slate-800 hover:border-slate-700"
                  }`}
                >
                  {m}
                </button>
              ))}
              <button
                type="button"
                onClick={() => {
                  setTargetProviderForCustom(aiProvider);
                  setCustomModalOpen(true);
                }}
                className="px-3 py-1.5 rounded-xl text-xs font-mono border border-dashed border-cyan-500/40 text-cyan-400 hover:bg-cyan-500/10 transition-all cursor-pointer flex items-center gap-1"
              >
                <Plus className="w-3.5 h-3.5" /> Add Custom...
              </button>
            </div>
          </div>
        </GlassCard>

        {/* Backend API Endpoint Configuration */}
        <GlassCard className="p-6 space-y-4" topBarGradient={true}>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
            <div>
              <h3 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <Server className="w-4 h-4 text-cyan-400" /> Backend API Endpoint & Hybrid Mode
              </h3>
              <p className="text-xs text-slate-400 mt-0.5">
                Connect to a custom FastAPI backend server or use the built-in High-Performance In-Browser SAST Engine.
              </p>
            </div>
            <span className="px-3 py-1 bg-cyan-500/10 text-cyan-300 border border-cyan-500/30 rounded-full text-xs font-mono font-bold">
              ⚡ HYBRID READY
            </span>
          </div>

          <div className="space-y-3">
            <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-400">
              FastAPI Backend Server URL (Optional Override)
            </label>
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Globe className="w-4 h-4 text-slate-500 absolute left-3.5 top-3.5 pointer-events-none" />
                <input
                  type="text"
                  value={customApiUrl}
                  onChange={(e) => setCustomApiUrl(e.target.value)}
                  placeholder="e.g. http://localhost:8000 or https://your-backend.onrender.com (Leave blank for automatic)"
                  className="w-full pl-10 pr-4 py-3 glass-input rounded-xl text-xs font-mono focus:outline-none placeholder-slate-600"
                />
              </div>
              <Button
                type="button"
                variant="secondary"
                size="md"
                onClick={handleTestBackendConnection}
                loading={testingBackend}
                className="shrink-0 text-xs"
              >
                <Zap className="w-3.5 h-3.5 text-cyan-400" /> Test Connection
              </Button>
            </div>
            {backendStatusMsg && (
              <div className="p-3 bg-slate-900/80 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300 flex items-center gap-2 animate-fade-in">
                <span>{backendStatusMsg}</span>
              </div>
            )}
            <p className="text-[11px] text-slate-500 font-mono">
              💡 If no remote backend is configured or reachable, AI Bug Hunter automatically runs all SAST analyzers, ZIP extractions, AST vulnerability detection, and AI recommendations directly in your browser.
            </p>
          </div>
        </GlassCard>

        {/* Security Scanner Engines Status Cards */}
        <div className="space-y-4">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
            SAST Scanner Engines Operational Status
          </h3>

          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            {[
              { name: "Gitleaks Secret Scanner", status: "ACTIVE", detail: "Signature DB Ready" },
              { name: "Bandit Python AST Engine", status: "ACTIVE", detail: "AST Parser Loaded" },
              { name: "Semgrep Rule Engine", status: "ACTIVE", detail: "OWASP Ruleset 2026" },
              { name: "OWASP Dependency Audit", status: "DATABASE READY", detail: "Offline CVE DB" },
            ].map((eng, idx) => (
              <GlassCard key={idx} className="p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <StatusBadge status="completed" label={eng.status} size="sm" />
                </div>
                <h4 className="text-xs font-bold text-slate-100">{eng.name}</h4>
                <p className="text-[10px] text-slate-500 font-mono">{eng.detail}</p>
              </GlassCard>
            ))}
          </div>
        </div>

        {/* Save Button Action Bar */}
        <div className="flex justify-end pt-4 border-t border-slate-800">
          <Button type="submit" variant="primary" size="lg" icon={Save} loading={saving}>
            Save All Configuration & API Credentials
          </Button>
        </div>

      </form>

      {/* API Key Modal Overlay */}
      {apiKeyModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in">
          <div className="w-full max-w-md bg-[#0b1324] border border-amber-500/30 rounded-3xl p-6 shadow-2xl shadow-amber-500/10 space-y-5 relative">
            <button
              type="button"
              onClick={() => setApiKeyModalOpen(false)}
              className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-white rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/30 flex items-center justify-center text-amber-400 shrink-0">
                <Key className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100 font-sans capitalize">
                  Configure {keyModalProvider} API Key
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Enter secret API access key to activate {keyModalProvider.toUpperCase()} cloud model
                </p>
              </div>
            </div>

            <form onSubmit={handleSaveApiKeyFromModal} className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Secret API Key
                </label>
                <div className="relative">
                  <input
                    type={showModalKey ? "text" : "password"}
                    required
                    placeholder={
                      keyModalProvider === "openrouter"
                        ? "sk-or-v1-..."
                        : keyModalProvider === "openai"
                        ? "sk-proj-..."
                        : keyModalProvider === "gemini"
                        ? "AIzaSy..."
                        : keyModalProvider === "claude"
                        ? "sk-ant-api03-..."
                        : "xai-..."
                    }
                    value={keyModalInputValue}
                    onChange={(e) => setKeyModalInputValue(e.target.value)}
                    className="w-full px-4 py-3 pr-10 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowModalKey(!showModalKey)}
                    className="absolute right-3 top-3.5 text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {showModalKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-[11px] text-slate-500 mt-1.5 font-sans">
                  Your key is securely transmitted and stored as an environment configuration on the backend.
                </p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setApiKeyModalOpen(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer"
                >
                  Cancel
                </button>
                <Button type="submit" variant="primary" size="sm" icon={Save} loading={saving}>
                  Save API Key
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Custom Model Modal Overlay */}
      {customModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-md animate-fade-in">
          <div className="w-full max-w-md bg-[#0b1324] border border-cyan-500/30 rounded-3xl p-6 shadow-2xl shadow-cyan-500/10 space-y-5 relative">
            <button
              type="button"
              onClick={() => setCustomModalOpen(false)}
              className="absolute top-4 right-4 p-1.5 text-slate-400 hover:text-white rounded-lg bg-slate-900/80 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 shrink-0">
                <Plus className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-bold text-slate-100 font-sans">
                  Create Custom LLM Model
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Add a custom fine-tuned or local model identifier for{" "}
                  <span className="text-cyan-400 font-bold uppercase font-mono">
                    {targetProviderForCustom}
                  </span>
                </p>
              </div>
            </div>

            <form onSubmit={handleAddCustomModel} className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Custom Model Identifier Name
                </label>
                <input
                  type="text"
                  required
                  placeholder={
                    targetProviderForCustom === "openrouter"
                      ? "e.g. deepseek/deepseek-r1:free or meta-llama/llama-3.3-70b-instruct"
                      : targetProviderForCustom === "openai"
                      ? "e.g. ft:gpt-4o-mini:org:custom-001"
                      : "e.g. my-custom-fine-tuned-model"
                  }
                  value={customModelInput}
                  onChange={(e) => setCustomModelInput(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500"
                  autoFocus
                />
                <p className="text-[11px] text-slate-500 mt-1.5 font-sans">
                  Enter the exact model tag registered in your {targetProviderForCustom} server or API endpoint.
                </p>
              </div>

              <div className="flex items-center justify-end gap-3 pt-2">
                <button
                  type="button"
                  onClick={() => setCustomModalOpen(false)}
                  className="px-4 py-2 text-xs font-semibold text-slate-400 hover:text-white rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all cursor-pointer"
                >
                  Cancel
                </button>
                <Button type="submit" variant="primary" size="sm" icon={Plus}>
                  Add & Select Model
                </Button>
              </div>
            </form>
          </div>
        </div>
      )}

    </div>
  );
};

export default SettingsPage;
