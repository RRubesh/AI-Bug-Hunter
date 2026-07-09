import React, { useEffect, useState } from "react";
import { api } from "../services/api";
import type { AppSettings } from "../services/api";
import { 
  Cpu, 
  HardDrive, 
  RefreshCw, 
  AlertCircle, 
  Save, 
  DownloadCloud, 
  CheckCircle2, 
  Server, 
  Cloud, 
  Eye, 
  EyeOff, 
  Globe 
} from "lucide-react";

const PROVIDER_MODELS: Record<string, string[]> = {
  ollama: [],
  openai: ["gpt-4o-mini", "gpt-4o", "gpt-4-turbo", "gpt-3.5-turbo"],
  gemini: ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-1.0-pro"],
  groq: ["llama-3.1-8b-instant", "llama-3.1-70b-versatile", "mixtral-8x7b-32768"],
  claude: ["claude-3-5-sonnet-20240620", "claude-3-haiku-20240307", "claude-3-opus-20240229"],
  grok: ["grok-2-1212", "grok-2-vision-1212", "grok-beta"]
};

export const SettingsPage: React.FC = () => {
  const [configs, setConfigs] = useState<AppSettings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  
  // Editable fields
  const [ollamaUrl, setOllamaUrl] = useState("");
  const [defaultModel, setDefaultModel] = useState("");
  const [customModel, setCustomModel] = useState("");
  const [aiProvider, setAiProvider] = useState("ollama");
  const [openaiApiKey, setOpenaiApiKey] = useState("");
  const [geminiApiKey, setGeminiApiKey] = useState("");
  const [groqApiKey, setGroqApiKey] = useState("");
  const [claudeApiKey, setClaudeApiKey] = useState("");
  const [grokApiKey, setGrokApiKey] = useState("");
  
  // States
  const [saving, setSaving] = useState(false);
  const [saveSuccess, setSaveSuccess] = useState("");
  const [saveError, setSaveError] = useState("");
  const [showKeys, setShowKeys] = useState<Record<string, boolean>>({
    openai: false,
    gemini: false,
    groq: false,
    claude: false,
    grok: false
  });

  const fetchSettings = async () => {
    setLoading(true);
    setError("");
    setSaveSuccess("");
    setSaveError("");
    try {
      const data = await api.getSettings();
      setConfigs(data);
      setOllamaUrl(data.ollama_url);
      setDefaultModel(data.default_model);
      setAiProvider(data.ai_provider);
      // Reset inputs
      setOpenaiApiKey("");
      setGeminiApiKey("");
      setGroqApiKey("");
      setClaudeApiKey("");
      setGrokApiKey("");
    } catch {
      setError("Failed to load settings from server. Make sure FastAPI server and Ollama are reachable.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    let active = true;
    (async () => {
      await Promise.resolve();
      if (active) {
        fetchSettings();
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  const handleProviderChange = (provider: string) => {
    setAiProvider(provider);
    const defaults: Record<string, string> = {
      openai: "gpt-4o-mini",
      gemini: "gemini-1.5-flash",
      groq: "llama-3.1-8b-instant",
      claude: "claude-3-5-sonnet-20240620",
      grok: "grok-2-1212",
      ollama: configs?.available_models?.[0] || "qwen2.5-coder:1.5b"
    };
    setDefaultModel(defaults[provider] || "");
  };

  const handleSave = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setSaveSuccess("");
    setSaveError("");
    try {
      const data = await api.updateSettings({
        ollama_url: ollamaUrl,
        default_model: defaultModel,
        ai_provider: aiProvider,
        openai_api_key: openaiApiKey.trim() || undefined,
        gemini_api_key: geminiApiKey.trim() || undefined,
        groq_api_key: groqApiKey.trim() || undefined,
        claude_api_key: claudeApiKey.trim() || undefined,
        grok_api_key: grokApiKey.trim() || undefined,
      });
      setConfigs(data);
      setOllamaUrl(data.ollama_url);
      setDefaultModel(data.default_model);
      setAiProvider(data.ai_provider);
      
      // Clear entered keys
      setOpenaiApiKey("");
      setGeminiApiKey("");
      setGroqApiKey("");
      setClaudeApiKey("");
      setGrokApiKey("");
      
      setSaveSuccess("System configurations updated successfully!");
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSaveError(errMsg || "Failed to update configurations.");
    } finally {
      setSaving(false);
    }
  };

  const toggleShowKey = (provider: string) => {
    setShowKeys(prev => ({ ...prev, [provider]: !prev[provider] }));
  };

  const handlePullModel = async () => {
    if (!customModel.trim()) return;
    setSaving(true);
    setSaveSuccess("");
    setSaveError("");
    try {
      const data = await api.updateSettings({
        ollama_url: ollamaUrl,
        default_model: customModel.trim(),
        ai_provider: aiProvider
      });
      setConfigs(data);
      setOllamaUrl(data.ollama_url);
      setDefaultModel(data.default_model);
      setSaveSuccess(`Active model changed to '${customModel.trim()}'. If using Ollama, download will proceed in the background.`);
      setCustomModel("");
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setSaveError(errMsg || "Failed to update model settings.");
    } finally {
      setSaving(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[50vh]">
        <div className="w-10 h-10 border-4 border-slate-800 border-t-rose-500 rounded-full animate-spin"></div>
      </div>
    );
  }

  // Get options for model dropdown based on selected provider
  const modelOptions = aiProvider === "ollama" 
    ? (configs?.available_models || []) 
    : PROVIDER_MODELS[aiProvider];

  return (
    <div className="max-w-2xl mx-auto space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-slate-100 tracking-tight">System Configurations</h1>
          <p className="text-xs text-slate-400 mt-1">
            Configure integration adapters, endpoints, and secure code reasoning engines.
          </p>
        </div>
        <button
          onClick={fetchSettings}
          className="p-2 bg-slate-900 border border-slate-850 hover:bg-slate-800 text-slate-400 hover:text-slate-200 rounded-lg cursor-pointer transition-colors"
          title="Reload Settings"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      {error && (
        <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {saveSuccess && (
        <div className="p-3.5 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg flex items-center gap-2 animate-slide-up">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span>{saveSuccess}</span>
        </div>
      )}

      {saveError && (
        <div className="p-3.5 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{saveError}</span>
        </div>
      )}

      {/* Provider Selector Cards */}
      <div className="p-6 glass-panel rounded-xl border-slate-800 space-y-4">
        <div className="flex items-center gap-2 border-b border-slate-850 pb-2.5">
          <Globe className="w-4 h-4 text-rose-500" />
          <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Select AI Reasoning Engine</h2>
        </div>
        
        <div className="grid grid-cols-2 sm:grid-cols-6 gap-3">
          {[
            { id: "ollama", name: "Ollama", type: "Local", icon: Server, configured: (configs?.available_models && configs.available_models.length > 0) },
            { id: "openai", name: "OpenAI", type: "Cloud", icon: Cloud, configured: configs?.openai_api_key_configured },
            { id: "gemini", name: "Gemini", type: "Cloud", icon: Cloud, configured: configs?.gemini_api_key_configured },
            { id: "groq", name: "Groq", type: "Cloud", icon: Cloud, configured: configs?.groq_api_key_configured },
            { id: "claude", name: "Claude", type: "Cloud", icon: Cloud, configured: configs?.claude_api_key_configured },
            { id: "grok", name: "Grok", type: "Cloud", icon: Cloud, configured: configs?.grok_api_key_configured },
          ].map((prov) => {
            const Icon = prov.icon;
            const isSelected = aiProvider === prov.id;
            return (
              <button
                key={prov.id}
                type="button"
                onClick={() => handleProviderChange(prov.id)}
                className={`flex flex-col items-center justify-between p-3.5 rounded-xl border text-center transition-all cursor-pointer ${
                  isSelected
                    ? "bg-rose-500/10 border-rose-500/80 shadow-lg shadow-rose-950/20 text-rose-400"
                    : "bg-slate-950/60 border-slate-850 hover:bg-slate-900/40 hover:border-slate-800 text-slate-400 hover:text-slate-200"
                }`}
              >
                <Icon className={`w-5 h-5 mb-1.5 ${isSelected ? "text-rose-500 animate-pulse" : "text-slate-500"}`} />
                <span className="text-xs font-black tracking-tight block">{prov.name}</span>
                <span className="text-[8px] uppercase tracking-wider block text-slate-500 mt-0.5">{prov.type}</span>
                <span className={`mt-2 text-[8px] px-1.5 py-0.5 rounded font-bold ${
                  prov.configured 
                    ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/20" 
                    : "bg-slate-950 text-slate-500 border border-slate-850"
                }`}>
                  {prov.configured ? (prov.id === "ollama" ? "Connected" : "Configured") : "Offline"}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Main Configurations Form */}
      <form onSubmit={handleSave} className="p-6 glass-panel rounded-xl border-slate-800 space-y-5">
        <div className="flex items-center justify-between border-b border-slate-850 pb-2.5">
          <div className="flex items-center gap-2">
            <Cpu className="w-4 h-4 text-rose-500" />
            <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
              {aiProvider === "ollama" ? "Ollama Local configuration" : `${aiProvider.toUpperCase()} Cloud Configuration`}
            </h2>
          </div>
        </div>

        <div className="space-y-4 text-xs">
          {/* Endpoint URL (Ollama Only) */}
          {aiProvider === "ollama" && (
            <div className="space-y-1.5">
              <label htmlFor="ollama-url" className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">
                Ollama Endpoint URL
              </label>
              <input
                id="ollama-url"
                type="text"
                value={ollamaUrl}
                onChange={(e) => setOllamaUrl(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-850 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500/80 focus:ring-1 focus:ring-rose-500/30 transition-all"
                placeholder="e.g. http://localhost:11434"
                required
              />
            </div>
          )}

          {/* Cloud API Key (Cloud Providers Only) */}
          {aiProvider !== "ollama" && (
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label htmlFor="api-key" className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">
                  {aiProvider.toUpperCase()} API Key
                </label>
                {configs?.[`${aiProvider as "openai" | "gemini" | "groq" | "claude" | "grok"}_api_key_configured`] && (
                  <span className="text-[9px] text-emerald-400 font-semibold bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/20">
                    Existing Key Loaded
                  </span>
                )}
              </div>
              <div className="relative">
                <input
                  id="api-key"
                  type={showKeys[aiProvider] ? "text" : "password"}
                  value={
                    aiProvider === "openai" ? openaiApiKey : 
                    aiProvider === "gemini" ? geminiApiKey : 
                    aiProvider === "groq" ? groqApiKey : 
                    aiProvider === "claude" ? claudeApiKey : grokApiKey
                  }
                  onChange={(e) => {
                    const val = e.target.value;
                    if (aiProvider === "openai") setOpenaiApiKey(val);
                    else if (aiProvider === "gemini") setGeminiApiKey(val);
                    else if (aiProvider === "groq") setGroqApiKey(val);
                    else if (aiProvider === "claude") setClaudeApiKey(val);
                    else if (aiProvider === "grok") setGrokApiKey(val);
                  }}
                  className="w-full bg-slate-950/80 border border-slate-850 rounded-lg pl-3 pr-10 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500/80 focus:ring-1 focus:ring-rose-500/30 transition-all"
                  placeholder={
                    configs?.[`${aiProvider as "openai" | "gemini" | "groq" | "claude" | "grok"}_api_key_configured`]
                      ? "•••••••••••••••••••••••••••••••• (Leave blank to keep current key)"
                      : "Enter API credential"
                  }
                />
                <button
                  type="button"
                  onClick={() => toggleShowKey(aiProvider)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition-colors"
                >
                  {showKeys[aiProvider] ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>
          )}

          {/* Model Selector */}
          <div className="space-y-1.5">
            <label htmlFor="default-model" className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">
              Active Analysis LLM Model
            </label>
            {modelOptions.length > 0 ? (
              <div className="flex gap-2">
                <select
                  id="default-model"
                  value={defaultModel}
                  onChange={(e) => setDefaultModel(e.target.value)}
                  className="flex-1 bg-slate-950 border border-slate-850 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500/80 focus:ring-1 focus:ring-rose-500/30 transition-all cursor-pointer"
                >
                  {modelOptions.map((model) => (
                    <option key={model} value={model}>
                      {model}
                    </option>
                  ))}
                  <option value="custom">-- Use Custom Model Name --</option>
                </select>
              </div>
            ) : (
              <input
                id="default-model"
                type="text"
                value={defaultModel}
                onChange={(e) => setDefaultModel(e.target.value)}
                className="w-full bg-slate-950/80 border border-slate-850 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500/80 focus:ring-1 focus:ring-rose-500/30 transition-all"
                placeholder={aiProvider === "ollama" ? "e.g. qwen2.5-coder:1.5b" : "e.g. gpt-4o-mini"}
                required
              />
            )}
          </div>

          {/* Quick Model Tags Selector */}
          {modelOptions.length > 0 && (
            <div>
              <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Recommended Models</span>
              <div className="flex flex-wrap gap-2 mt-2">
                {modelOptions.map((model) => (
                  <button
                    key={model}
                    type="button"
                    className={`px-2.5 py-1 border text-[9px] font-mono rounded-lg transition-all cursor-pointer ${
                      model === defaultModel
                        ? "bg-rose-500/10 border-rose-500/30 text-rose-400"
                        : "bg-slate-950 border-slate-850 text-slate-400 hover:text-slate-200 hover:border-slate-800"
                    }`}
                    onClick={() => setDefaultModel(model)}
                  >
                    {model}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* If Ollama has no local models */}
          {aiProvider === "ollama" && modelOptions.length === 0 && (
            <span className="text-rose-400 bg-rose-500/5 border border-rose-500/15 p-3 rounded-lg block mt-2 text-[10px]">
              Ollama has no models downloaded or Ollama service is unreachable. Ensure you run: <code className="bg-slate-950 px-1.5 py-0.5 rounded text-[10px] text-slate-200">ollama pull qwen2.5-coder:1.5b</code> in your local CLI.
            </span>
          )}

          {/* Custom Model Name input (shown if selected or typing) */}
          {(modelOptions.length === 0 || defaultModel === "custom") && (
            <div className="border-t border-slate-850/60 pt-4 mt-2 space-y-2">
              <span className="text-[10px] text-slate-500 font-bold block uppercase tracking-wider">Specify Custom Model Name</span>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={customModel}
                  onChange={(e) => setCustomModel(e.target.value)}
                  placeholder={aiProvider === "ollama" ? "deepseek-coder:1.3b" : "gpt-4o-2024-08-06"}
                  className="flex-1 bg-slate-950/80 border border-slate-850 rounded-lg px-3 py-2 text-xs text-slate-200 font-mono focus:outline-none focus:border-rose-500/80 focus:ring-1 focus:ring-rose-500/30 transition-all"
                />
                <button
                  type="button"
                  onClick={handlePullModel}
                  disabled={saving || !customModel.trim()}
                  className="flex items-center gap-1.5 px-4 py-2 bg-slate-900 border border-slate-800 hover:bg-slate-800 text-slate-300 hover:text-slate-100 disabled:opacity-50 disabled:cursor-not-allowed rounded-lg text-xs font-bold transition-all cursor-pointer"
                >
                  <DownloadCloud className="w-3.5 h-3.5" />
                  <span>Set Active</span>
                </button>
              </div>
              <p className="text-[9px] text-slate-500">
                Provide custom model variant strings matching your cloud account availability or Ollama library download names.
              </p>
            </div>
          )}
        </div>

        <div className="flex justify-end pt-2">
          <button
            type="submit"
            disabled={saving}
            className="flex items-center gap-1.5 px-4 py-2.5 bg-rose-600 hover:bg-rose-500 disabled:bg-rose-700/60 text-white rounded-lg text-xs font-bold shadow-lg shadow-rose-950/20 hover:shadow-rose-600/10 hover:-translate-y-0.5 disabled:-translate-y-0 active:translate-y-0 transition-all cursor-pointer"
          >
            {saving ? (
              <>
                <div className="w-3.5 h-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                <span>Saving Changes...</span>
              </>
            ) : (
              <>
                <Save className="w-3.5 h-3.5" />
                <span>Save Configurations</span>
              </>
            )}
          </button>
        </div>
      </form>

      {/* Scanners information */}
      <div className="p-6 glass-panel rounded-xl border-slate-800 space-y-5">
        <div className="flex items-center gap-2 border-b border-slate-850 pb-2.5">
          <HardDrive className="w-4 h-4 text-amber-500" />
          <h2 className="text-xs font-bold text-slate-300 uppercase tracking-wider">Scanner Engines Status</h2>
        </div>

        <div className="space-y-3.5 text-xs">
          <div className="flex items-center justify-between p-2.5 bg-slate-950/60 border border-slate-850 rounded-lg">
            <span className="font-semibold text-slate-300">Gitleaks Secret Scanner</span>
            <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 text-[10px] font-bold rounded">REGEX FALLBACK ACTIVE</span>
          </div>

          <div className="flex items-center justify-between p-2.5 bg-slate-950/60 border border-slate-850 rounded-lg">
            <span className="font-semibold text-slate-300">Bandit Python Scanner</span>
            <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 text-[10px] font-bold rounded">AST FALLBACK ACTIVE</span>
          </div>

          <div className="flex items-center justify-between p-2.5 bg-slate-950/60 border border-slate-850 rounded-lg">
            <span className="font-semibold text-slate-300">Semgrep Rules Engine</span>
            <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 text-[10px] font-bold rounded">MULTI-LANG REGEX ACTIVE</span>
          </div>

          <div className="flex items-center justify-between p-2.5 bg-slate-950/60 border border-slate-850 rounded-lg">
            <span className="font-semibold text-slate-300">OWASP Dependency Checker</span>
            <span className="px-2 py-0.5 bg-emerald-500/10 text-emerald-400 border border-emerald-500/25 text-[10px] font-bold rounded">OFFLINE DATABASE ACTIVE</span>
          </div>
        </div>
      </div>
    </div>
  );
};
