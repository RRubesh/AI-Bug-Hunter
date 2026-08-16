import React, { useEffect, useState, useRef } from "react";
import { api } from "../services/api";
import type { Project, Scan, Vulnerability, ChatMessage } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import { 
  Send, Bot, User, Sparkles, Shield, AlertTriangle, 
  Code, Copy, Check, RefreshCw, Terminal, Lock, ChevronDown,
  Key, Eye, EyeOff, X, CheckCircle2, AlertCircle
} from "lucide-react";

interface LocalMessage {
  id: string | number;
  isUser: boolean;
  text: string;
  timestamp: string;
}

const makeWelcome = (): LocalMessage => ({
  id: "welcome-1",
  isUser: false,
  text: `👋 **Welcome to AI Bug Hunter Security Assistant!**\n\nI am your automated SAST & Defense Architect. Ask me anything about:\n- 🛡️ **Vulnerability Exploit Analysis** & Code Remediation\n- 🔑 **Hardcoded Secrets & Credential Leak Fixes**\n- ⚡ **OWASP Top 10 Risk Mitigation** & Defensive Refactoring\n- 📦 **Dependency CVE Auditing & Patching**\n\n*Select a scanned project on the left to load codebase vulnerability context!*`,
  timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
});

const SUGGESTED_PROMPTS = [
  { icon: Shield, label: "Explain how to patch SQL Injection risks" },
  { icon: Lock, label: "Scan for hardcoded API keys & suggest vault storage" },
  { icon: Code, label: "Refactor vulnerable CORS & CSRF header middleware" },
  { icon: Terminal, label: "Generate OWASP Top 10 remediation checklist" },
];

export const AIChatPage: React.FC<{ initialScanId?: number | null }> = ({ initialScanId }) => {
  // Data states
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(initialScanId || null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);

  // Provider state
  const [selectedProvider, setSelectedProvider] = useState<string>("openrouter");
  const [selectedModel, setSelectedModel] = useState<string>("deepseek/deepseek-chat");
  const [configuredKeys, setConfiguredKeys] = useState<Record<string, boolean>>({
    openrouter: false,
    openai: false,
    gemini: false,
    claude: false,
    grok: false,
  });

  // API Key Quick Modal in Chat
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [keySaving, setKeySaving] = useState(false);
  const [keySaveSuccess, setKeySaveSuccess] = useState("");
  const [keySaveError, setKeySaveError] = useState("");

  // Chat states
  const [messages, setMessages] = useState<LocalMessage[]>([makeWelcome()]);
  const [inputMessage, setInputMessage] = useState("");
  const [sending, setSending] = useState(false);
  const [loadingHistory, setLoadingHistory] = useState(false);
  const [copiedIndex, setCopiedIndex] = useState<string | number | null>(null);

  // Scroll-to-bottom button state
  const [showScrollBtn, setShowScrollBtn] = useState(false);
  const [unreadCount, setUnreadCount] = useState(0);
  const [scrollPercent, setScrollPercent] = useState(0);  // 0-1 scroll position
  const [thumbHeight, setThumbHeight] = useState(30);      // thumb height as % of track

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const messagesContainerRef = useRef<HTMLDivElement>(null);
  const minimapTrackRef = useRef<HTMLDivElement>(null);
  const isDraggingRef = useRef(false);

  const scrollToBottom = (smooth = true) => {
    messagesEndRef.current?.scrollIntoView({ behavior: smooth ? "smooth" : "auto" });
    setShowScrollBtn(false);
    setUnreadCount(0);
  };

  const handleScroll = () => {
    const el = messagesContainerRef.current;
    if (!el) return;
    const distFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    setShowScrollBtn(distFromBottom > 100);
    // Update minimap scroll percent and thumb size
    const maxScroll = el.scrollHeight - el.clientHeight;
    setScrollPercent(maxScroll > 0 ? el.scrollTop / maxScroll : 0);
    setThumbHeight(Math.max(8, (el.clientHeight / el.scrollHeight) * 100));
  };

  // Update thumb size when messages change
  useEffect(() => {
    const el = messagesContainerRef.current;
    if (!el) return;
    setThumbHeight(Math.max(8, (el.clientHeight / el.scrollHeight) * 100));
  }, [messages]);

  // Minimap drag handlers
  const handleMinimapClick = (e: React.MouseEvent<HTMLDivElement>) => {
    const track = minimapTrackRef.current;
    const el = messagesContainerRef.current;
    if (!track || !el) return;
    const rect = track.getBoundingClientRect();
    const clickY = e.clientY - rect.top;
    const pct = clickY / rect.height;
    el.scrollTop = pct * (el.scrollHeight - el.clientHeight);
  };

  const handleMinimapMouseDown = (e: React.MouseEvent) => {
    isDraggingRef.current = true;
    e.preventDefault();
    const onMove = (ev: MouseEvent) => {
      if (!isDraggingRef.current) return;
      const track = minimapTrackRef.current;
      const el = messagesContainerRef.current;
      if (!track || !el) return;
      const rect = track.getBoundingClientRect();
      const pct = Math.max(0, Math.min(1, (ev.clientY - rect.top) / rect.height));
      el.scrollTop = pct * (el.scrollHeight - el.clientHeight);
    };
    const onUp = () => { isDraggingRef.current = false; };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp, { once: true });
  };

  useEffect(() => {
    const el = messagesContainerRef.current;
    if (!el) return;
    const distFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    if (distFromBottom > 100) {
      // User is scrolled up — increment unread count
      setUnreadCount((prev) => prev + 1);
    } else {
      scrollToBottom(false);
    }
  }, [messages]);

  // Always scroll when sending indicator appears
  useEffect(() => {
    if (sending) scrollToBottom();
  }, [sending]);

  // Load projects + settings on mount
  useEffect(() => {
    let active = true;
    Promise.all([api.getProjects(), api.getSettings()])
      .then(([projData, settingsData]) => {
        if (!active) return;
        setProjects(projData);
        if (settingsData) {
          setSelectedProvider(settingsData.ai_provider || "openrouter");
          setSelectedModel(settingsData.default_model || "deepseek/deepseek-chat");
          setConfiguredKeys({
            openrouter: !!settingsData.openrouter_api_key_configured,
            openai: !!settingsData.openai_api_key_configured,
            gemini: !!settingsData.gemini_api_key_configured,
            claude: !!settingsData.claude_api_key_configured,
            grok: !!settingsData.grok_api_key_configured,
          });
        }
        // Auto-select first project only if no initialScanId given
        if (projData.length > 0 && !initialScanId) {
          setSelectedProjectId(projData[0].id);
        }
      })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  // When a project is selected, load its scans
  useEffect(() => {
    if (!selectedProjectId) return;
    let active = true;
    api.getScans(selectedProjectId)
      .then((scansData) => {
        if (!active) return;
        setScans(scansData);
        // Only auto-select if user hasn't chosen one from initialScanId
        if (scansData.length > 0 && !selectedScanId) {
          setSelectedScanId(scansData[0].id);
        }
      })
      .catch(() => {});
    return () => { active = false; };
  }, [selectedProjectId]);

  // When a scan is selected, load its vulnerabilities & chat history
  useEffect(() => {
    if (!selectedScanId) return;
    let active = true;
    setLoadingHistory(true);

    Promise.all([
      api.getVulnerabilities(selectedScanId),
      api.getChatHistory(selectedScanId).catch((): ChatMessage[] => []),
    ])
      .then(([vulnsData, historyData]) => {
        if (!active) return;
        setVulnerabilities(vulnsData);

        if (historyData && historyData.length > 0) {
          const formatted: LocalMessage[] = historyData.map((m) => ({
            id: m.id,
            isUser: !m.is_ai,
            text: m.message,
            timestamp: new Date(m.created_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          }));
          setMessages(formatted);
        } else {
          const critHigh = vulnsData.filter(
            (v) => v.severity === "CRITICAL" || v.severity === "HIGH"
          ).length;
          setMessages([
            {
              id: "scan-welcome",
              isUser: false,
              text: `🛡️ **Scan #${selectedScanId} Context Loaded**\n\nI have indexed **${vulnsData.length} vulnerabilities** (${critHigh} Critical/High). Click any vulnerability on the left to ask me for a fix, or type your own question!`,
              timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
            },
          ]);
        }
      })
      .catch(() => {})
      .finally(() => { if (active) setLoadingHistory(false); });

    return () => { active = false; };
  }, [selectedScanId]);

  const handleSendMessage = async (textToSend?: string) => {
    const query = (textToSend ?? inputMessage).trim();
    if (!query || sending) return;

    const userMsg: LocalMessage = {
      id: `user-${Date.now()}`,
      isUser: true,
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!textToSend) setInputMessage("");
    setSending(true);

    const addAI = (text: string) => {
      const aiMsg: LocalMessage = {
        id: `ai-${Date.now()}`,
        isUser: false,
        text,
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      };
      setMessages((prev) => [...prev, aiMsg]);
    };

    try {
      if (selectedScanId) {
        const response = await api.sendChatMessage(selectedScanId, query);
        addAI(response.message);
      } else {
        // Fallback local reasoning
        await new Promise((r) => setTimeout(r, 900));
        addAI(generateFallbackResponse(query, selectedProvider, selectedModel, vulnerabilities));
      }
    } catch {
      addAI(generateFallbackResponse(query, selectedProvider, selectedModel, vulnerabilities));
    } finally {
      setSending(false);
    }
  };

  const handleCopyCode = (id: string | number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(id);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const handleClearChat = () => {
    setMessages([makeWelcome()]);
  };

  const handleSaveApiKey = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKeyInput.trim()) return;

    setKeySaving(true);
    setKeySaveSuccess("");
    setKeySaveError("");

    try {
      const keyProp = `${selectedProvider}_api_key`;
      await api.updateSettings({
        [keyProp]: apiKeyInput.trim(),
        ai_provider: selectedProvider,
        default_model: selectedModel,
      });

      setConfiguredKeys((prev) => ({ ...prev, [selectedProvider]: true }));
      setKeySaveSuccess(`${selectedProvider.toUpperCase()} API key saved and activated!`);
      setTimeout(() => {
        setApiKeyModalOpen(false);
        setApiKeyInput("");
        setKeySaveSuccess("");
      }, 1000);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setKeySaveError(`Failed to save key: ` + errMsg);
    } finally {
      setKeySaving(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto space-y-6 animate-fade-in">
      {/* Page Header */}
      <PageHeader
        title="AI Security Assistant & Remediation Chat"
        subtitle="Interactive SAST reasoning, exploit analysis, code refactoring, and OWASP mitigation powered by your configured LLM."
        badge={
          <span className="px-3 py-1 bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 rounded-full text-xs font-mono font-bold uppercase flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5" />
            {selectedProvider.toUpperCase()} · {selectedModel}
          </span>
        }
      />

      {/* Main Layout: sidebar + chat */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6" style={{ minHeight: "72vh" }}>
        
        {/* ── Left Sidebar ── */}
        <div className="lg:col-span-1 flex flex-col gap-4">
          
          {/* Scan Context Selector */}
          <GlassCard className="p-4 space-y-3">
            <div className="flex items-center gap-1.5 border-b border-slate-800 pb-2">
              <Shield className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                Scan Context
              </span>
            </div>

            <div className="space-y-1">
              <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider">Target Project</label>
              <select
                value={selectedProjectId ?? ""}
                onChange={(e) => {
                  setSelectedProjectId(e.target.value ? Number(e.target.value) : null);
                  setSelectedScanId(null);
                  setVulnerabilities([]);
                }}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
              >
                <option value="">— General Security Audit —</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.name}{p.language_detected ? ` (${p.language_detected})` : ""}
                  </option>
                ))}
              </select>
            </div>

            {selectedProjectId && (
              <div className="space-y-1">
                <label className="block text-[10px] font-mono text-slate-400 uppercase tracking-wider">Scan Session</label>
                <select
                  value={selectedScanId ?? ""}
                  onChange={(e) => setSelectedScanId(e.target.value ? Number(e.target.value) : null)}
                  className="w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 focus:outline-none focus:border-cyan-500 cursor-pointer"
                >
                  <option value="">— Select a Scan —</option>
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      Scan #{s.id} · {new Date(s.created_at).toLocaleDateString()} ({s.status})
                    </option>
                  ))}
                </select>
              </div>
            )}
          </GlassCard>

          {/* Vulnerability List */}
          {vulnerabilities.length > 0 && (
            <GlassCard className="p-4 space-y-3 flex-1 overflow-hidden flex flex-col">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4 text-rose-400" /> Findings
                </span>
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-rose-500/10 text-rose-400 border border-rose-500/30">
                  {vulnerabilities.length}
                </span>
              </div>

              <div className="space-y-2 overflow-y-auto flex-1 pr-1 max-h-64">
                {vulnerabilities.map((v) => (
                  <button
                    key={v.id}
                    type="button"
                    onClick={() =>
                      handleSendMessage(
                        `Analyze this vulnerability and give me a secure code fix:\n\nRule: ${v.category}\nFile: ${v.file_path}:${v.line_number ?? "?"}\nMessage: ${v.message}\n${v.code_snippet ? `\nCode:\n\`\`\`\n${v.code_snippet}\n\`\`\`` : ""}`
                      )
                    }
                    className="w-full text-left p-2.5 rounded-xl bg-slate-900/60 border border-slate-800 hover:border-cyan-500/50 cursor-pointer transition-all space-y-1 group"
                  >
                    <div className="flex items-center justify-between">
                      <span className={`text-[9px] font-mono font-extrabold px-2 py-0.5 rounded uppercase ${
                        v.severity === "CRITICAL" || v.severity === "HIGH"
                          ? "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                          : v.severity === "MEDIUM"
                          ? "bg-amber-500/10 text-amber-400 border border-amber-500/30"
                          : "bg-cyan-500/10 text-cyan-400 border border-cyan-500/30"
                      }`}>
                        {v.severity}
                      </span>
                      <span className="text-[10px] font-mono text-slate-500 group-hover:text-cyan-400 transition-colors">
                        Ask AI →
                      </span>
                    </div>
                    <p className="text-xs font-bold text-slate-200 truncate">{v.category}</p>
                    <p className="text-[10px] text-slate-400 font-mono truncate">
                      {v.file_path}{v.line_number ? `:${v.line_number}` : ""}
                    </p>
                  </button>
                ))}
              </div>
            </GlassCard>
          )}

          {/* Active Engine Card & Quick Switcher */}
          <GlassCard className="p-4 space-y-2.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] font-mono text-slate-400 uppercase tracking-wider block">Reasoning Engine</span>
              <span className="text-[9px] font-mono text-cyan-400 bg-cyan-500/10 px-1.5 py-0.5 rounded border border-cyan-500/20 uppercase font-bold">
                {selectedProvider}
              </span>
            </div>
            
            <select
              value={selectedModel}
              onChange={(e) => {
                const newModel = e.target.value;
                setSelectedModel(newModel);
                let prov = "openrouter";
                if (newModel.startsWith("gpt-") || newModel.startsWith("o1") || newModel.startsWith("o3")) prov = "openai";
                else if (newModel.startsWith("gemini-")) prov = "gemini";
                else if (newModel.startsWith("claude-")) prov = "claude";
                else if (newModel.startsWith("grok-")) prov = "grok";
                setSelectedProvider(prov);
                api.updateSettings({ ai_provider: prov, default_model: newModel }).catch(() => {});
              }}
              className="w-full px-2.5 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-cyan-300 focus:outline-none focus:border-cyan-500 cursor-pointer"
            >
              <optgroup label="OpenRouter Hub" className="bg-slate-950 text-violet-400 font-bold">
                <option value="deepseek/deepseek-chat">DeepSeek V3 (Fast & Accurate)</option>
                <option value="deepseek/deepseek-r1:free">DeepSeek R1 (Free Tier)</option>
                <option value="deepseek/deepseek-r1">DeepSeek R1 (Full Reasoning)</option>
                <option value="google/gemini-2.0-flash-001">Gemini 2.0 Flash</option>
                <option value="anthropic/claude-3.5-sonnet">Claude 3.5 Sonnet</option>
                <option value="openai/o3-mini">OpenAI o3-mini</option>
                <option value="openai/gpt-4o-mini">GPT-4o Mini</option>
                <option value="meta-llama/llama-3.3-70b-instruct">Meta Llama 3.3 70B</option>
                <option value="qwen/qwen-2.5-coder-32b-instruct">Qwen 2.5 Coder 32B</option>
              </optgroup>
              <optgroup label="OpenAI Direct" className="bg-slate-950 text-sky-400 font-bold">
                <option value="gpt-4o">GPT-4o (Omni Flagship)</option>
                <option value="gpt-4o-mini">GPT-4o Mini</option>
                <option value="o3-mini">o3-mini (Code Reasoning)</option>
                <option value="o1">o1 (Deep Reasoning)</option>
                <option value="o1-mini">o1-mini (Fast Reasoning)</option>
                <option value="gpt-4-turbo">GPT-4 Turbo</option>
              </optgroup>
              <optgroup label="Google Gemini Direct" className="bg-slate-950 text-cyan-400 font-bold">
                <option value="gemini-2.0-flash">Gemini 2.0 Flash</option>
                <option value="gemini-2.0-flash-thinking-exp">Gemini 2.0 Thinking</option>
                <option value="gemini-1.5-pro">Gemini 1.5 Pro</option>
                <option value="gemini-1.5-flash">Gemini 1.5 Flash</option>
                <option value="gemini-1.5-flash-8b">Gemini 1.5 Flash 8B</option>
              </optgroup>
              <optgroup label="Anthropic Claude Direct" className="bg-slate-950 text-orange-400 font-bold">
                <option value="claude-3-5-sonnet-20241022">Claude 3.5 Sonnet v2</option>
                <option value="claude-3-5-haiku-20241022">Claude 3.5 Haiku</option>
                <option value="claude-3-opus-20240229">Claude 3 Opus</option>
                <option value="claude-3-haiku-20240307">Claude 3 Haiku</option>
              </optgroup>
              <optgroup label="xAI Grok Direct" className="bg-slate-950 text-slate-300 font-bold">
                <option value="grok-2-1212">Grok 2 Reasoning</option>
                <option value="grok-2-vision-1212">Grok 2 Vision</option>
                <option value="grok-2-mini">Grok 2 Mini</option>
              </optgroup>
            </select>

            <div className="flex items-center justify-between pt-1">
              {configuredKeys[selectedProvider] ? (
                <span className="text-[10px] font-mono text-emerald-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                  Key Configured
                </span>
              ) : (
                <span className="text-[10px] font-mono text-amber-400 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                  Key Missing
                </span>
              )}

              <button
                type="button"
                onClick={() => {
                  setApiKeyInput("");
                  setShowKey(false);
                  setKeySaveSuccess("");
                  setKeySaveError("");
                  setApiKeyModalOpen(true);
                }}
                className="px-2 py-0.5 text-[10px] font-mono font-bold text-amber-300 hover:text-amber-200 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded flex items-center gap-1 cursor-pointer transition-all"
              >
                <Key className="w-3 h-3" />
                <span>{configuredKeys[selectedProvider] ? "Update Key" : "Enter Key"}</span>
              </button>
            </div>
          </GlassCard>

          {/* Clear Chat */}
          <Button variant="glass" size="sm" onClick={handleClearChat} icon={RefreshCw} className="w-full">
            Clear Chat
          </Button>
        </div>

        {/* ── Chat Panel ── */}
        <div className="lg:col-span-3 flex h-[72vh] min-h-[32rem] flex-col glass-panel border border-slate-800/80 rounded-2xl shadow-2xl relative overflow-hidden">

          {/* Chat Header */}
          <div className="p-4 bg-slate-950/80 border-b border-slate-800/80 flex items-center justify-between backdrop-blur-md shrink-0">
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500/20 via-blue-500/20 to-violet-500/20 border border-cyan-500/40 flex items-center justify-center shadow-lg shadow-cyan-500/10">
                <Sparkles className="w-5 h-5 text-cyan-400 animate-pulse" />
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-100 flex items-center gap-2">
                  AI Bug Hunter Assistant
                  <span className="w-2 h-2 rounded-full bg-emerald-400 status-dot-active" />
                </h3>
                <p className="text-[11px] text-slate-400 font-mono">
                  {selectedScanId ? `Linked to Scan #${selectedScanId}` : "Standalone Security Auditor"}
                </p>
              </div>
            </div>

            {loadingHistory && (
              <span className="text-xs font-mono text-cyan-400 flex items-center gap-1.5 animate-pulse">
                <RefreshCw className="w-3.5 h-3.5 animate-spin" /> Loading history...
              </span>
            )}
          </div>

          {/* Messages area + Minimap track side-by-side */}
          <div className="flex flex-1 min-h-0 overflow-hidden">

            {/* Messages — native scrollbar hidden, controlled by minimap */}
            <div
              ref={messagesContainerRef}
              onScroll={handleScroll}
              className="chat-message-scrollbar flex-1 min-h-0 p-5 pr-3 space-y-4 relative scroll-smooth overflow-y-auto"
            >
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={`flex gap-3 animate-fade-in ${msg.isUser ? "justify-end" : "justify-start"}`}
              >
                {!msg.isUser && (
                  <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0 mt-5">
                    <Bot className="w-4 h-4" />
                  </div>
                )}

                <div className="max-w-[85%] space-y-1">
                  <div className="flex items-center gap-2 px-1">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-slate-400 font-mono">
                      {msg.isUser ? "You" : "AI Bug Hunter"}
                    </span>
                    <span className="text-[9px] font-mono text-slate-500">{msg.timestamp}</span>
                  </div>

                  <div className={`p-4 rounded-2xl text-xs leading-relaxed shadow-md ${
                    msg.isUser
                      ? "bg-gradient-to-r from-cyan-600 via-blue-600 to-violet-600 text-white font-medium rounded-tr-none"
                      : "bg-slate-900/90 border border-slate-800 text-slate-200 rounded-tl-none"
                  }`}>
                    <div className="whitespace-pre-wrap">
                      {renderFormattedMessage(msg.text, msg.id, copiedIndex, handleCopyCode)}
                    </div>
                  </div>
                </div>

                {msg.isUser && (
                  <div className="w-8 h-8 rounded-xl bg-violet-500/10 border border-violet-500/30 text-violet-400 flex items-center justify-center shrink-0 mt-5">
                    <User className="w-4 h-4" />
                  </div>
                )}
              </div>
            ))}

            {sending && (
              <div className="flex gap-3 animate-fade-in">
                <div className="w-8 h-8 rounded-xl bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 flex items-center justify-center shrink-0">
                  <Bot className="w-4 h-4" />
                </div>
                <div className="p-4 rounded-2xl bg-slate-900/90 border border-slate-800 text-cyan-400 text-xs font-mono flex items-center gap-2.5 rounded-tl-none">
                  <span className="flex gap-1">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "0ms" }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "150ms" }} />
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-bounce" style={{ animationDelay: "300ms" }} />
                  </span>
                  AI reasoning via {selectedProvider} · {selectedModel}...
                </div>
              </div>
            )}

            {/* ── Sticky Floating Scroll-to-Bottom Button ── */}
            <div
              className={`sticky bottom-2 z-20 flex justify-end pr-1 transition-all duration-300 ${
                showScrollBtn ? "opacity-100 translate-y-0 pointer-events-auto" : "opacity-0 translate-y-4 pointer-events-none"
              }`}
            >
              <button
                type="button"
                onClick={() => scrollToBottom()}
                title="Scroll to latest"
                className="relative flex items-center justify-center w-10 h-10 rounded-full bg-slate-900/95 border-2 border-cyan-500/70 text-cyan-400 shadow-2xl shadow-cyan-500/40 hover:bg-slate-800 hover:border-cyan-400 hover:text-white hover:scale-110 hover:shadow-cyan-500/60 transition-all duration-200 cursor-pointer group"
              >
                {/* Glowing background */}
                <span className="absolute inset-0 rounded-full bg-gradient-to-br from-cyan-500/10 to-blue-500/10 group-hover:from-cyan-500/25 group-hover:to-blue-500/20 transition-all duration-200" />
                {/* Ping ring when unread messages */}
                {unreadCount > 0 && (
                  <>
                    <span className="absolute inset-0 rounded-full border-2 border-cyan-400/50 animate-ping" />
                    <span className="absolute -top-2 -right-2 flex items-center justify-center min-w-[18px] h-[18px] px-1 rounded-full bg-gradient-to-r from-cyan-500 to-blue-500 text-[9px] font-black text-white shadow-lg shadow-cyan-500/70 z-20 border border-slate-900">
                      {unreadCount > 9 ? "9+" : unreadCount}
                    </span>
                  </>
                )}
                {/* Down Arrow */}
                <ChevronDown className="w-5 h-5 relative z-10 group-hover:translate-y-0.5 transition-transform duration-150" />
              </button>
            </div>

              <div ref={messagesEndRef} />
            </div>

            {/* ── Minimap Scroll Track ── */}
            <div
              ref={minimapTrackRef}
              onClick={handleMinimapClick}
              className="w-5 shrink-0 relative bg-slate-950/60 border-l border-slate-800/60 cursor-pointer select-none flex flex-col"
              title="Click or drag to scroll"
            >
              {/* Track background line */}
              <div className="absolute inset-x-0 top-1 bottom-1 flex justify-center">
                <div className="w-px bg-slate-700/50 h-full" />
              </div>

              {/* Message position dots */}
              {messages.map((msg, idx) => {
                const posPercent = messages.length <= 1 ? 50 : (idx / (messages.length - 1)) * 100;
                return (
                  <div
                    key={msg.id}
                    className="absolute left-1/2 -translate-x-1/2 transition-all duration-300"
                    style={{ top: `calc(${posPercent}% * 0.9 + 5%)` }}
                  >
                    <div
                      className={`rounded-full transition-all duration-200 ${
                        msg.isUser
                          ? "w-1.5 h-1.5 bg-violet-400 shadow-sm shadow-violet-500/60"
                          : "w-1.5 h-1.5 bg-cyan-400 shadow-sm shadow-cyan-500/60"
                      }`}
                    />
                  </div>
                );
              })}

              {/* Viewport Thumb */}
              <div
                onMouseDown={handleMinimapMouseDown}
                className="absolute left-0.5 right-0.5 rounded-md bg-cyan-500/25 border border-cyan-500/50 cursor-grab active:cursor-grabbing hover:bg-cyan-500/35 transition-colors duration-150 z-10"
                style={{
                  top: `${scrollPercent * (100 - thumbHeight)}%`,
                  height: `${thumbHeight}%`,
                }}
              >
                {/* Thumb grip lines */}
                <div className="absolute inset-x-1 top-1/2 -translate-y-1/2 flex flex-col gap-0.5">
                  <div className="h-px bg-cyan-400/60 rounded" />
                  <div className="h-px bg-cyan-400/60 rounded" />
                  <div className="h-px bg-cyan-400/60 rounded" />
                </div>
              </div>

              {/* Unread new messages indicator at bottom */}
              {unreadCount > 0 && (
                <div className="absolute bottom-1 left-1/2 -translate-x-1/2 flex flex-col items-center gap-0.5">
                  <div className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-ping" />
                  <div className="w-1.5 h-1.5 rounded-full bg-rose-500 absolute" />
                </div>
              )}
            </div>
          </div>

          {/* Quick Prompts */}
          <div className="px-5 py-2.5 bg-slate-950/40 border-t border-slate-800/60 flex flex-wrap items-center gap-2 shrink-0">
            <span className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Quick:</span>
            {SUGGESTED_PROMPTS.map((p, idx) => {
              const Icon = p.icon;
              return (
                <button
                  key={idx}
                  type="button"
                  onClick={() => handleSendMessage(p.label)}
                  disabled={sending}
                  className="px-3 py-1 rounded-xl bg-slate-900 hover:bg-slate-800 border border-slate-800 hover:border-cyan-500/40 text-slate-300 hover:text-cyan-300 text-[11px] font-mono transition-all cursor-pointer flex items-center gap-1.5 disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Icon className="w-3 h-3 text-cyan-400 shrink-0" />
                  <span>{p.label}</span>
                </button>
              );
            })}
          </div>

          {/* Input */}
          <div className="p-4 bg-slate-950/80 border-t border-slate-800/80 backdrop-blur-md shrink-0">
            <form
              onSubmit={(e) => { e.preventDefault(); handleSendMessage(); }}
              className="flex items-center gap-3"
            >
              <input
                type="text"
                placeholder={
                  selectedScanId
                    ? `Ask about Scan #${selectedScanId} vulnerabilities, exploits, or fixes…`
                    : "Ask any security audit question or paste a code snippet…"
                }
                value={inputMessage}
                onChange={(e) => setInputMessage(e.target.value)}
                disabled={sending}
                className="flex-1 px-4 py-3 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 disabled:opacity-50"
              />
              <Button
                type="submit"
                variant="primary"
                size="md"
                disabled={!inputMessage.trim() || sending}
                loading={sending}
                icon={Send}
              >
                Send
              </Button>
            </form>
          </div>
        </div>
      </div>

      {/* API Key Quick Modal for Chat Assistant */}
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
                  Configure {selectedProvider} API Key
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Save secret API key to enable live reasoning with {selectedProvider.toUpperCase()}
                </p>
              </div>
            </div>

            {keySaveSuccess && (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-xs rounded-xl flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                <span>{keySaveSuccess}</span>
              </div>
            )}

            {keySaveError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-xl flex items-center gap-2">
                <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />
                <span>{keySaveError}</span>
              </div>
            )}

            <form onSubmit={handleSaveApiKey} className="space-y-4">
              <div>
                <label className="block text-xs font-mono font-bold uppercase tracking-wider text-slate-400 mb-2">
                  Secret API Key
                </label>
                <div className="relative">
                  <input
                    type={showKey ? "text" : "password"}
                    required
                    placeholder={
                      selectedProvider === "openrouter"
                        ? "sk-or-v1-..."
                        : selectedProvider === "openai"
                        ? "sk-proj-..."
                        : selectedProvider === "gemini"
                        ? "AIzaSy..."
                        : selectedProvider === "claude"
                        ? "sk-ant-api03-..."
                        : "xai-..."
                    }
                    value={apiKeyInput}
                    onChange={(e) => setApiKeyInput(e.target.value)}
                    className="w-full px-4 py-3 pr-10 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono text-amber-300 focus:outline-none focus:border-amber-500 focus:ring-1 focus:ring-amber-500"
                    autoFocus
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3 top-3.5 text-slate-400 hover:text-slate-200 cursor-pointer"
                  >
                    {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
                <p className="text-[11px] text-slate-500 mt-1.5 font-sans">
                  Stored securely for your profile. You only need to enter this key once.
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
                <button
                  type="submit"
                  disabled={keySaving}
                  className="px-5 py-2 text-xs font-bold text-black bg-amber-400 hover:bg-amber-300 rounded-xl shadow-lg shadow-amber-500/20 transition-all cursor-pointer disabled:opacity-50"
                >
                  {keySaving ? "Saving..." : "Save & Activate Key"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

// ── Helpers ──────────────────────────────────────────────────────────────────

function renderFormattedMessage(
  text: string,
  msgId: string | number,
  copiedIdx: string | number | null,
  onCopy: (id: string | number, text: string) => void
): React.ReactNode {
  if (!text.includes("```")) return <span>{text}</span>;

  const parts = text.split("```");
  return (
    <>
      {parts.map((part, i) => {
        if (i % 2 === 1) {
          // code block
          const lines = part.split("\n");
          const lang = /^[a-zA-Z0-9_-]+$/.test(lines[0].trim()) ? lines[0].trim() : "";
          const code = lang ? lines.slice(1).join("\n") : part;
          const copyKey = `${msgId}-${i}`;
          return (
            <div key={i} className="my-3 rounded-xl bg-slate-950 border border-slate-700 overflow-hidden">
              <div className="flex items-center justify-between px-3 py-1.5 bg-slate-900 border-b border-slate-800 text-[10px]">
                <span className="font-bold text-cyan-400 uppercase">{lang || "Code"}</span>
                <button
                  type="button"
                  onClick={() => onCopy(copyKey, code)}
                  className="flex items-center gap-1 text-slate-400 hover:text-white transition-colors cursor-pointer"
                >
                  {copiedIdx === copyKey ? (
                    <><Check className="w-3 h-3 text-emerald-400" /><span className="text-emerald-400">Copied!</span></>
                  ) : (
                    <><Copy className="w-3 h-3" /><span>Copy</span></>
                  )}
                </button>
              </div>
              <pre className="p-3 text-[11px] text-cyan-300 overflow-x-auto font-mono whitespace-pre">{code}</pre>
            </div>
          );
        }
        return <span key={i}>{part}</span>;
      })}
    </>
  );
}

function generateFallbackResponse(
  query: string,
  provider: string,
  model: string,
  vulns: Vulnerability[]
): string {
  const q = query.toLowerCase();

  if (q.includes("sql") || q.includes("injection")) {
    return `🛡️ **SQL Injection (CWE-89) Remediation**\n\nSQL injection occurs when user input is concatenated directly into SQL queries.\n\n**Secure Pattern — Parameterized Queries (Python):**\n\`\`\`python\n# ❌ VULNERABLE\ncursor.execute(f"SELECT * FROM users WHERE username = '{username}'")\n\n# ✅ SECURE\ncursor.execute("SELECT * FROM users WHERE username = %s", (username,))\nuser = cursor.fetchone()\n\`\`\`\n\n**FastAPI with SQLAlchemy:**\n\`\`\`python\nresult = db.execute(\n    select(User).where(User.username == username)\n).scalars().first()\n\`\`\``;
  }

  if (q.includes("secret") || q.includes("hardcode") || q.includes("api key")) {
    return `🔑 **Hardcoded Secret Remediation (OWASP A07:2021)**\n\n**Steps:**\n1. Rotate compromised credentials immediately\n2. Remove secrets from source code and git history\n3. Store in environment variables or a secrets manager\n\n**Secure Pattern:**\n\`\`\`python\nimport os\nfrom dotenv import load_dotenv\n\nload_dotenv()\nOPENAI_API_KEY = os.getenv("OPENAI_API_KEY")  # Never hardcode!\n\`\`\`\n\n**For production:** use AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.`;
  }

  if (q.includes("cors") || q.includes("csrf")) {
    return `⚡ **CORS & CSRF Security Configuration**\n\nAvoid wildcard origins (\`*\`) in production. Use specific trusted domains.\n\n**FastAPI:**\n\`\`\`python\nfrom fastapi.middleware.cors import CORSMiddleware\n\napp.add_middleware(\n    CORSMiddleware,\n    allow_origins=["https://yourdomain.com"],\n    allow_credentials=True,\n    allow_methods=["GET", "POST"],\n    allow_headers=["Authorization", "Content-Type"],\n)\n\`\`\``;
  }

  if (q.includes("owasp")) {
    return `📋 **OWASP Top 10 Remediation Checklist**\n\n1. **A01 Broken Access Control** — Enforce principle of least privilege; deny by default\n2. **A02 Cryptographic Failures** — Use TLS 1.3+; never roll your own crypto\n3. **A03 Injection** — Parameterized queries; input validation; ORM usage\n4. **A04 Insecure Design** — Threat modeling; secure design patterns\n5. **A05 Security Misconfiguration** — Disable debug in prod; patch regularly\n6. **A06 Vulnerable Components** — Audit dependencies with \`pip-audit\` / \`npm audit\`\n7. **A07 Auth Failures** — MFA; strong password policies; secure session handling\n8. **A08 Integrity Failures** — Code signing; verify supply chain\n9. **A09 Logging Failures** — Log security events; centralize with SIEM\n10. **A10 SSRF** — Validate/sanitize URLs; block internal network access`;
  }

  return `🤖 **AI Security Analysis** (${provider.toUpperCase()} · ${model})\n\nQuery received: *"${query}"*\n\n${
    vulns.length > 0
      ? `I have ${vulns.length} vulnerabilities indexed for this scan (${vulns.filter(v => v.severity === "CRITICAL" || v.severity === "HIGH").length} Critical/High). Click any finding on the left to get a targeted fix, or ask me a more specific question!`
      : "Select a completed scan session on the left to load vulnerability context for targeted remediation advice."
  }`;
}

export default AIChatPage;
