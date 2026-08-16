import React, { useState } from "react";
import { api, getMaxUploadSizeMB, getMaxUploadSizeBytes, isCloudDeployment } from "../services/api";
import { optimizeZipFile, type ZipOptimizationResult } from "../utils/zipOptimizer";
import { PageHeader } from "../components/ui/PageHeader";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import { 
  Upload, GitBranch, Code, Globe, FileArchive, 
  AlertCircle, Cpu, Sparkles, FileText, Play, Check,
  FileCode2, Flame, Zap, RefreshCw, ArrowRight,
  Key, Eye, EyeOff, X, CheckCircle2
} from "lucide-react";

interface UploadProjectProps {
  onUploadSuccess: (scanId: number) => void;
  onCancel: () => void;
}

const SAMPLE_SNIPPETS = [
  {
    name: "Python (SQLi & Hardcoded AWS Secret)",
    code: `import os
import sqlite3

# Hardcoded AWS Credentials
AWS_ACCESS_KEY = "AKIA1234567890EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_user_records(user_input_id):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection via string formatting
    query = f"SELECT * FROM users WHERE id = '{user_input_id}'"
    cursor.execute(query)
    return cursor.fetchall()

def execute_maintenance(cmd_param):
    # Command injection vulnerability
    os.system("echo Maintenance: " + cmd_param)
`,
  },
  {
    name: "JavaScript/Node (DOM XSS & Command Exec)",
    code: `const express = require('express');
const { exec } = require('child_process');
const app = express();

const JWT_SECRET = "super_secret_jwt_key_12345";

app.get('/search', (req, res) => {
    const q = req.query.q;
    // DOM-based / reflected XSS
    document.getElementById("results").innerHTML = "<div>Search: " + q + "</div>";
    
    // Command Injection
    exec("ping -c 1 " + q, (err, stdout) => {
        res.send(stdout);
    });
});
`,
  },
  {
    name: "Java (Command Injection & Weak Crypto)",
    code: `import javax.crypto.Cipher;
import java.io.IOException;

public class SecurityDemo {
    private static final String API_KEY = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";

    public void runCommand(String userInput) throws IOException {
        // Insecure command execution
        Runtime.getRuntime().exec("sh -c " + userInput);
    }

    public void encryptData() throws Exception {
        // Broken cryptographic cipher
        Cipher cipher = Cipher.getInstance("DES");
    }
}
`,
  }
];

export const UploadProject: React.FC<UploadProjectProps> = ({ onUploadSuccess, onCancel }) => {
  // Form State
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [uploadType, setUploadType] = useState<"zip" | "git" | "url" | "file">("zip");
  
  // Code source inputs
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [optimizationResult, setOptimizationResult] = useState<ZipOptimizationResult | null>(null);
  const [optimizingZip, setOptimizingZip] = useState(false);
  const [gitUrl, setGitUrl] = useState("");
  const [pastedCode, setPastedCode] = useState("");
  const [isDragOver, setIsDragOver] = useState(false);

  // Security Engines selection
  const [engines, setEngines] = useState({
    gitleaks: true,
    bandit: true,
    semgrep: true,
    dependency: true,
  });

  // AI Provider & Model Selection (All 5 Providers Supported)
  const [selectedProvider, setSelectedProvider] = useState("openrouter");
  const [aiModel, setAiModel] = useState("deepseek/deepseek-chat");
  const [configuredKeys, setConfiguredKeys] = useState<Record<string, boolean>>({
    openrouter: false,
    openai: false,
    gemini: false,
    claude: false,
    grok: false,
  });

  // API Key Quick Editor Modal State
  const [apiKeyModalOpen, setApiKeyModalOpen] = useState(false);
  const [apiKeyInput, setApiKeyInput] = useState("");
  const [showKey, setShowKey] = useState(false);
  const [keySaving, setKeySaving] = useState(false);
  const [keySaveSuccess, setKeySaveSuccess] = useState("");
  const [keySaveError, setKeySaveError] = useState("");

  const detectProviderFromModel = (modelName: string): string => {
    if (modelName.startsWith("gpt-") || modelName.startsWith("o1") || modelName.startsWith("o3")) return "openai";
    if (modelName.startsWith("gemini-")) return "gemini";
    if (modelName.startsWith("claude-")) return "claude";
    if (modelName.startsWith("grok-")) return "grok";
    return "openrouter";
  };

  // Load user's saved active provider & model and configured keys from Settings
  React.useEffect(() => {
    let active = true;
    api.getSettings()
      .then((settings) => {
        if (!active || !settings) return;
        if (settings.ai_provider && settings.ai_provider.toLowerCase() !== "ollama") setSelectedProvider(settings.ai_provider);
        if (settings.default_model) setAiModel(settings.default_model);
        setConfiguredKeys({
          openrouter: !!settings.openrouter_api_key_configured,
          openai: !!settings.openai_api_key_configured,
          gemini: !!settings.gemini_api_key_configured,
          claude: !!settings.claude_api_key_configured,
          grok: !!settings.grok_api_key_configured,
        });
      })
      .catch(() => {});
    return () => { active = false; };
  }, []);

  const handleModelChange = (newModel: string) => {
    setAiModel(newModel);
    const prov = detectProviderFromModel(newModel);
    setSelectedProvider(prov);
  };

  const handleOpenApiKeyModal = () => {
    setApiKeyInput("");
    setShowKey(false);
    setKeySaveSuccess("");
    setKeySaveError("");
    setApiKeyModalOpen(true);
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
        default_model: aiModel,
      });

      setConfiguredKeys((prev) => ({ ...prev, [selectedProvider]: true }));
      setKeySaveSuccess(`${selectedProvider.toUpperCase()} API key saved and activated successfully!`);
      setTimeout(() => {
        setApiKeyModalOpen(false);
        setApiKeyInput("");
        setKeySaveSuccess("");
      }, 1000);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : String(err);
      setKeySaveError(`Failed to save ${selectedProvider} API key: ` + errMsg);
    } finally {
      setKeySaving(false);
    }
  };

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const maxMB = getMaxUploadSizeMB();
  const maxBytes = getMaxUploadSizeBytes();
  const isCloud = isCloudDeployment();

  const processFileSelection = async (file: File) => {
    setError("");
    setSelectedFile(file);
    setOptimizationResult(null);

    // Auto-generate project name from filename
    if (!name.trim()) {
      const cleanName = file.name.replace(/\.[^/.]+$/, "").replace(/[^a-zA-Z0-9_-]/g, "_");
      setName(cleanName || "Uploaded-Project");
    }

    // Run in-browser ZIP optimization for .zip archives
    if (file.name.toLowerCase().endsWith(".zip") || file.type.includes("zip")) {
      setOptimizingZip(true);
      try {
        const result = await optimizeZipFile(file);
        setOptimizationResult(result);
        setSelectedFile(result.file);

        if (result.file.size > maxBytes) {
          setError(`Even after stripping node_modules/bloat, file is ${(result.file.size / (1024 * 1024)).toFixed(2)} MB (limit: ${maxMB} MB on cloud serverless). Switch to the Git Repository tab to clone and scan this repo with no size limits!`);
        }
      } catch (err) {
        console.error("ZIP optimization error:", err);
      } finally {
        setOptimizingZip(false);
      }
    } else {
      if (file.size > maxBytes) {
        setError(`File "${file.name}" is ${(file.size / (1024 * 1024)).toFixed(2)} MB, which exceeds the ${maxMB} MB cloud upload limit.`);
      }
    }
  };

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFileSelection(e.dataTransfer.files[0]);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFileSelection(e.target.files[0]);
    }
  };

  const handleLoadSample = (sample: typeof SAMPLE_SNIPPETS[0]) => {
    setPastedCode(sample.code);
    if (!name.trim()) {
      setName(sample.name.split(" ")[0] + "-Security-Audit");
    }
    setError("");
  };

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (loading || optimizingZip) return; // Prevent double execution

    let effectiveName = name.trim();

    // Auto-generate project name if not specified
    if (!effectiveName) {
      if (uploadType === "zip" && selectedFile) {
        effectiveName = selectedFile.name.replace(/\.[^/.]+$/, "").replace(/[^a-zA-Z0-9_-]/g, "_") || "Uploaded-Source";
      } else if (uploadType === "git" && gitUrl) {
        const match = gitUrl.match(/\/([^/]+?)(?:\.git)?$/);
        effectiveName = (match ? match[1] : "Git-Repository").replace(/[^a-zA-Z0-9_-]/g, "_");
      } else if (uploadType === "url" && gitUrl) {
        effectiveName = "Web-Repository-Audit";
      } else if (uploadType === "file" && pastedCode) {
        effectiveName = `Code-Snippet-Audit-${new Date().toISOString().slice(0, 10)}`;
      } else {
        effectiveName = `Security-Scan-${new Date().toISOString().slice(0, 10)}`;
      }
      setName(effectiveName);
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("name", effectiveName);
      if (description) formData.append("description", description);
      formData.append("upload_type", uploadType);

      if (uploadType === "zip") {
        if (!selectedFile) {
          throw new Error("Please select or drop a source code file (.py, .js, .ts, etc.) or a .ZIP archive to scan.");
        }
        if (selectedFile.size > maxBytes) {
          throw new Error(`File "${selectedFile.name}" is ${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB, which exceeds the ${maxMB} MB upload limit. Please use the Git Repository tab to scan this repository.`);
        }
        formData.append("file", selectedFile);
      } else if (uploadType === "git") {
        if (!gitUrl.trim()) throw new Error("Please enter a valid Git Repository URL (e.g. https://github.com/owner/repo.git).");
        formData.append("git_url", gitUrl.trim());
      } else if (uploadType === "url") {
        if (!gitUrl.trim()) throw new Error("Please enter a valid Web Repository link.");
        formData.append("git_url", gitUrl.trim());
      } else if (uploadType === "file") {
        if (!pastedCode.trim()) throw new Error("Pasted source code cannot be empty. Paste your code snippet or click a preset sample below.");
        formData.append("pasted_code", pastedCode.trim());
      }

      // 1. Persist active AI model & provider configuration
      try {
        await api.updateSettings({
          ai_provider: selectedProvider,
          default_model: aiModel,
        });
      } catch (e) {
        console.warn("Settings sync notice:", e);
      }

      // 2. Create project record
      const proj = await api.createProject(formData);
      
      // 3. Trigger asynchronous multi-engine SAST scan
      const scan = await api.triggerScan(proj.id);
      
      // 4. Forward to real-time progress monitor
      onUploadSuccess(scan.id);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Failed to upload project. Check input parameters.";
      setError(errMsg);
      setLoading(false);
    }
  };

  const tabOptions = [
    { id: "zip", label: "Source Code / ZIP", icon: FileArchive, desc: "Upload .zip or single file" },
    { id: "file", label: "Paste Code", icon: Code, desc: "Direct snippet analysis" },
    { id: "git", label: "Git Repository", icon: GitBranch, desc: "Clone GitHub / GitLab" },
    { id: "url", label: "Web Repository", icon: Globe, desc: "Remote web repository" },
  ];

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-fade-in pb-12">
      
      {/* Header */}
      <PageHeader
        title="New Security Analysis Scan"
        subtitle="Upload source code or repository links to launch automated SAST scanning and AI vulnerability reasoning"
        action={
          <Button variant="ghost" size="sm" onClick={onCancel}>
            Cancel
          </Button>
        }
      />

      {error && (
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-2xl flex items-center gap-3 animate-fade-in shadow-lg shadow-rose-500/5">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-500" />
          <span className="font-medium leading-relaxed">{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        
        {/* SECTION 1: Project Metadata */}
        <GlassCard className="p-6 space-y-4" topBarGradient={true}>
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
              <FileText className="w-4 h-4 text-cyan-400" /> 1. Project Metadata
            </h2>
            <p className="text-xs text-slate-400 mt-1">Specify unique project identifiers for your SAST analysis report.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Project Name <span className="text-slate-500 font-normal">(Auto-generated if empty)</span>
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Fintech-Payment-Gateway API"
                className="w-full px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                Description / Scope (Optional)
              </label>
              <input
                type="text"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g. Audit for secrets, SQLi, and OWASP Top 10"
                className="w-full px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
              />
            </div>
          </div>
        </GlassCard>

        {/* SECTION 2: Code Source Selection Tabs */}
        <GlassCard className="p-6 space-y-6" topBarGradient={true}>
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
              <Upload className="w-4 h-4 text-cyan-400" /> 2. Source Code Selection
            </h2>
            <p className="text-xs text-slate-400 mt-1">Choose how you want to upload code for static analysis.</p>
          </div>

          {/* 4 Touch-friendly Source Tabs */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {tabOptions.map((tab) => {
              const Icon = tab.icon;
              const isSelected = uploadType === tab.id;
              return (
                <button
                  type="button"
                  key={tab.id}
                  onClick={() => {
                    setUploadType(tab.id as any);
                    setError("");
                  }}
                  className={`p-4 rounded-xl text-left border transition-all cursor-pointer min-h-[64px] flex flex-col justify-between ${
                    isSelected
                      ? "bg-gradient-to-br from-cyan-500/20 to-blue-500/15 border-cyan-500/40 text-cyan-300 shadow-lg shadow-cyan-500/10 scale-[1.02]"
                      : "bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700 hover:text-slate-200"
                  }`}
                >
                  <div className="flex items-center justify-between w-full">
                    <Icon className={`w-5 h-5 ${isSelected ? "text-cyan-400" : "text-slate-400"}`} />
                    {isSelected && <Check className="w-4 h-4 text-cyan-400" />}
                  </div>
                  <div className="mt-3">
                    <span className="text-xs font-bold block">{tab.label}</span>
                    <span className="text-[10px] text-slate-500 font-mono block">{tab.desc}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* TAB CONTENT: ZIP or Direct Code File Upload */}
          {uploadType === "zip" && (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleFileDrop}
              className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all cursor-pointer min-h-[170px] flex flex-col items-center justify-center ${
                isDragOver
                  ? "border-cyan-400 bg-cyan-500/10"
                  : selectedFile
                  ? "border-emerald-500/40 bg-emerald-500/5"
                  : "border-slate-800 bg-slate-900/40 hover:border-slate-700"
              }`}
            >
              <input
                type="file"
                accept=".zip,.py,.js,.ts,.tsx,.jsx,.java,.c,.cpp,.cs,.php,.go,.rs,.html,.json,.txt,.sql"
                onChange={handleFileChange}
                className="hidden"
                id="source-file-input"
              />
              <label htmlFor="source-file-input" className="cursor-pointer w-full h-full flex flex-col items-center">
                {optimizingZip ? (
                  <div className="space-y-3 py-4 animate-pulse">
                    <div className="w-12 h-12 rounded-full border border-cyan-500/40 bg-cyan-500/10 text-cyan-400 flex items-center justify-center mx-auto">
                      <RefreshCw className="w-6 h-6 animate-spin" />
                    </div>
                    <span className="font-bold text-sm text-cyan-300 block">⚡ Optimizing Code Archive in Browser...</span>
                    <span className="text-xs text-slate-400 font-mono block">
                      Stripping bloated node_modules, .git, and binaries for instant Vercel cloud upload...
                    </span>
                  </div>
                ) : selectedFile ? (
                  <div className="space-y-3 w-full max-w-lg mx-auto">
                    <div className={`w-12 h-12 rounded-full border flex items-center justify-center mx-auto ${
                      selectedFile.size > maxBytes
                        ? "bg-rose-500/20 border-rose-500/40 text-rose-400"
                        : "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
                    }`}>
                      {selectedFile.size > maxBytes ? <AlertCircle className="w-6 h-6" /> : <Check className="w-6 h-6" />}
                    </div>

                    <div>
                      <span className="font-bold text-sm text-slate-100 block truncate">{selectedFile.name}</span>
                      
                      {optimizationResult && optimizationResult.isOptimized && (
                        <div className="mt-2 p-2.5 bg-emerald-500/10 border border-emerald-500/30 rounded-xl text-left text-xs font-mono space-y-1">
                          <div className="flex items-center justify-between font-bold text-emerald-300">
                            <span className="flex items-center gap-1.5"><Zap className="w-3.5 h-3.5 text-emerald-400" /> Auto-Optimized In-Browser</span>
                            <span className="bg-emerald-500/20 px-2 py-0.5 rounded text-[11px]">-{optimizationResult.savingsPercent}% Size</span>
                          </div>
                          <div className="text-slate-300 text-[11px] flex justify-between">
                            <span>{optimizationResult.originalSizeMB} MB ➔ {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</span>
                            <span className="text-slate-400">Stripped {optimizationResult.excludedFilesCount} bloat files</span>
                          </div>
                        </div>
                      )}

                      {selectedFile.size > maxBytes ? (
                        <div className="mt-3 p-3 bg-rose-500/10 border border-rose-500/30 rounded-xl text-xs space-y-2">
                          <span className="text-rose-400 font-mono block font-semibold">
                            ⚠️ {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB exceeds {maxMB} MB Cloud Serverless limit
                          </span>
                          <p className="text-slate-300 text-[11px]">
                            Vercel Serverless Functions have a 4.5 MB request limit. For larger codebases, clone directly via Git without size constraints:
                          </p>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation();
                              setUploadType("git");
                              setError("");
                            }}
                            className="w-full py-2 px-3 bg-cyan-500/20 hover:bg-cyan-500/30 border border-cyan-500/40 text-cyan-200 rounded-lg font-mono font-bold text-xs flex items-center justify-center gap-2 cursor-pointer transition-all hover:scale-[1.02]"
                          >
                            <GitBranch className="w-4 h-4 text-cyan-400" />
                            <span>Switch to Git Repository Clone</span>
                            <ArrowRight className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      ) : (
                        <span className="text-xs text-emerald-400 font-mono block mt-1.5">
                          {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for SAST scan
                        </span>
                      )}
                    </div>

                    <span className="text-[11px] text-cyan-400 hover:text-cyan-300 underline block pt-1">
                      Click to choose a different file
                    </span>
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Upload className="w-8 h-8 text-cyan-400 mx-auto" />
                    <span className="text-xs font-bold text-slate-200 block">
                      Drag & Drop your .zip source archive or source code file here, or <span className="text-cyan-400 underline">Browse</span>
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono block">
                      Supports Python, JS, TS, Go, Java, C++, PHP, and .ZIP packages (Auto-optimizes node_modules & bloat)
                    </span>
                    {isCloud && (
                      <span className="text-[10px] text-cyan-400/80 font-mono block bg-slate-950/40 py-1 px-3 rounded-full border border-slate-800/80 w-fit mx-auto">
                        ☁️ Cloud Serverless Optimized (Auto-filters node_modules & binaries)
                      </span>
                    )}
                  </div>
                )}
              </label>
            </div>
          )}

          {/* TAB CONTENT: Paste Source Code */}
          {uploadType === "file" && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                  Paste Source Code Snippet
                </label>
                <div className="flex items-center gap-1 text-[11px] text-slate-400">
                  <Flame className="w-3.5 h-3.5 text-amber-400" />
                  <span>Try sample:</span>
                </div>
              </div>

              {/* Sample Code Quick-Pills */}
              <div className="flex flex-wrap gap-2">
                {SAMPLE_SNIPPETS.map((sample, idx) => (
                  <button
                    type="button"
                    key={idx}
                    onClick={() => handleLoadSample(sample)}
                    className="px-3 py-1.5 rounded-lg text-xs font-mono bg-slate-900 border border-slate-800 text-slate-300 hover:border-cyan-500/40 hover:text-cyan-300 hover:bg-cyan-500/10 transition-all flex items-center gap-1.5 cursor-pointer"
                  >
                    <FileCode2 className="w-3.5 h-3.5 text-cyan-400" />
                    <span>{sample.name}</span>
                  </button>
                ))}
              </div>

              <textarea
                rows={10}
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                placeholder={`# Paste python code, JS script, or API file here...\nimport os\napi_key = "AKIA1234567890EXAMPLE"\nquery = f"SELECT * FROM users WHERE name = '{user_name}'"`}
                className="w-full p-4 glass-input rounded-xl text-xs font-mono placeholder-slate-600 focus:outline-none leading-relaxed"
              />
              <span className="text-[11px] text-slate-500 font-mono block">
                Instant static analysis scan for raw source code snippets up to 10,000 lines.
              </span>
            </div>
          )}

          {/* TAB CONTENT: Git Repository URL */}
          {uploadType === "git" && (
            <div className="space-y-3">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                Git Repository HTTPS / SSH URL
              </label>
              <div className="flex gap-2">
                <input
                  type="url"
                  value={gitUrl}
                  onChange={(e) => {
                    setGitUrl(e.target.value);
                    if (!name.trim()) {
                      const match = e.target.value.match(/\/([^/]+?)(?:\.git)?$/);
                      if (match) setName(match[1]);
                    }
                  }}
                  placeholder="https://github.com/organization/secure-api.git"
                  className="flex-1 px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
                />
              </div>
              <span className="text-[11px] text-slate-500 font-mono block">
                The scanner will perform shallow clone & run Gitleaks + Semgrep + AST rules against the head commit.
              </span>
            </div>
          )}

          {/* TAB CONTENT: Web Repository URL */}
          {uploadType === "url" && (
            <div className="space-y-3">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                Web Repository or Codebase Link
              </label>
              <input
                type="url"
                value={gitUrl}
                onChange={(e) => setGitUrl(e.target.value)}
                placeholder="https://gitlab.com/company/auth-service"
                className="w-full px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
              />
              <span className="text-[11px] text-slate-500 font-mono block">
                Fetches and analyzes web-hosted source code repositories over standard HTTPS.
              </span>
            </div>
          )}
        </GlassCard>

        {/* SECTION 3: Scanner Engines & AI Model Settings */}
        <GlassCard className="p-6 space-y-4" topBarGradient={true}>
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" /> 3. Scanner Engines & AI Reasoning Model
            </h2>
            <p className="text-xs text-slate-400 mt-1">Configure active SAST engines and local LLM options.</p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {/* SAST Scanner Toggles */}
            <div className="space-y-3">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono block">
                Active Security Scanners
              </span>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer hover:border-slate-700 transition-colors">
                  <input
                    type="checkbox"
                    checked={engines.gitleaks}
                    onChange={(e) => setEngines({ ...engines, gitleaks: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Gitleaks (Secrets)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer hover:border-slate-700 transition-colors">
                  <input
                    type="checkbox"
                    checked={engines.bandit}
                    onChange={(e) => setEngines({ ...engines, bandit: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Bandit (Python AST)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer hover:border-slate-700 transition-colors">
                  <input
                    type="checkbox"
                    checked={engines.semgrep}
                    onChange={(e) => setEngines({ ...engines, semgrep: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Semgrep (Multi-Lang)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer hover:border-slate-700 transition-colors">
                  <input
                    type="checkbox"
                    checked={engines.dependency}
                    onChange={(e) => setEngines({ ...engines, dependency: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Dependency (CVEs)</span>
                </label>
              </div>
            </div>

            {/* AI Security Model Selection (Supports 5 AI Providers) */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono block">
                  AI Security Intelligence Engine
                </span>
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-500/20 px-2 py-0.5 rounded-md">
                  5 Providers Supported
                </span>
              </div>
              
              <select
                value={aiModel}
                onChange={(e) => handleModelChange(e.target.value)}
                className="w-full px-4 py-3 glass-input rounded-xl text-xs font-mono focus:outline-none cursor-pointer border border-slate-700/80 bg-slate-900/90 text-slate-200"
              >
                <optgroup label="OpenRouter.ai (Recommended Cloud Hub)" className="bg-slate-950 text-violet-400 font-bold">
                  <option value="deepseek/deepseek-chat" className="bg-slate-900 text-slate-200 font-mono py-1">
                    deepseek/deepseek-chat (DeepSeek V3 671B - High Accuracy & Fast)
                  </option>
                  <option value="deepseek/deepseek-r1:free" className="bg-slate-900 text-slate-200 font-mono py-1">
                    deepseek/deepseek-r1:free (DeepSeek R1 Reasoning - Free Tier)
                  </option>
                  <option value="deepseek/deepseek-r1" className="bg-slate-900 text-slate-200 font-mono py-1">
                    deepseek/deepseek-r1 (DeepSeek R1 Full Reasoning)
                  </option>
                  <option value="google/gemini-2.0-flash-001" className="bg-slate-900 text-slate-200 font-mono py-1">
                    google/gemini-2.0-flash-001 (Google Gemini 2.0 Flash)
                  </option>
                  <option value="google/gemini-2.0-flash-exp:free" className="bg-slate-900 text-slate-200 font-mono py-1">
                    google/gemini-2.0-flash-exp:free (Gemini 2.0 Flash Free)
                  </option>
                  <option value="anthropic/claude-3.5-sonnet" className="bg-slate-900 text-slate-200 font-mono py-1">
                    anthropic/claude-3.5-sonnet (Claude 3.5 Sonnet)
                  </option>
                  <option value="openai/o3-mini" className="bg-slate-900 text-slate-200 font-mono py-1">
                    openai/o3-mini (OpenAI o3-mini Reasoning)
                  </option>
                  <option value="openai/gpt-4o-mini" className="bg-slate-900 text-slate-200 font-mono py-1">
                    openai/gpt-4o-mini (GPT-4o Mini via OpenRouter)
                  </option>
                  <option value="meta-llama/llama-3.3-70b-instruct" className="bg-slate-900 text-slate-200 font-mono py-1">
                    meta-llama/llama-3.3-70b-instruct (Meta Llama 3.3 70B)
                  </option>
                  <option value="qwen/qwen-2.5-coder-32b-instruct" className="bg-slate-900 text-slate-200 font-mono py-1">
                    qwen/qwen-2.5-coder-32b-instruct (Qwen 2.5 Coder 32B)
                  </option>
                  <option value="mistralai/mistral-large-2411" className="bg-slate-900 text-slate-200 font-mono py-1">
                    mistralai/mistral-large-2411 (Mistral Large 2411)
                  </option>
                </optgroup>
                <optgroup label="OpenAI (Direct Cloud API)" className="bg-slate-950 text-sky-400 font-bold">
                  <option value="gpt-4o" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gpt-4o (OpenAI Omni Flagship Multi-Step Reasoning)
                  </option>
                  <option value="gpt-4o-mini" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gpt-4o-mini (OpenAI Fast Lightweight Intelligence)
                  </option>
                  <option value="o3-mini" className="bg-slate-900 text-slate-200 font-mono py-1">
                    o3-mini (OpenAI Next-Gen STEM & Code Reasoning)
                  </option>
                  <option value="o1" className="bg-slate-900 text-slate-200 font-mono py-1">
                    o1 (OpenAI Deep Reasoning Leader)
                  </option>
                  <option value="o1-mini" className="bg-slate-900 text-slate-200 font-mono py-1">
                    o1-mini (OpenAI Fast Reasoning)
                  </option>
                  <option value="gpt-4-turbo" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gpt-4-turbo (OpenAI Deep Code Audit)
                  </option>
                </optgroup>
                <optgroup label="Google Gemini (Direct Cloud API)" className="bg-slate-950 text-cyan-400 font-bold">
                  <option value="gemini-2.0-flash" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gemini-2.0-flash (Google Gemini 2.0 Next-Gen Flagship)
                  </option>
                  <option value="gemini-2.0-flash-thinking-exp" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gemini-2.0-flash-thinking-exp (Gemini 2.0 Thinking & Deep Reasoning)
                  </option>
                  <option value="gemini-1.5-pro" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gemini-1.5-pro (Google 2M Token Deep Code Analysis)
                  </option>
                  <option value="gemini-1.5-flash" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gemini-1.5-flash (Google Ultra Fast & Low Latency)
                  </option>
                  <option value="gemini-1.5-flash-8b" className="bg-slate-900 text-slate-200 font-mono py-1">
                    gemini-1.5-flash-8b (Google Ultra-Compact High Throughput)
                  </option>
                </optgroup>
                <optgroup label="Anthropic Claude (Direct Cloud API)" className="bg-slate-950 text-orange-400 font-bold">
                  <option value="claude-3-5-sonnet-20241022" className="bg-slate-900 text-slate-200 font-mono py-1">
                    claude-3-5-sonnet-20241022 (Claude 3.5 Sonnet v2 - SOTA Code Audit)
                  </option>
                  <option value="claude-3-5-haiku-20241022" className="bg-slate-900 text-slate-200 font-mono py-1">
                    claude-3-5-haiku-20241022 (Claude 3.5 Haiku - Ultra Fast & Precise)
                  </option>
                  <option value="claude-3-opus-20240229" className="bg-slate-900 text-slate-200 font-mono py-1">
                    claude-3-opus-20240229 (Claude 3 Opus - Deep Comprehensive Review)
                  </option>
                  <option value="claude-3-haiku-20240307" className="bg-slate-900 text-slate-200 font-mono py-1">
                    claude-3-haiku-20240307 (Claude 3 Haiku - Rapid Threat Assessment)
                  </option>
                </optgroup>
                <optgroup label="xAI Grok (Direct Cloud API)" className="bg-slate-950 text-slate-300 font-bold">
                  <option value="grok-2-1212" className="bg-slate-900 text-slate-200 font-mono py-1">
                    grok-2-1212 (xAI Grok 2 Advanced Reasoning)
                  </option>
                  <option value="grok-2-vision-1212" className="bg-slate-900 text-slate-200 font-mono py-1">
                    grok-2-vision-1212 (xAI Grok 2 Vision Multimodal)
                  </option>
                  <option value="grok-2-mini" className="bg-slate-900 text-slate-200 font-mono py-1">
                    grok-2-mini (xAI Grok 2 Mini Fast Intelligence)
                  </option>
                </optgroup>
              </select>

              <div className="flex flex-wrap items-center justify-between gap-2 text-[11px] font-mono pt-1">
                <span className="flex items-center gap-1.5 text-slate-300">
                  <Sparkles className="w-3.5 h-3.5 text-cyan-400 shrink-0" />
                  <span>Selected Engine:</span>
                  <span className="font-bold text-cyan-300 uppercase">{selectedProvider}</span>
                  <span className="text-slate-400 truncate max-w-[180px]">({aiModel})</span>
                </span>

                <div className="flex items-center gap-2">
                  {configuredKeys[selectedProvider] ? (
                    <span className="px-2 py-0.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                      Key Saved
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-full bg-amber-500/10 border border-amber-500/30 text-amber-400 text-[10px] font-bold flex items-center gap-1">
                      <span className="w-1.5 h-1.5 rounded-full bg-amber-400 animate-pulse" />
                      Key Required
                    </span>
                  )}

                  <button
                    type="button"
                    onClick={handleOpenApiKeyModal}
                    className="px-2.5 py-1 text-[10px] font-mono font-bold text-amber-300 hover:text-amber-200 bg-amber-500/10 hover:bg-amber-500/20 border border-amber-500/30 rounded-lg flex items-center gap-1 transition-all cursor-pointer shadow-sm"
                  >
                    <Key className="w-3 h-3" />
                    <span>{configuredKeys[selectedProvider] ? "Update Key" : "Enter API Key"}</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        </GlassCard>

        {/* Submit Actions Footer */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <Button variant="ghost" onClick={onCancel} disabled={loading}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon={Play}
            loading={loading}
            disabled={loading}
            className="min-h-[48px] px-8 text-sm cursor-pointer shadow-lg shadow-cyan-500/20"
          >
            {loading ? "Starting Scan..." : "Launch SAST Analysis"}
          </Button>
        </div>
      </form>

      {/* API Key Modal Overlay for Scan Launcher */}
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
                  Save secret API key to execute AI security fixes with {selectedProvider.toUpperCase()}
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
                  Stored securely for your user profile. You only need to enter this key once.
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
