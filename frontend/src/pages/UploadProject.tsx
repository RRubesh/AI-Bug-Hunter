import React, { useState } from "react";
import { api } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import { 
  Upload, GitBranch, Code, Globe, FileArchive, 
  AlertCircle, Shield, Cpu, Sparkles, FileText, Play, Check
} from "lucide-react";

interface UploadProjectProps {
  onUploadSuccess: (scanId: number) => void;
  onCancel: () => void;
}

export const UploadProject: React.FC<UploadProjectProps> = ({ onUploadSuccess, onCancel }) => {
  // Form State
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [uploadType, setUploadType] = useState<"zip" | "git" | "file" | "url">("zip");
  
  // Code source inputs
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
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

  // AI Model Selection
  const [aiProvider] = useState("ollama");
  const [aiModel, setAiModel] = useState("qwen2.5-coder:1.5b");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleSubmit = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    if (!name.trim()) {
      setError("Project name is required.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const formData = new FormData();
      formData.append("name", name);
      if (description) formData.append("description", description);
      formData.append("upload_type", uploadType);

      if (uploadType === "zip") {
        if (!selectedFile) throw new Error("Please select a ZIP file containing the source code.");
        formData.append("file", selectedFile);
      } else if (uploadType === "git") {
        if (!gitUrl.trim()) throw new Error("Please enter a valid Git Repository URL.");
        formData.append("git_url", gitUrl);
      } else if (uploadType === "url") {
        if (!gitUrl.trim()) throw new Error("Please enter a valid website or repository URL link.");
        formData.append("git_url", gitUrl);
      } else if (uploadType === "file") {
        if (!pastedCode.trim()) throw new Error("Pasted source code cannot be empty.");
        formData.append("pasted_code", pastedCode);
      }

      const proj = await api.createProject(formData);
      const scan = await api.triggerScan(proj.id);
      onUploadSuccess(scan.id);
    } catch (err: unknown) {
      const errMsg = err instanceof Error ? err.message : "Failed to upload project. Check input parameters.";
      setError(errMsg);
      setLoading(false);
    }
  };

  return (
    <div className="max-w-5xl mx-auto space-y-8 animate-fade-in">
      
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
        <div className="p-4 bg-rose-500/10 border border-rose-500/30 text-rose-400 text-xs rounded-2xl flex items-center gap-3">
          <AlertCircle className="w-5 h-5 shrink-0 text-rose-500" />
          <span>{error}</span>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        
        {/* SECTION 1: Project Information */}
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
                Project Name <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Fintech-Payment-Gateway API"
                className="w-full px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
                required
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
                placeholder="e.g. Core authentication microservice handling JWT tokens"
                className="w-full px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
              />
            </div>
          </div>
        </GlassCard>

        {/* SECTION 2: Code Source Input */}
        <GlassCard className="p-6 space-y-6">
          <div className="border-b border-slate-800 pb-3">
            <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
              <Code className="w-4 h-4 text-cyan-400" /> 2. Source Code Input
            </h2>
            <p className="text-xs text-slate-400 mt-1">Select source type and attach project files or repository links.</p>
          </div>

          {/* Upload Method Selector Tabs */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { id: "zip", label: "ZIP Archive", icon: FileArchive, desc: "Upload .zip archive" },
              { id: "git", label: "Git Repository", icon: GitBranch, desc: "Clone from Git URL" },
              { id: "url", label: "Web Link", icon: Globe, desc: "Analyze web link" },
              { id: "file", label: "Paste Code", icon: Code, desc: "Direct snippet paste" },
            ].map((method) => {
              const Icon = method.icon;
              const isSelected = uploadType === method.id;

              return (
                <button
                  key={method.id}
                  type="button"
                  onClick={() => setUploadType(method.id as "zip" | "git" | "file" | "url")}
                  aria-pressed={isSelected}
                  className={`group relative min-h-36 overflow-hidden p-4 rounded-2xl text-left border transition-all duration-300 ease-out flex flex-col justify-between focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/80 ${
                    isSelected
                      ? "bg-gradient-to-br from-cyan-500/20 via-blue-500/10 to-violet-500/15 border-cyan-400/80 text-cyan-300 shadow-[0_14px_30px_-15px_rgba(6,182,212,0.55)]"
                      : "bg-slate-950/40 border-slate-700/70 text-slate-400 hover:-translate-y-1 hover:border-cyan-500/45 hover:bg-slate-800/70 hover:shadow-[0_12px_28px_-18px_rgba(6,182,212,0.45)]"
                  }`}
                >
                  <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/60 to-transparent opacity-0 transition-opacity duration-300 group-hover:opacity-100" />
                  <div className="flex items-center justify-between w-full mb-3">
                    <span className={`w-10 h-10 rounded-xl flex items-center justify-center border transition-all duration-300 ${
                      isSelected
                        ? "bg-cyan-400/15 border-cyan-300/40 text-cyan-300 shadow-[0_0_18px_rgba(34,211,238,0.22)]"
                        : "bg-slate-900/80 border-slate-700/70 text-slate-400 group-hover:border-cyan-500/30 group-hover:text-cyan-300"
                    }`}>
                      <Icon className="w-5 h-5" />
                    </span>
                    {isSelected && (
                      <span className="w-5 h-5 rounded-full bg-cyan-400 text-slate-950 flex items-center justify-center shadow-[0_0_14px_rgba(34,211,238,0.7)] animate-pulse">
                        <Check className="w-3.5 h-3.5 stroke-[3]" />
                      </span>
                    )}
                  </div>
                  <div>
                    <span className={`text-xs font-bold font-mono block transition-colors ${isSelected ? "text-cyan-100" : "text-slate-200 group-hover:text-cyan-100"}`}>{method.label}</span>
                    <span className="text-[11px] text-slate-400 mt-1 block leading-relaxed">{method.desc}</span>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Tab 1: ZIP Drag & Drop */}
          {uploadType === "zip" && (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleFileDrop}
              className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all duration-300 ${
                isDragOver
                  ? "border-cyan-400 bg-cyan-500/10"
                  : selectedFile
                  ? "border-emerald-500/40 bg-emerald-500/5"
                  : "border-slate-800 hover:border-slate-700 bg-slate-900/30"
              }`}
            >
              <input
                type="file"
                accept=".zip"
                onChange={handleFileChange}
                className="hidden"
                id="file-upload"
              />
              <label htmlFor="file-upload" className="cursor-pointer block space-y-3">
                <div className="w-14 h-14 rounded-2xl bg-cyan-500/10 text-cyan-400 flex items-center justify-center mx-auto border border-cyan-500/20">
                  <Upload className="w-7 h-7" />
                </div>
                {selectedFile ? (
                  <div>
                    <span className="text-sm font-bold text-emerald-400 block font-mono">
                      {selectedFile.name}
                    </span>
                    <span className="text-xs text-slate-400 mt-1 block">
                      {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB — Ready to scan
                    </span>
                  </div>
                ) : (
                  <div>
                    <span className="text-sm font-bold text-slate-200 block">
                      Drag & Drop ZIP file here, or <span className="text-cyan-400 underline">Browse</span>
                    </span>
                    <span className="text-xs text-slate-400 mt-1 block font-mono">
                      Supports .ZIP archives containing source files (.py, .js, .ts, .go, .java, .php, etc.)
                    </span>
                  </div>
                )}
              </label>
            </div>
          )}

          {/* Tab 2 & 3: Git / Web URL Input */}
          {(uploadType === "git" || uploadType === "url") && (
            <div className="space-y-3">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                {uploadType === "git" ? "Git Repository URL" : "Web / Target Link URL"}
              </label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none text-slate-400">
                  {uploadType === "git" ? <GitBranch className="w-4 h-4" /> : <Globe className="w-4 h-4" />}
                </div>
                <input
                  type="url"
                  value={gitUrl}
                  onChange={(e) => setGitUrl(e.target.value)}
                  placeholder={
                    uploadType === "git"
                      ? "https://github.com/org/security-repository.git"
                      : "https://example.com/api/endpoint"
                  }
                  className="w-full pl-10 pr-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none font-mono"
                />
              </div>
            </div>
          )}

          {/* Tab 4: Direct Code Paste */}
          {uploadType === "file" && (
            <div className="space-y-3">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                Paste Source Code Snippet
              </label>
              <textarea
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                rows={10}
                placeholder={`// Paste snippet here for instant SAST analysis...\nfunction authenticateUser(user, pass) {\n  const query = "SELECT * FROM users WHERE username = '" + user + "' AND password = '" + pass + "'";\n  return db.execute(query);\n}`}
                className="w-full p-4 glass-input rounded-xl font-mono text-xs text-cyan-300 placeholder-slate-600 focus:outline-none leading-relaxed"
              />
            </div>
          )}
        </GlassCard>

        {/* SECTION 3: Scanner Engines & AI Model Selection */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          
          {/* Scanner Engines */}
          <GlassCard className="p-6 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-400" /> 3. Security Engine Suite
              </h2>
              <p className="text-xs text-slate-400 mt-1">Select active SAST static analysis scanners.</p>
            </div>

            <div className="space-y-3">
              {[
                { id: "gitleaks", name: "Gitleaks Engine", desc: "Hardcoded secret & API key scanner" },
                { id: "bandit", name: "Bandit AST Analyzer", desc: "Python AST security analysis" },
                { id: "semgrep", name: "Semgrep SAST Rules", desc: "Multi-language vulnerability patterns" },
                { id: "dependency", name: "Dependency Audit", desc: "Vulnerable package audit" },
              ].map((engine) => (
                <label
                  key={engine.id}
                  className="flex items-center justify-between p-3 rounded-xl bg-slate-900/40 border border-slate-800 cursor-pointer hover:border-slate-700 transition-all"
                >
                  <div className="flex items-center gap-3">
                    <input
                      type="checkbox"
                      checked={engines[engine.id as keyof typeof engines]}
                      onChange={(e) =>
                        setEngines({ ...engines, [engine.id]: e.target.checked })
                      }
                      className="w-4 h-4 accent-cyan-500 rounded cursor-pointer"
                    />
                    <div>
                      <span className="text-xs font-bold text-slate-200 block font-mono">{engine.name}</span>
                      <span className="text-[11px] text-slate-400 block">{engine.desc}</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono font-bold text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/20">
                    Active
                  </span>
                </label>
              ))}
            </div>
          </GlassCard>

          {/* AI Model Settings */}
          <GlassCard className="p-6 space-y-4">
            <div className="border-b border-slate-800 pb-3">
              <h2 className="text-sm font-bold text-slate-100 uppercase tracking-wider font-mono flex items-center gap-2">
                <Cpu className="w-4 h-4 text-cyan-400" /> 4. AI Vulnerability Reasoning
              </h2>
              <p className="text-xs text-slate-400 mt-1">Configure LLM for automated remediation fixes.</p>
            </div>

            <div className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                  AI Provider Engine
                </label>
                <div className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Sparkles className="w-4 h-4 text-cyan-400" />
                    <span className="text-xs font-bold text-slate-200 font-mono capitalize">{aiProvider} (Local LLM)</span>
                  </div>
                  <span className="text-[10px] font-mono font-bold text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/20">
                    Connected
                  </span>
                </div>
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1.5 font-mono">
                  Reasoning Model
                </label>
                <select
                  value={aiModel}
                  onChange={(e) => setAiModel(e.target.value)}
                  className="w-full px-4 py-3 glass-input rounded-xl text-sm focus:outline-none font-mono bg-slate-950"
                >
                  <option value="qwen2.5-coder:1.5b">qwen2.5-coder:1.5b (Fast SAST Fixes)</option>
                  <option value="qwen3-coder:30b">qwen3-coder:30b (Deep Reasoning)</option>
                  <option value="codellama:13b">codellama:13b (Code Security)</option>
                </select>
              </div>
            </div>
          </GlassCard>

        </div>

        {/* Submit Actions Bar */}
        <GlassCard className="p-4 flex items-center justify-between">
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>

          <Button
            type="submit"
            variant="primary"
            size="lg"
            icon={Play}
            loading={loading}
            disabled={!name.trim()}
          >
            Launch Security Scan
          </Button>
        </GlassCard>

      </form>
    </div>
  );
};
