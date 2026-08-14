import React, { useState } from "react";
import { api, getMaxUploadSizeMB, getMaxUploadSizeBytes } from "../services/api";
import { PageHeader } from "../components/ui/PageHeader";
import { GlassCard } from "../components/ui/GlassCard";
import { Button } from "../components/ui/Button";
import { 
  Upload, GitBranch, Code, Globe, FileArchive, 
  AlertCircle, Cpu, Sparkles, FileText, Play, Check
} from "lucide-react";

interface UploadProjectProps {
  onUploadSuccess: (scanId: number) => void;
  onCancel: () => void;
}

export const UploadProject: React.FC<UploadProjectProps> = ({ onUploadSuccess, onCancel }) => {
  // Form State
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [uploadType, setUploadType] = useState<"zip" | "git" | "url" | "file">("zip");
  
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
  const [aiModel, setAiModel] = useState("qwen2.5-coder:1.5b");

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const maxMB = getMaxUploadSizeMB();
  const maxBytes = getMaxUploadSizeBytes();

  const validateFile = (file: File): boolean => {
    if (file.size > maxBytes) {
      setError(`File "${file.name}" is ${(file.size / (1024 * 1024)).toFixed(2)} MB, which exceeds the ${maxMB} MB upload limit. Please compress your source code without node_modules, .git, or venv folders, or use the Git Repository / Paste Code option.`);
      return false;
    }
    return true;
  };

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragOver(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setError("");
      validateFile(file);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setError("");
      validateFile(file);
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
        if (selectedFile.size > maxBytes) {
          throw new Error(`File "${selectedFile.name}" is ${(selectedFile.size / (1024 * 1024)).toFixed(2)} MB, which exceeds the ${maxMB} MB upload limit. Please compress your source code without node_modules, .git, or venv folders, or use the Git Repository / Paste Code option.`);
        }
        formData.append("file", selectedFile);
      } else if (uploadType === "git") {
        if (!gitUrl.trim()) throw new Error("Please enter a valid Git Repository URL.");
        formData.append("git_url", gitUrl);
      } else if (uploadType === "url") {
        if (!gitUrl.trim()) throw new Error("Please enter a valid Web Repository link.");
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

  const tabOptions = [
    { id: "zip", label: "ZIP Archive", icon: FileArchive, desc: "Upload .zip source code" },
    { id: "git", label: "Git Repository", icon: GitBranch, desc: "Clone GitHub / GitLab" },
    { id: "url", label: "Web Repository", icon: Globe, desc: "Remote web repository" },
    { id: "file", label: "Paste Code", icon: Code, desc: "Direct snippet analysis" },
  ];

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
                  onClick={() => setUploadType(tab.id as any)}
                  className={`p-4 rounded-xl text-left border transition-all cursor-pointer min-h-[56px] flex flex-col justify-between ${
                    isSelected
                      ? "bg-gradient-to-br from-cyan-500/20 to-blue-500/15 border-cyan-500/40 text-cyan-300 shadow-lg shadow-cyan-500/10"
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

          {/* TAB CONTENT: ZIP Upload */}
          {uploadType === "zip" && (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleFileDrop}
              className={`border-2 border-dashed rounded-2xl p-8 text-center transition-all cursor-pointer min-h-[160px] flex flex-col items-center justify-center ${
                isDragOver
                  ? "border-cyan-400 bg-cyan-500/10"
                  : selectedFile
                  ? "border-emerald-500/40 bg-emerald-500/5"
                  : "border-slate-800 bg-slate-900/40 hover:border-slate-700"
              }`}
            >
              <input
                type="file"
                accept=".zip"
                onChange={handleFileChange}
                className="hidden"
                id="zip-file-input"
              />
              <label htmlFor="zip-file-input" className="cursor-pointer w-full h-full flex flex-col items-center">
                {selectedFile ? (
                  <div className="space-y-2">
                    <div className={`w-12 h-12 rounded-full border flex items-center justify-center mx-auto ${
                      selectedFile.size > maxBytes
                        ? "bg-rose-500/20 border-rose-500/40 text-rose-400"
                        : "bg-emerald-500/20 border-emerald-500/40 text-emerald-400"
                    }`}>
                      {selectedFile.size > maxBytes ? <AlertCircle className="w-6 h-6" /> : <Check className="w-6 h-6" />}
                    </div>
                    <span className="font-bold text-sm text-slate-100 block">{selectedFile.name}</span>
                    {selectedFile.size > maxBytes ? (
                      <span className="text-xs text-rose-400 font-mono block font-semibold">
                        ⚠️ {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Exceeds {maxMB} MB limit (Upload will fail)
                      </span>
                    ) : (
                      <span className="text-xs text-emerald-400 font-mono block">
                        {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB • Ready for scan
                      </span>
                    )}
                  </div>
                ) : (
                  <div className="space-y-2">
                    <Upload className="w-8 h-8 text-cyan-400 mx-auto" />
                    <span className="text-xs font-bold text-slate-200 block">
                      Drag & Drop your .zip source archive here, or <span className="text-cyan-400 underline">Browse</span>
                    </span>
                    <span className="text-[11px] text-slate-500 font-mono block">
                      Supports Python, JS, TS, Go, Java & C++ zip packages up to {maxMB} MB (Exclude node_modules, .git, venv)
                    </span>
                  </div>
                )}
              </label>
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
                  onChange={(e) => setGitUrl(e.target.value)}
                  placeholder="https://github.com/organization/secure-api.git"
                  className="flex-1 px-4 py-3 glass-input rounded-xl text-sm placeholder-slate-600 focus:outline-none"
                />
              </div>
              <span className="text-[11px] text-slate-500 font-mono block">
                The scanner will perform shallow clone & run Gitleaks + Semgrep rules against the head commit.
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

          {/* TAB CONTENT: Paste Source Code */}
          {uploadType === "file" && (
            <div className="space-y-3">
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 font-mono">
                Paste Source Code Snippet
              </label>
              <textarea
                rows={8}
                value={pastedCode}
                onChange={(e) => setPastedCode(e.target.value)}
                placeholder={`# Paste python code or API script here...\nimport os\napi_key = "AKIA1234567890EXAMPLE"`}
                className="w-full p-4 glass-input rounded-xl text-xs font-mono placeholder-slate-600 focus:outline-none leading-relaxed"
              />
              <span className="text-[11px] text-slate-500 font-mono block">
                Instant static analysis scan for raw source code snippets up to 10,000 lines.
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
                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={engines.gitleaks}
                    onChange={(e) => setEngines({ ...engines, gitleaks: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Gitleaks (Secrets)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={engines.bandit}
                    onChange={(e) => setEngines({ ...engines, bandit: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Bandit (Python)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={engines.semgrep}
                    onChange={(e) => setEngines({ ...engines, semgrep: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Semgrep (AST)</span>
                </label>

                <label className="flex items-center gap-2 p-2.5 bg-slate-900/60 rounded-xl border border-slate-800 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={engines.dependency}
                    onChange={(e) => setEngines({ ...engines, dependency: e.target.checked })}
                    className="accent-cyan-500 rounded"
                  />
                  <span className="text-slate-200">Snyk / Safety</span>
                </label>
              </div>
            </div>

            {/* AI Model Selection */}
            <div className="space-y-3">
              <span className="text-xs font-bold uppercase tracking-wider text-slate-400 font-mono block">
                Local AI Model (Ollama)
              </span>
              <select
                value={aiModel}
                onChange={(e) => setAiModel(e.target.value)}
                className="w-full px-4 py-3 glass-input rounded-xl text-xs font-mono focus:outline-none cursor-pointer"
              >
                <option value="qwen2.5-coder:1.5b" className="bg-slate-900">
                  qwen2.5-coder:1.5b (Fast & Precise - Local)
                </option>
                <option value="qwen3-coder:30b" className="bg-slate-900">
                  qwen3-coder:30b (Advanced Deep Code Reasoning)
                </option>
                <option value="deepseek-coder:6.7b" className="bg-slate-900">
                  deepseek-coder:6.7b (Cybersecurity Expert)
                </option>
              </select>
              <span className="text-[11px] text-emerald-400 font-mono flex items-center gap-1">
                <Sparkles className="w-3.5 h-3.5" /> Ollama Local LLM engine active for zero data exposure.
              </span>
            </div>
          </div>
        </GlassCard>

        {/* Submit Actions Footer */}
        <div className="flex items-center justify-end gap-3 pt-2">
          <Button variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button
            variant="primary"
            icon={Play}
            loading={loading}
            onClick={handleSubmit}
            className="min-h-[48px] px-6 text-sm"
          >
            Launch SAST Analysis
          </Button>
        </div>
      </form>
    </div>
  );
};
